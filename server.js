const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const crypto = require("crypto");
const admin = require("firebase-admin");
require("dotenv").config();

const {
  SUPPORTED_TYPE_POLICY,
  generateRetrievalCode,
  generateHighEntropyToken,
  hashToken,
  hashSecret,
  verifySecret,
  createSignedToken,
  verifySignedToken,
  sanitizeFilename,
  inspectUploadedFile,
  parseLegacyLocation,
  resolveRequestLocation,
  sanitizeCsvCell,
} = require("./lib/security");

const {
  Upload,
  Workspace,
  AbuseReport,
  AdminAuditLog,
  DailyStats,
} = require("./models");

const app = express();
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;

// Retention & Lifecycle Configuration
// Files remain available permanently unless revoked by the uploader or deleted/moderated by an admin.
const FILE_TTL_HOURS = process.env.FILE_TTL_HOURS ? Number(process.env.FILE_TTL_HOURS) : null;
const OPERATIONAL_HISTORY_RETENTION_DAYS = Number(
  process.env.OPERATIONAL_HISTORY_RETENTION_DAYS || 3650
);
const STRUCTURED_TRACKING_STARTED_AT = "2026-11-16T00:00:00.000Z";

// ===== FIREBASE CONFIG =====
let bucket = null;
try {
  let serviceAccount = null;
  if (process.env.FIREBASE_CREDENTIALS) {
    serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
  } else if (process.env.NODE_ENV !== "test") {
    serviceAccount = require("./serviceAccountKey.json");
  }
  if (serviceAccount) {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        storageBucket: "fileverse-krwk3.firebasestorage.app",
      });
    }
    bucket = admin.storage().bucket();
  }
} catch (error) {
  if (process.env.NODE_ENV !== "test") {
    console.error("Failed to load Firebase credentials:", error.message);
  }
}

// Allow injecting a mock bucket in automated tests
function setStorageBucketForTesting(mockBucket) {
  bucket = mockBucket;
}

// ===== SECURITY HEADERS & CORS MIDDLEWARE =====
const allowedOrigins = [
  "https://fylshare.com",
  "https://www.fylshare.com",
  "https://fylshare.vercel.app",
  "https://filehub-gyll.web.app",
  "https://fileverse-krwk3.web.app",
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
];

app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=()"
  );
  next();
});

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV === "test") {
        callback(null, true);
      } else {
        callback(new Error("Origin not allowed by CORS"));
      }
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "X-Revoke-Token"],
    exposedHeaders: ["Content-Disposition"],
  })
);

app.use(express.json({ limit: "1mb" }));

// ===== MULTER CONFIG =====
const uploadMiddleware = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: SUPPORTED_TYPE_POLICY.maxTotalBytes,
    files: SUPPORTED_TYPE_POLICY.maxFilesPerTransfer,
  },
});

// ===== RATE LIMITERS =====
const lookupRateMap = new Map();
const loginRateMap = new Map();

function checkRateLimit(map, key, maxRequests, windowMs) {
  const now = Date.now();
  const entry = map.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) {
    entry.count = 1;
    entry.resetAt = now + windowMs;
  } else {
    entry.count += 1;
  }
  map.set(key, entry);
  return {
    allowed: entry.count <= maxRequests,
    remaining: Math.max(0, maxRequests - entry.count),
    resetAt: entry.resetAt,
  };
}

function getClientRateKey(req) {
  if (process.env.TRUST_PROXY !== "false" && req.headers["x-forwarded-for"]) {
    return String(req.headers["x-forwarded-for"]).split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "local";
}

// ===== ADMIN AUTHENTICATION & AUTHORIZATION =====
// Admin credentials are verified strictly on the server using scrypt hashes or env variables.
// No passwords or secrets are ever sent to or stored in the frontend bundle.
function getAdminAccounts() {
  const adminUser = process.env.ADMIN_USERNAME || "fazal";
  const adminPass = process.env.ADMIN_PASSWORD || "9948";

  const adminSecret = hashSecret(adminPass, "fylshare-admin-salt-v1");

  return [
    {
      username: adminUser,
      passwordHash: process.env.ADMIN_PASSWORD_HASH || adminSecret.hash,
      passwordSalt: process.env.ADMIN_PASSWORD_SALT || adminSecret.salt,
      role: "admin",
    },
  ];
}

async function recordAuditLog({
  actor,
  role,
  action,
  targetType,
  targetId = null,
  reason = null,
  result = "success",
  metadata = {},
}) {
  try {
    await AdminAuditLog.create({
      actor: actor || "unknown",
      role: role || "unknown",
      action,
      targetType,
      targetId: targetId ? String(targetId) : null,
      reason,
      result,
      metadata,
      timestamp: new Date(),
    });
  } catch (err) {
    console.error("Audit log write error:", err.message);
  }
}

function extractBearerToken(req) {
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  return null;
}

function requireAdminAuth(allowedRoles = ["admin", "viewer"]) {
  return async (req, res, next) => {
    const token = extractBearerToken(req);
    const payload = verifySignedToken(token);
    if (!payload || payload.scope !== "admin_session" || !payload.username) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (!allowedRoles.includes(payload.role)) {
      await recordAuditLog({
        actor: payload.username,
        role: payload.role,
        action: `${req.method} ${req.path}`,
        targetType: "admin_endpoint",
        result: "denied",
      });
      return res.status(403).json({ error: "Insufficient privileges for this operation" });
    }
    req.adminUser = {
      username: payload.username,
      role: payload.role,
    };
    next();
  };
}

// ===== DAILY AGGREGATE STATS HELPER =====
function getUtcDateKey(date = new Date()) {
  return new Date(date).toISOString().slice(0, 10);
}

async function incrementDailyStats(date, increments) {
  try {
    const dateKey = getUtcDateKey(date);
    await DailyStats.findOneAndUpdate(
      { dateKey },
      {
        $inc: increments,
        $set: { updatedAt: new Date() },
      },
      { upsert: true, new: true }
    );
  } catch (err) {
    console.error("DailyStats update error:", err.message);
  }
}

// ===== STORAGE HELPERS (PRIVATE OBJECTS + BOUNDED SIGNED URLS) =====
async function uploadToFirebasePrivate(file, transferId, fileId, inspection) {
  const storagePath = `uploads/${transferId}/${fileId}${inspection.extension}`;

  if (!bucket) {
    // Local / test fallback when Firebase is not configured
    return {
      fileId,
      name: inspection.sanitizedName,
      storagePath,
      url: "",
      isPublicLegacy: false,
      size: file.size,
      type: file.mimetype || "application/octet-stream",
      extension: inspection.extension,
      scanStatus: inspection.scanStatus,
      forceAttachment: inspection.forceAttachment,
      storageDeleted: false,
    };
  }

  const fileUpload = bucket.file(storagePath);
  const contentDisposition = inspection.forceAttachment
    ? `attachment; filename="${inspection.sanitizedName.replace(/"/g, "")}"`
    : `inline; filename="${inspection.sanitizedName.replace(/"/g, "")}"`;

  const stream = fileUpload.createWriteStream({
    resumable: false,
    metadata: {
      contentType: file.mimetype || "application/octet-stream",
      contentDisposition,
      cacheControl: "private, no-store",
    },
  });

  return new Promise((resolve, reject) => {
    stream.on("error", (err) => reject(err));
    stream.on("finish", async () => {
      // Do NOT call fileUpload.makePublic()! Keep objects private and authorize at download time.
      resolve({
        fileId,
        name: inspection.sanitizedName,
        storagePath,
        url: "",
        isPublicLegacy: false,
        size: file.size,
        type: file.mimetype || "application/octet-stream",
        extension: inspection.extension,
        scanStatus: inspection.scanStatus,
        forceAttachment: inspection.forceAttachment,
        storageDeleted: false,
      });
    });
    stream.end(file.buffer);
  });
}

async function generateBoundedDownloadUrl(fileObj, expiresAtDate, forceDownload = false) {
  const now = Date.now();
  const maxWindowMs = 10 * 60 * 1000; // Max 10 minutes per signed link
  const remainingLifetimeMs = expiresAtDate
    ? Math.max(5000, new Date(expiresAtDate).getTime() - now)
    : maxWindowMs;
  const boundedTtlMs = Math.min(maxWindowMs, remainingLifetimeMs);

  let storagePath = fileObj.storagePath;
  if (!storagePath && fileObj.url && bucket) {
    const marker = `${bucket.name}/`;
    const idx = fileObj.url.indexOf(marker);
    if (idx !== -1) {
      storagePath = decodeURIComponent(fileObj.url.slice(idx + marker.length));
    }
  }

  if (bucket && storagePath) {
    try {
      const cleanName = sanitizeFilename(fileObj.name || "download").replace(/"/g, "");
      const dispositionType =
        forceDownload || fileObj.forceAttachment ? "attachment" : "inline";
      const [signedUrl] = await bucket.file(storagePath).getSignedUrl({
        version: "v4",
        action: "read",
        expires: now + boundedTtlMs,
        responseDisposition: `${dispositionType}; filename="${cleanName}"`,
      });
      return signedUrl;
    } catch (err) {
      // Fallback for legacy objects if v4 signing fails
      if (fileObj.url) return fileObj.url;
      throw err;
    }
  }

  if (fileObj.url) return fileObj.url;
  return `/api/mock-storage/${encodeURIComponent(storagePath || fileObj.fileId || "file")}`;
}

async function deleteFromFirebase(files) {
  if (!Array.isArray(files) || files.length === 0) return { ok: true, errors: [] };
  if (!bucket) return { ok: true, errors: [] };

  const errors = [];
  await Promise.all(
    files.map(async (f) => {
      if (!f || f.storageDeleted) return;
      let storagePath = f.storagePath;
      if (!storagePath && f.url) {
        const marker = `${bucket.name}/`;
        const idx = f.url.indexOf(marker);
        if (idx !== -1) {
          storagePath = decodeURIComponent(f.url.slice(idx + marker.length));
        }
      }
      if (!storagePath) return;
      try {
        await bucket.file(storagePath).delete({ ignoreNotFound: true });
      } catch (err) {
        errors.push(`${storagePath}: ${err.message}`);
      }
    })
  );

  return {
    ok: errors.length === 0,
    errors,
  };
}

// ===== IDEMPOTENT LIFECYCLE & EXPIRY CLEANUP ENGINE =====
let lastCleanupRunSummary = {
  lastRunAt: null,
  expiredProcessed: 0,
  failures: 0,
};

async function runStorageCleanupCycle() {
  const now = new Date();

  // Only retry transfers explicitly marked as "deletion_pending" (or with an explicit expiresAt set in the past).
  // Standard transfers without an expiration date remain stored permanently.
  const candidates = await Upload.find({
    $or: [
      { status: "deletion_pending" },
      { status: "available", expiresAt: { $ne: null, $lte: now } },
    ],
  }).limit(100);

  let expiredProcessed = 0;
  let failures = 0;

  for (const transfer of candidates) {
    transfer.cleanupAttempts = (transfer.cleanupAttempts || 0) + 1;
    transfer.lastCleanupAttemptAt = now;

    const delResult = await deleteFromFirebase(transfer.files);
    if (delResult.ok) {
      const deletedFilesCount = Array.isArray(transfer.files) ? transfer.files.length : 0;
      transfer.status = transfer.status === "deletion_pending" ? "deleted" : "expired";
      transfer.storageDeletedAt = now;
      transfer.lastCleanupError = null;

      if (Array.isArray(transfer.files)) {
        transfer.files = transfer.files.map((f, idx) => ({
          fileId: f.fileId || `file_${idx + 1}`,
          name: f.name,
          storagePath: "",
          url: "",
          isPublicLegacy: false,
          size: f.size || 0,
          date: f.date,
          type: f.type || "application/octet-stream",
          extension: f.extension || "",
          code: f.code || "",
          scanStatus: f.scanStatus || "passed",
          forceAttachment: Boolean(f.forceAttachment),
          storageDeleted: true,
        }));
      }

      await transfer.save();
      await incrementDailyStats(now, {
        transfersExpired: 1,
        filesDeleted: deletedFilesCount,
      });
      expiredProcessed += 1;
    } else {
      transfer.status = "deletion_pending";
      transfer.lastCleanupError = delResult.errors.join("; ").slice(0, 500);
      await transfer.save();
      failures += 1;
    }
  }

  lastCleanupRunSummary = {
    lastRunAt: now.toISOString(),
    expiredProcessed,
    failures,
  };

  return lastCleanupRunSummary;
}

// ===== NORMALIZE TRANSFER RECORD FOR ADMIN & API =====
function normalizeTransferForAdmin(doc, includeFileNames = true) {
  const now = new Date();
  const rawDate = doc.date ? new Date(doc.date) : now;
  const computedExpiresAt = doc.expiresAt ? new Date(doc.expiresAt) : null;

  let effectiveStatus = doc.status || "available";
  if (effectiveStatus === "available" && computedExpiresAt && computedExpiresAt <= now) {
    effectiveStatus = "expired";
  }

  // Derive accurate country fields (handling both structured fields and legacy location strings)
  let countryCode = doc.countryCode || null;
  let countryName = doc.countryName || "Unknown";
  let locationSource = doc.locationSource || "unknown";
  let locationStatus = doc.locationStatus || "unknown";
  let browserTimezone = doc.browserTimezone || null;
  let deviceCategory = doc.deviceCategory || "unknown";

  if ((!countryName || countryName === "Unknown") && doc.location) {
    const parsed = parseLegacyLocation(doc.location);
    countryCode = parsed.countryCode;
    countryName = parsed.countryName;
    locationSource = parsed.locationSource;
    locationStatus = parsed.locationStatus;
    browserTimezone = browserTimezone || parsed.browserTimezone;
    deviceCategory = deviceCategory !== "unknown" ? deviceCategory : parsed.deviceCategory || "unknown";
  }

  const files = Array.isArray(doc.files) ? doc.files : [];
  const fileCount = typeof doc.fileCount === "number" && doc.fileCount > 0 ? doc.fileCount : files.length;
  const totalBytes =
    typeof doc.size === "number" && doc.size > 0
      ? doc.size
      : files.reduce((sum, f) => sum + (Number(f.size) || 0), 0);

  return {
    id: String(doc._id),
    transferId: doc.transferId || String(doc._id),
    code: doc.code || null,
    transferType: doc.transferType || "anonymous",
    workspaceName: doc.workspaceName || null,
    label: doc.labelRedacted ? "[Redacted]" : doc.name || "Anonymous",
    labelRedacted: Boolean(doc.labelRedacted),
    fileCount,
    totalBytes,
    status: effectiveStatus,
    scanStatus: doc.scanStatus || "passed",
    createdAt: rawDate.toISOString(),
    expiresAt: computedExpiresAt ? computedExpiresAt.toISOString() : null,
    storageDeletedAt: doc.storageDeletedAt ? new Date(doc.storageDeletedAt).toISOString() : null,
    cleanupAttempts: doc.cleanupAttempts || 0,
    lastCleanupError: doc.lastCleanupError || null,
    countryCode,
    countryName: countryCode ? countryName : "Unknown",
    locationSource,
    locationStatus: countryCode ? "available" : "unknown",
    deviceCategory,
    browserTimezone,
    retrievalCount: doc.retrievalCount || 0,
    downloadRequestCount: doc.downloadRequestCount || 0,
    downloadServedCount: doc.downloadServedCount || 0,
    reports: doc.reports || 0,
    files: files.map((f, idx) => ({
      index: idx,
      fileId: f.fileId || `file_${idx + 1}`,
      name: includeFileNames && !f.storageDeleted ? f.name : f.storageDeleted ? "[Deleted from storage]" : f.name,
      size: f.size || 0,
      type: f.type || "application/octet-stream",
      extension: f.extension || "",
      scanStatus: f.scanStatus || "passed",
      storageDeleted: Boolean(f.storageDeleted || doc.storageDeletedAt),
    })),
  };
}

// Compute UTC date boundaries for a selected timezone (e.g., "Asia/Dubai")
function getDateWindowBounds(period, timezone = "Asia/Dubai", startDateStr = "", endDateStr = "") {
  const now = new Date();
  let tz = "Asia/Dubai";
  try {
    Intl.DateTimeFormat("en-US", { timeZone: timezone });
    tz = timezone;
  } catch {
    tz = "Asia/Dubai";
  }

  // Helper to get YYYY-MM-DD in target timezone
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });

  // Determine offset in ms for the target timezone at a given UTC timestamp
  function getTzMidnightUtc(yyyyMmDd) {
    const [y, m, d] = yyyyMmDd.split("-").map(Number);
    const approxUtc = new Date(Date.UTC(y, m - 1, d, 0, 0, 0));
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).formatToParts(approxUtc);
    const map = {};
    for (const p of parts) map[p.type] = p.value;
    const hr = Number(map.hour === "24" ? 0 : map.hour);
    const min = Number(map.minute);
    const tzAsUtc = Date.UTC(Number(map.year), Number(map.month) - 1, Number(map.day), hr, min, 0);
    const offsetMs = tzAsUtc - approxUtc.getTime();
    return new Date(approxUtc.getTime() - offsetMs);
  }

  const todayInTz = fmt.format(now); // YYYY-MM-DD
  const startOfTodayUtc = getTzMidnightUtc(todayInTz);
  const endOfTodayUtc = new Date(startOfTodayUtc.getTime() + 24 * 3600 * 1000 - 1);

  if (period === "today") {
    return { startUtc: startOfTodayUtc, endUtc: endOfTodayUtc, timezone: tz };
  }
  if (period === "7d") {
    return {
      startUtc: new Date(startOfTodayUtc.getTime() - 6 * 24 * 3600 * 1000),
      endUtc: endOfTodayUtc,
      timezone: tz,
    };
  }
  if (period === "30d") {
    return {
      startUtc: new Date(startOfTodayUtc.getTime() - 29 * 24 * 3600 * 1000),
      endUtc: endOfTodayUtc,
      timezone: tz,
    };
  }
  if (period === "custom" && startDateStr) {
    const startUtc = /^\d{4}-\d{2}-\d{2}$/.test(startDateStr)
      ? getTzMidnightUtc(startDateStr)
      : new Date(startDateStr);
    const endUtc =
      endDateStr && /^\d{4}-\d{2}-\d{2}$/.test(endDateStr)
        ? new Date(getTzMidnightUtc(endDateStr).getTime() + 24 * 3600 * 1000 - 1)
        : endDateStr
        ? new Date(endDateStr)
        : endOfTodayUtc;
    return { startUtc, endUtc, timezone: tz };
  }

  // "all_retained"
  return { startUtc: null, endUtc: null, timezone: tz };
}

function formatDateInTz(date, timezone = "Asia/Dubai") {
  try {
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: timezone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date(date));
  } catch {
    return new Date(date).toISOString().slice(0, 10);
  }
}

// ===== PUBLIC TRANSFER ROUTES =====

// Supported-Type & Retention Policy Metadata (used by Frontend to display exact, truthful limits)
app.get("/api/policy", (req, res) => {
  res.json({
    maxFilesPerTransfer: SUPPORTED_TYPE_POLICY.maxFilesPerTransfer,
    maxTotalBytes: SUPPORTED_TYPE_POLICY.maxTotalBytes,
    defaultExpiryHours: FILE_TTL_HOURS,
    operationalHistoryRetentionDays: OPERATIONAL_HISTORY_RETENTION_DAYS,
    allowedExtensions: Array.from(SUPPORTED_TYPE_POLICY.allowedExtensions),
    blockedExtensions: Array.from(SUPPORTED_TYPE_POLICY.blockedExtensions),
  });
});

// Create new upload (Multipart/Form-Data)
app.post("/api/uploads", (req, res) => {
  uploadMiddleware.array("files", SUPPORTED_TYPE_POLICY.maxFilesPerTransfer)(
    req,
    res,
    async (multerErr) => {
      if (multerErr) {
        return res.status(400).json({
          error:
            multerErr.code === "LIMIT_FILE_SIZE"
              ? "File exceeds the 1 GB maximum size limit."
              : multerErr.code === "LIMIT_FILE_COUNT"
              ? `Maximum ${SUPPORTED_TYPE_POLICY.maxFilesPerTransfer} files allowed per transfer.`
              : multerErr.message || "Invalid file upload request.",
        });
      }

      try {
        if (!req.files || req.files.length === 0) {
          return res.status(400).json({ error: "Please select at least one file to upload." });
        }

        if (req.files.length > SUPPORTED_TYPE_POLICY.maxFilesPerTransfer) {
          return res.status(400).json({
            error: `Maximum ${SUPPORTED_TYPE_POLICY.maxFilesPerTransfer} files allowed per transfer.`,
          });
        }

        const totalBytes = req.files.reduce((sum, f) => sum + (f.size || 0), 0);
        if (totalBytes > SUPPORTED_TYPE_POLICY.maxTotalBytes) {
          return res.status(400).json({ error: "Total transfer size exceeds the 1 GB limit." });
        }

        // Validate every file against the supported-type policy and magic-byte signatures
        const inspections = [];
        for (const file of req.files) {
          const check = inspectUploadedFile(file);
          if (!check.accepted) {
            return res.status(400).json({
              error: check.reason,
              code: "UNSUPPORTED_OR_UNSAFE_FILE",
            });
          }
          inspections.push(check);
        }

        // Generate cryptographically secure 6-digit code (ensuring no collision with active transfers)
        let code = generateRetrievalCode();
        for (let attempt = 0; attempt < 5; attempt++) {
          const existing = await Upload.findOne({ code, status: "available" });
          if (!existing) break;
          code = generateRetrievalCode();
        }

        const transferId = `tr_${generateHighEntropyToken(12)}`;
        const shareToken = generateHighEntropyToken(24);
        const revokeToken = generateHighEntropyToken(24);
        const now = new Date();
        // Persistent storage by default (null expiresAt unless FILE_TTL_HOURS env var is explicitly set)
        const expiresAt = FILE_TTL_HOURS
          ? new Date(now.getTime() + FILE_TTL_HOURS * 3600 * 1000)
          : null;

        // Upload files privately to storage
        const uploadedFiles = await Promise.all(
          req.files.map((file, idx) =>
            uploadToFirebasePrivate(file, transferId, `f_${idx + 1}_${generateHighEntropyToken(6)}`, inspections[idx])
          )
        );

        const finalFileData = uploadedFiles.map((f) => ({ ...f, code }));

        // Derive approximate country strictly from trusted server/proxy headers
        const locInfo = resolveRequestLocation(req);
        const rawLabel = typeof req.body?.name === "string" ? req.body.name.trim().slice(0, 80) : "";

        const overallScanStatus = inspections.some(
          (i) => i.scanStatus === "uninspectable_encrypted_archive"
        )
          ? "uninspectable_encrypted_archive"
          : "passed";

        const newUpload = new Upload({
          transferId,
          transferType: "anonymous",
          name: rawLabel || "",
          code,
          codeHash: hashToken(code),
          shareTokenHash: hashToken(shareToken),
          revokeTokenHash: hashToken(revokeToken),
          files: finalFileData,
          fileCount: finalFileData.length,
          size: totalBytes,
          status: "available",
          scanStatus: overallScanStatus,
          date: now,
          expiresAt,
          countryCode: locInfo.countryCode,
          countryName: locInfo.countryName,
          locationSource: locInfo.locationSource,
          locationStatus: locInfo.locationStatus,
          deviceCategory: locInfo.deviceCategory,
          location: locInfo.countryCode ? locInfo.countryName : "Unknown",
        });

        await newUpload.save();

        await incrementDailyStats(now, {
          transfersCreated: 1,
          filesUploaded: finalFileData.length,
          bytesUploaded: totalBytes,
        });

        res.status(201).json({
          message: "Upload complete",
          transferId,
          code,
          shareToken,
          revokeToken,
          createdAt: now.toISOString(),
          expiresAt: expiresAt ? expiresAt.toISOString() : null,
          status: "available",
          scanStatus: overallScanStatus,
          fileCount: finalFileData.length,
          totalBytes,
          files: finalFileData.map((f, idx) => ({
            index: idx,
            fileId: f.fileId,
            name: f.name,
            size: f.size,
            type: f.type,
            extension: f.extension,
            scanStatus: f.scanStatus,
          })),
        });
      } catch (error) {
        console.error("Upload error:", error);
        res.status(500).json({ error: "Failed to process upload" });
      }
    }
  );
});

// Retrieve transfer metadata by 6-digit code OR high-entropy shareToken
app.get("/api/uploads/:identifier", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(lookupRateMap, clientKey, 20, 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({
        message: "Too many retrieval attempts from your network. Please wait a minute and try again.",
      });
    }

    const identifier = String(req.params.identifier || "").trim();
    const tokenParam = String(req.query.token || "").trim();
    const now = new Date();

    let uploadData = null;
    if (tokenParam && tokenParam.length >= 16) {
      uploadData = await Upload.findOne({ shareTokenHash: hashToken(tokenParam) });
    } else if (/^\d{6}$/.test(identifier)) {
      uploadData = await Upload.findOne({ code: identifier });
    } else if (identifier.length >= 16) {
      uploadData = await Upload.findOne({ shareTokenHash: hashToken(identifier) });
    } else {
      return res.status(404).json({ message: "Transfer not found or expired." });
    }

    if (uploadData) {
      const computedExpiresAt = uploadData.expiresAt ? new Date(uploadData.expiresAt) : null;

      // Enforce lifecycle status and optional expiration at request time
      if (
        uploadData.status !== "available" ||
        (computedExpiresAt && computedExpiresAt <= now) ||
        uploadData.storageDeletedAt
      ) {
        return res.status(404).json({
          message: "This transfer is no longer available.",
        });
      }

      uploadData.retrievalCount = (uploadData.retrievalCount || 0) + 1;
      await uploadData.save();
      await incrementDailyStats(now, { retrievalsSucceeded: 1 });

      const authIdentifier = tokenParam || identifier;

      return res.json({
        transferId: uploadData.transferId || String(uploadData._id),
        name: uploadData.name || "Untitled transfer",
        status: "available",
        scanStatus: uploadData.scanStatus || "passed",
        createdAt: new Date(uploadData.date).toISOString(),
        expiresAt: computedExpiresAt ? computedExpiresAt.toISOString() : null,
        fileCount: uploadData.files?.length || 0,
        files: (uploadData.files || []).map((f, index) => ({
          index,
          fileId: f.fileId || `file_${index + 1}`,
          name: f.name,
          size: f.size,
          type: f.type,
          extension: f.extension,
          scanStatus: f.scanStatus || "passed",
          forceAttachment: Boolean(f.forceAttachment),
          downloadEndpoint: `/api/uploads/${encodeURIComponent(
            authIdentifier
          )}/files/${index}/download`,
        })),
      });
    }

    return res.status(404).json({ message: "Transfer not found or expired." });
  } catch (error) {
    console.error("Retrieval error:", error);
    res.status(500).json({ error: "Unable to complete retrieval request" });
  }
});

// Authorized, time-bounded file download/preview endpoint
app.get("/api/uploads/:identifier/files/:fileIndex/download", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(lookupRateMap, clientKey, 30, 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({ message: "Too many download requests. Please wait a minute." });
    }

    const identifier = String(req.params.identifier || "").trim();
    const fileIndex = Number(req.params.fileIndex);
    const mode = req.query.mode === "inline" ? "inline" : "download";
    const now = new Date();

    let uploadData = null;
    if (/^\d{6}$/.test(identifier)) {
      uploadData = await Upload.findOne({ code: identifier });
    } else if (identifier.length >= 16) {
      uploadData = await Upload.findOne({ shareTokenHash: hashToken(identifier) });
    }

    if (!uploadData) {
      return res.status(404).json({ message: "Transfer not found or expired." });
    }

    const computedExpiresAt = uploadData.expiresAt ? new Date(uploadData.expiresAt) : null;

    if (
      uploadData.status !== "available" ||
      (computedExpiresAt && computedExpiresAt <= now) ||
      uploadData.storageDeletedAt
    ) {
      return res.status(410).json({ message: "This transfer has been removed." });
    }

    const files = Array.isArray(uploadData.files) ? uploadData.files : [];
    if (isNaN(fileIndex) || fileIndex < 0 || fileIndex >= files.length) {
      return res.status(404).json({ message: "Requested file not found in transfer." });
    }

    const targetFile = files[fileIndex];
    if (targetFile.storageDeleted) {
      return res.status(410).json({ message: "File is no longer stored." });
    }

    uploadData.downloadRequestCount = (uploadData.downloadRequestCount || 0) + 1;
    const forceAttachment = mode === "download" || Boolean(targetFile.forceAttachment);
    const signedUrl = await generateBoundedDownloadUrl(
      targetFile,
      computedExpiresAt,
      forceAttachment
    );
    uploadData.downloadServedCount = (uploadData.downloadServedCount || 0) + 1;
    await uploadData.save();

    await incrementDailyStats(now, {
      downloadsRequested: 1,
      downloadsServed: 1,
    });

    if (req.query.json === "true") {
      return res.json({
        downloadUrl: signedUrl,
        fileName: sanitizeFilename(targetFile.name),
        forceAttachment,
        expiresAt: computedExpiresAt ? computedExpiresAt.toISOString() : null,
      });
    }

    return res.redirect(302, signedUrl);
  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({ error: "Unable to generate download link" });
  }
});

// Uploader Self-Revocation (Deletes stored files using the uploader's revokeToken)
app.post("/api/uploads/:code/revoke", async (req, res) => {
  try {
    const code = String(req.params.code || "").trim();
    const revokeToken =
      req.headers["x-revoke-token"] || (req.body && req.body.revokeToken) || "";

    if (!revokeToken || revokeToken.length < 16) {
      return res.status(401).json({
        error: "Valid uploader revocation token is required to delete server files.",
      });
    }

    const uploadData = await Upload.findOne({
      $or: [{ code }, { transferId: code }],
      revokeTokenHash: hashToken(revokeToken),
    });

    if (!uploadData) {
      return res.status(404).json({ error: "Transfer not found or already deleted." });
    }

    const delResult = await deleteFromFirebase(uploadData.files);
    const now = new Date();
    const deletedCount = Array.isArray(uploadData.files) ? uploadData.files.length : 0;

    uploadData.status = delResult.ok ? "revoked" : "deletion_pending";
    uploadData.storageDeletedAt = delResult.ok ? now : null;
    uploadData.metadataMinimizedAt = now;
    uploadData.lastCleanupError = delResult.ok ? null : delResult.errors.join("; ");
    uploadData.code = null;
    uploadData.shareTokenHash = null;
    uploadData.revokeTokenHash = null;
    uploadData.name = "[Revoked by uploader]";
    uploadData.labelRedacted = true;
    if (Array.isArray(uploadData.files)) {
      uploadData.files = uploadData.files.map((f, idx) => ({
        fileId: f.fileId || `file_${idx + 1}`,
        name: "[Deleted by uploader]",
        storagePath: "",
        url: "",
        size: f.size || 0,
        type: f.type || "application/octet-stream",
        extension: f.extension || "",
        storageDeleted: delResult.ok,
      }));
    }

    await uploadData.save();
    await incrementDailyStats(now, {
      transfersRevoked: 1,
      filesDeleted: delResult.ok ? deletedCount : 0,
    });

    res.json({
      message: "Transfer revoked and stored files deleted from server.",
      status: uploadData.status,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to revoke transfer" });
  }
});

// Protect legacy GET /api/uploads and DELETE /api/uploads/:code with Admin Authentication
app.get("/api/uploads", requireAdminAuth(["admin", "viewer"]), async (req, res) => {
  try {
    const uploads = await Upload.find().sort({ date: -1, _id: -1 }).limit(100);
    res.json(uploads.map((u) => normalizeTransferForAdmin(u, false)));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

app.delete("/api/uploads/:code", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const target = req.params.code;
    const uploadData = await Upload.findOne({
      $or: [
        { code: target },
        { transferId: target },
        ...(mongoose.Types.ObjectId.isValid(target) ? [{ _id: target }] : []),
      ],
    });
    if (!uploadData) return res.status(404).json({ message: "No transfer found" });

    const delResult = await deleteFromFirebase(uploadData.files);
    const now = new Date();
    const fileCount = Array.isArray(uploadData.files) ? uploadData.files.length : 0;

    uploadData.status = delResult.ok ? "deleted" : "deletion_pending";
    uploadData.storageDeletedAt = delResult.ok ? now : null;
    uploadData.metadataMinimizedAt = now;
    uploadData.lastCleanupError = delResult.ok ? null : delResult.errors.join("; ");
    uploadData.code = null;
    uploadData.shareTokenHash = null;
    uploadData.revokeTokenHash = null;
    uploadData.name = "[Deleted by admin]";
    uploadData.labelRedacted = true;
    if (Array.isArray(uploadData.files)) {
      uploadData.files = uploadData.files.map((f, idx) => ({
        fileId: f.fileId || `file_${idx + 1}`,
        name: "[Deleted]",
        storagePath: "",
        url: "",
        size: f.size || 0,
        type: f.type || "application/octet-stream",
        extension: f.extension || "",
        storageDeleted: delResult.ok,
      }));
    }
    await uploadData.save();

    await incrementDailyStats(now, {
      filesDeleted: delResult.ok ? fileCount : 0,
    });

    await recordAuditLog({
      actor: req.adminUser.username,
      role: req.adminUser.role,
      action: "delete_transfer",
      targetType: "transfer",
      targetId: uploadData.transferId || String(uploadData._id),
      reason: req.body?.reason || "Admin manual deletion",
      result: delResult.ok ? "success" : "error",
    });

    res.status(200).json({
      message: delResult.ok
        ? "Stored files deleted and transfer marked as deleted."
        : "Transfer disabled; storage cleanup queued for retry.",
      status: uploadData.status,
    });
  } catch (error) {
    res.status(500).json({ error: "Error deleting transfer" });
  }
});

// ===== ABUSE REPORTING & MODERATION QUEUE =====
app.post("/api/report", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(lookupRateMap, `report:${clientKey}`, 10, 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({ error: "Too many reports submitted. Please wait a minute." });
    }

    const { code, token, category = "other", reason, reporterContact } = req.body || {};
    if (!reason || String(reason).trim().length < 5) {
      return res.status(400).json({ error: "Please provide a brief description of the issue." });
    }

    let upload = null;
    if (code && /^\d{6}$/.test(String(code).trim())) {
      upload = await Upload.findOne({ code: String(code).trim() });
    } else if (token && String(token).trim().length >= 16) {
      upload = await Upload.findOne({ shareTokenHash: hashToken(String(token).trim()) });
    }

    const validCategories = ["copyright", "malware", "privacy", "unlawful", "other"];
    const cleanCategory = validCategories.includes(category) ? category : "other";
    const cleanReason = String(reason).trim().slice(0, 500);

    const reportDoc = await AbuseReport.create({
      reportId: `rep_${generateHighEntropyToken(8)}`,
      transferId: upload ? upload._id : null,
      codeHash: upload ? upload.codeHash || hashToken(upload.code) : hashToken(code || token || ""),
      category: cleanCategory,
      reason: cleanReason,
      reporterContact: reporterContact ? String(reporterContact).trim().slice(0, 120) : null,
      status: "open",
      createdAt: new Date(),
    });

    if (upload) {
      upload.reports = (upload.reports || 0) + 1;
      upload.reportReasons.push(`[${cleanCategory}] ${cleanReason}`);

      // Automatically quarantine transfer pending review if reported >= 2 times or flagged as unlawful/malware
      if (upload.reports >= 2 || cleanCategory === "malware" || cleanCategory === "unlawful") {
        upload.status = "quarantined";
        reportDoc.status = "quarantined";
        await reportDoc.save();
      }
      await upload.save();
    }

    res.status(201).json({
      message: "Report received. Reference ID generated for our safety team.",
      reportId: reportDoc.reportId,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to submit abuse report" });
  }
});

// ===== WORKSPACE ROUTES (WITH HASHED PINS & SESSION TOKENS) =====
function verifyWorkspaceToken(req, expectedBoxName) {
  const token = extractBearerToken(req);
  const payload = verifySignedToken(token);
  if (
    !payload ||
    payload.scope !== "workspace_session" ||
    payload.boxName !== expectedBoxName
  ) {
    return false;
  }
  return true;
}

app.post("/api/box/create", async (req, res) => {
  try {
    const rawBoxName = String(req.body?.boxName || "").trim();
    const rawPin = String(req.body?.pin || "").trim();

    if (!rawBoxName || rawBoxName.length < 3 || rawBoxName.length > 40) {
      return res.status(400).json({ error: "Box name must be between 3 and 40 characters." });
    }
    if (!rawPin || rawPin.length < 4 || rawPin.length > 32) {
      return res.status(400).json({ error: "PIN must be at least 4 characters." });
    }

    const existing = await Workspace.findOne({ boxName: rawBoxName });
    if (existing) return res.status(409).json({ error: "Box name already taken" });

    const { hash, salt } = hashSecret(rawPin);
    const newBox = new Workspace({
      boxName: rawBoxName,
      pin: rawPin, // Stored so the Admin Console can view the Box PIN
      pinHash: hash,
      pinSalt: salt,
      files: [],
    });
    await newBox.save();

    const workspaceToken = createSignedToken(
      { scope: "workspace_session", boxName: rawBoxName },
      2 * 3600
    );

    res.status(201).json({
      message: "Box created",
      boxName: rawBoxName,
      workspaceToken,
      files: [],
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to create box" });
  }
});

app.post("/api/box/login", async (req, res) => {
  try {
    const rawBoxName = String(req.body?.boxName || "").trim();
    const rawPin = String(req.body?.pin || "").trim();
    const clientKey = getClientRateKey(req);

    const rate = checkRateLimit(loginRateMap, `box:${clientKey}:${rawBoxName}`, 10, 5 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({ error: "Too many PIN attempts. Please wait 5 minutes." });
    }

    const box = await Workspace.findOne({ boxName: rawBoxName });
    if (!box) return res.status(401).json({ error: "Invalid Box name or PIN" });

    if (box.lockUntil && new Date(box.lockUntil) > new Date()) {
      return res.status(429).json({ error: "Workspace temporarily locked due to failed PIN attempts." });
    }

    let pinValid = false;
    if (box.pinHash && box.pinSalt) {
      pinValid = verifySecret(rawPin, box.pinHash, box.pinSalt);
      if (pinValid && !box.pin) {
        box.pin = rawPin;
      }
    } else if (box.pin) {
      const a = Buffer.from(String(box.pin));
      const b = Buffer.from(String(rawPin));
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        pinValid = true;
        const { hash, salt } = hashSecret(rawPin);
        box.pinHash = hash;
        box.pinSalt = salt;
      }
    }

    if (!pinValid) {
      box.failedAttempts = (box.failedAttempts || 0) + 1;
      if (box.failedAttempts >= 8) {
        box.lockUntil = new Date(Date.now() + 5 * 60 * 1000);
      }
      await box.save();
      return res.status(401).json({ error: "Invalid Box name or PIN" });
    }

    box.failedAttempts = 0;
    box.lockUntil = null;
    await box.save();

    const workspaceToken = createSignedToken(
      { scope: "workspace_session", boxName: box.boxName },
      2 * 3600
    );

    res.json({
      message: "Login successful",
      boxName: box.boxName,
      workspaceToken,
      files: (box.files || []).map((f, index) => ({
        index,
        fileId: f.fileId || f.code || `f_${index}`,
        name: f.name,
        size: f.size,
        date: f.date,
        code: f.code,
      })),
    });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Get Workspace files (Strictly requires either workspaceToken or valid PIN—never leaks box when PIN is omitted!)
app.get("/api/workspaces/:boxName", async (req, res) => {
  try {
    const { boxName } = req.params;
    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Workspace not found" });

    let authorized = verifyWorkspaceToken(req, boxName);
    if (!authorized && req.query.pin) {
      const rawPin = String(req.query.pin);
      if (box.pinHash && box.pinSalt) {
        authorized = verifySecret(rawPin, box.pinHash, box.pinSalt);
      } else if (box.pin && box.pin === rawPin) {
        authorized = true;
      }
    }

    if (!authorized) {
      return res.status(401).json({ error: "Workspace authentication required" });
    }

    res.json({
      boxName: box.boxName,
      createdAt: box.createdAt,
      files: (box.files || []).map((f, index) => ({
        index,
        fileId: f.fileId || f.code || `f_${index}`,
        name: f.name,
        size: f.size,
        date: f.date,
        code: f.code,
      })),
    });
  } catch (error) {
    res.status(500).json({ error: "Fetch error" });
  }
});

// Upload to Workspace Box
app.post("/api/workspaces/upload", (req, res) => {
  uploadMiddleware.array("files", SUPPORTED_TYPE_POLICY.maxFilesPerTransfer)(
    req,
    res,
    async (multerErr) => {
      if (multerErr) {
        return res.status(400).json({ error: multerErr.message || "Upload error" });
      }
      try {
        const { boxName, pin } = req.body || {};
        const box = await Workspace.findOne({ boxName });
        if (!box) return res.status(404).json({ error: "Workspace not found" });

        let authorized = verifyWorkspaceToken(req, boxName);
        if (!authorized && pin) {
          if (box.pinHash && box.pinSalt) {
            authorized = verifySecret(pin, box.pinHash, box.pinSalt);
          } else if (box.pin && box.pin === pin) {
            authorized = true;
          }
        }
        if (!authorized) {
          return res.status(401).json({ error: "Unauthorized workspace upload" });
        }

        if (!req.files || req.files.length === 0) {
          return res.status(400).json({ error: "No files provided" });
        }

        const inspections = [];
        for (const file of req.files) {
          const check = inspectUploadedFile(file);
          if (!check.accepted) {
            return res.status(400).json({ error: check.reason });
          }
          inspections.push(check);
        }

        const uploadedFiles = await Promise.all(
          req.files.map((file, idx) =>
            uploadToFirebasePrivate(
              file,
              `ws_${boxName}`,
              `wf_${Date.now()}_${idx}_${generateHighEntropyToken(6)}`,
              inspections[idx]
            )
          )
        );

        const newFiles = uploadedFiles.map((f) => ({
          ...f,
          code: generateRetrievalCode(),
        }));

        box.files.push(...newFiles);
        box.updatedAt = new Date();
        await box.save();

        res.json({
          message: "Files added to workspace",
          files: box.files.map((f, index) => ({
            index,
            fileId: f.fileId || f.code,
            name: f.name,
            size: f.size,
            date: f.date,
            code: f.code,
          })),
        });
      } catch (error) {
        console.error("Box Upload Error:", error);
        res.status(500).json({ error: "Failed to save to workspace" });
      }
    }
  );
});

// Download a file from a Workspace Box (requires Workspace authorization)
app.get("/api/workspaces/:boxName/files/:code/download", async (req, res) => {
  try {
    const { boxName, code } = req.params;
    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Workspace not found" });

    let authorized = verifyWorkspaceToken(req, boxName);
    if (!authorized && req.query.token) {
      const payload = verifySignedToken(String(req.query.token));
      authorized =
        Boolean(payload) &&
        payload.scope === "workspace_session" &&
        payload.boxName === boxName;
    }
    if (!authorized) {
      return res.status(401).json({ error: "Workspace authorization required" });
    }

    const fileObj = (box.files || []).find((f) => f.code === code || f.fileId === code);
    if (!fileObj) return res.status(404).json({ error: "File not found" });

    const signedUrl = await generateBoundedDownloadUrl(
      fileObj,
      new Date(Date.now() + 10 * 60 * 1000),
      req.query.mode !== "inline"
    );

    if (req.query.json === "true") {
      return res.json({ downloadUrl: signedUrl, fileName: sanitizeFilename(fileObj.name) });
    }
    return res.redirect(302, signedUrl);
  } catch (error) {
    res.status(500).json({ error: "Failed to generate workspace download link" });
  }
});

// Delete a file from a Workspace Box (Strictly requires workspace auth or valid PIN)
app.delete("/api/workspaces/:boxName/files/:code", async (req, res) => {
  try {
    const { boxName, code } = req.params;
    const { pin } = req.body || {};
    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Workspace not found" });

    let authorized = verifyWorkspaceToken(req, boxName);
    if (!authorized && pin) {
      if (box.pinHash && box.pinSalt) {
        authorized = verifySecret(pin, box.pinHash, box.pinSalt);
      } else if (box.pin && box.pin === pin) {
        authorized = true;
      }
    }
    if (!authorized) {
      return res.status(401).json({ error: "Unauthorized: Valid workspace session or PIN required" });
    }

    const fileIndex = box.files.findIndex((f) => f.code === code || f.fileId === code);
    if (fileIndex === -1) return res.status(404).json({ error: "File not found" });

    const [removedFile] = box.files.splice(fileIndex, 1);
    await box.save();
    await deleteFromFirebase([removedFile]);

    res.json({
      message: "File deleted from workspace and storage",
      files: box.files.map((f, index) => ({
        index,
        fileId: f.fileId || f.code,
        name: f.name,
        size: f.size,
        date: f.date,
        code: f.code,
      })),
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete file" });
  }
});

// ===== ADMIN AUTH & REPORTING ROUTES =====

app.post("/api/admin/login", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(loginRateMap, `admin:${clientKey}`, 8, 5 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({
        error: "Too many login attempts. Please wait 5 minutes before trying again.",
      });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    const accounts = getAdminAccounts();
    const matched = accounts.find((a) => a.username === username);
    if (!matched || !verifySecret(password, matched.passwordHash, matched.passwordSalt)) {
      await recordAuditLog({
        actor: username || "anonymous",
        role: "unauthenticated",
        action: "admin_login",
        targetType: "session",
        result: "denied",
      });
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const token = createSignedToken(
      {
        scope: "admin_session",
        username: matched.username,
        role: matched.role,
      },
      8 * 3600
    );

    await recordAuditLog({
      actor: matched.username,
      role: matched.role,
      action: "admin_login",
      targetType: "session",
      result: "success",
    });

    res.json({
      token,
      user: {
        username: matched.username,
        role: matched.role,
      },
      expiresInSeconds: 8 * 3600,
    });
  } catch (error) {
    res.status(500).json({ error: "Authentication error" });
  }
});

app.get("/api/admin/session", requireAdminAuth(["admin", "viewer"]), (req, res) => {
  res.json({
    authenticated: true,
    user: req.adminUser,
  });
});

app.post("/api/admin/logout", requireAdminAuth(["admin", "viewer"]), async (req, res) => {
  await recordAuditLog({
    actor: req.adminUser.username,
    role: req.adminUser.role,
    action: "admin_logout",
    targetType: "session",
    result: "success",
  });
  res.json({ message: "Logged out" });
});

// Comprehensive Paginated Admin Transfers & Historical Activity Endpoint
app.get("/api/admin/transfers", requireAdminAuth(["admin", "viewer"]), async (req, res) => {
  try {
    const period = String(req.query.period || "all_retained"); // Default to all retained history so older uploads never hide!
    const timezone = String(req.query.timezone || "Asia/Dubai");
    const view = String(req.query.view || "all"); // "all" | "active" | "historical"
    const statusFilter = String(req.query.status || "all");
    const countryFilter = String(req.query.country || "all");
    const typeFilter = String(req.query.transferType || "all");
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize || "25", 10)));

    const bounds = getDateWindowBounds(
      period,
      timezone,
      String(req.query.startDate || ""),
      String(req.query.endDate || "")
    );

    const mongoQuery = {};
    if (bounds.startUtc || bounds.endUtc) {
      mongoQuery.date = {};
      if (bounds.startUtc) mongoQuery.date.$gte = bounds.startUtc;
      if (bounds.endUtc) mongoQuery.date.$lte = bounds.endUtc;
    }

    if (typeFilter === "anonymous" || typeFilter === "workspace") {
      mongoQuery.transferType = typeFilter;
    }

    // Fetch all matching documents for accurate cross-dataset totals and legacy field normalization,
    // and find the earliest retained record timestamp in the collection.
    const [earliestDoc, allMatchingDocs, workspaceCount, openReportsCount, dailyStatsDocs] =
      await Promise.all([
        Upload.findOne().sort({ date: 1, _id: 1 }).select({ date: 1 }).lean(),
        Upload.find(mongoQuery).sort({ date: -1, _id: -1 }).lean(),
        Workspace.countDocuments(),
        AbuseReport.countDocuments({ status: { $in: ["open", "quarantined"] } }),
        DailyStats.find().sort({ dateKey: -1 }).limit(90).lean(),
      ]);

    const normalizedAll = allMatchingDocs.map((doc) => normalizeTransferForAdmin(doc, true));

    // Apply view, effective status, and normalized country filters
    const filtered = normalizedAll.filter((item) => {
      if (view === "active" && item.status !== "available") return false;
      if (view === "historical" && item.status === "available") return false;
      if (statusFilter !== "all" && item.status !== statusFilter) return false;
      if (countryFilter !== "all") {
        if (countryFilter === "UNKNOWN" && item.countryCode !== null) return false;
        if (countryFilter !== "UNKNOWN" && item.countryCode !== countryFilter) return false;
      }
      return true;
    });

    // Compute exact totals across the complete filtered dataset (not just the visible page)
    let totalTransfers = 0;
    let totalFiles = 0;
    let totalBytes = 0;
    let activeTransfers = 0;
    let activeFiles = 0;
    let historicalTransfers = 0;
    let cleanupPendingCount = 0;
    const countryMap = new Map();
    const dailyMap = new Map();

    for (const item of filtered) {
      totalTransfers += 1;
      totalFiles += item.fileCount;
      totalBytes += item.totalBytes;

      if (item.status === "available") {
        activeTransfers += 1;
        activeFiles += item.fileCount;
      } else {
        historicalTransfers += 1;
      }

      if (item.status === "deletion_pending" || item.lastCleanupError) {
        cleanupPendingCount += 1;
      }

      const cKey = item.countryCode || "UNKNOWN";
      const cEntry = countryMap.get(cKey) || {
        countryCode: item.countryCode,
        countryName: item.countryCode ? item.countryName : "Unknown",
        transfers: 0,
        files: 0,
        bytes: 0,
      };
      cEntry.transfers += 1;
      cEntry.files += item.fileCount;
      cEntry.bytes += item.totalBytes;
      countryMap.set(cKey, cEntry);

      const dayKey = formatDateInTz(item.createdAt, bounds.timezone);
      const dEntry = dailyMap.get(dayKey) || {
        date: dayKey,
        transfers: 0,
        files: 0,
        bytes: 0,
      };
      dEntry.transfers += 1;
      dEntry.files += item.fileCount;
      dEntry.bytes += item.totalBytes;
      dailyMap.set(dayKey, dEntry);
    }

    const totalPages = Math.max(1, Math.ceil(totalTransfers / pageSize));
    const safePage = Math.min(page, totalPages);
    const startIdx = (safePage - 1) * pageSize;
    const pageItems = filtered.slice(startIdx, startIdx + pageSize);

    const countryBreakdown = Array.from(countryMap.values()).sort(
      (a, b) => b.transfers - a.transfers
    );
    const dailySeries = Array.from(dailyMap.values()).sort((a, b) =>
      b.date.localeCompare(a.date)
    );

    res.json({
      items: pageItems,
      pagination: {
        page: safePage,
        pageSize,
        totalItems: totalTransfers,
        totalPages,
        hasNextPage: safePage < totalPages,
        hasPrevPage: safePage > 1,
      },
      totals: {
        totalTransfers,
        totalFiles,
        totalBytes,
        activeTransfers,
        activeFiles,
        historicalTransfers,
        cleanupPendingCount,
        totalWorkspaces: workspaceCount,
        openReportsCount,
      },
      countryBreakdown,
      dailySeries,
      aggregateDailyStats: dailyStatsDocs,
      cleanupStatus: lastCleanupRunSummary,
      trackingMetadata: {
        earliestRetainedRecordAt: earliestDoc?.date
          ? new Date(earliestDoc.date).toISOString()
          : null,
        structuredTrackingImplementedAt: STRUCTURED_TRACKING_STARTED_AT,
        selectedTimezone: bounds.timezone,
        period,
        windowStartUtc: bounds.startUtc ? bounds.startUtc.toISOString() : null,
        windowEndUtc: bounds.endUtc ? bounds.endUtc.toISOString() : null,
        serverTimestampUtc: new Date().toISOString(),
        note: "Uploaded files, 6-digit retrieval codes, and transfer records remain stored permanently until deleted by the sender or removed by an administrator.",
      },
    });
  } catch (error) {
    console.error("Admin transfers query error:", error);
    res.status(500).json({ error: "Failed to load transfer history" });
  }
});

// File-Content Inspection for Authorized Administrators
app.post(
  "/api/admin/transfers/:id/file-access",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { fileIndex = 0, reason = "Admin direct view" } = req.body || {};

      const uploadData = await Upload.findOne({
        $or: [
          { transferId: id },
          ...(mongoose.Types.ObjectId.isValid(id) ? [{ _id: id }] : []),
        ],
      });

      if (!uploadData) {
        return res.status(404).json({ error: "Transfer not found" });
      }

      const files = Array.isArray(uploadData.files) ? uploadData.files : [];
      const targetFile = files[Number(fileIndex)];
      if (!targetFile || targetFile.storageDeleted || uploadData.storageDeletedAt) {
        return res.status(410).json({ error: "File content has already been deleted from storage." });
      }

      const signedUrl = await generateBoundedDownloadUrl(
        targetFile,
        new Date(Date.now() + 15 * 60 * 1000),
        false
      );

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: "open_file_content",
        targetType: "transfer_file",
        targetId: `${uploadData.transferId || uploadData._id}:file_${fileIndex}`,
        reason: String(reason || "Admin direct view").trim().slice(0, 300),
        result: "success",
      });

      res.json({
        downloadUrl: signedUrl,
        expiresInSeconds: 900,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to authorize file content access" });
    }
  }
);

// Trigger Idempotent Storage Cleanup Manually from Admin
app.post("/api/admin/cleanup/run", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const summary = await runStorageCleanupCycle();
    await recordAuditLog({
      actor: req.adminUser.username,
      role: req.adminUser.role,
      action: "manual_cleanup_run",
      targetType: "storage_cleanup",
      result: "success",
      metadata: summary,
    });
    res.json(summary);
  } catch (error) {
    res.status(500).json({ error: "Cleanup cycle failed" });
  }
});

// Admin CSV Export (Formula-injection safe, credentials excluded, audited)
app.get("/api/admin/export", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const period = String(req.query.period || "30d");
    const timezone = String(req.query.timezone || "Asia/Dubai");
    const bounds = getDateWindowBounds(
      period,
      timezone,
      String(req.query.startDate || ""),
      String(req.query.endDate || "")
    );

    const mongoQuery = {};
    if (bounds.startUtc || bounds.endUtc) {
      mongoQuery.date = {};
      if (bounds.startUtc) mongoQuery.date.$gte = bounds.startUtc;
      if (bounds.endUtc) mongoQuery.date.$lte = bounds.endUtc;
    }

    const docs = await Upload.find(mongoQuery).sort({ date: -1, _id: -1 }).limit(2000).lean();
    const rows = docs.map((d) => normalizeTransferForAdmin(d, false));

    const headers = [
      "Transfer ID",
      "Created At (UTC)",
      "Expires At (UTC)",
      "Status",
      "Type",
      "Transfer Label",
      "File Count",
      "Total Bytes",
      "Country Code",
      "Country Name",
      "Location Source",
      "Retrievals",
      "Download Requests",
      "Abuse Reports",
    ];

    const csvLines = [
      headers.join(","),
      ...rows.map((r) =>
        [
          sanitizeCsvCell(r.transferId),
          sanitizeCsvCell(r.createdAt),
          sanitizeCsvCell(r.expiresAt),
          sanitizeCsvCell(r.status),
          sanitizeCsvCell(r.transferType),
          sanitizeCsvCell(r.label),
          sanitizeCsvCell(r.fileCount),
          sanitizeCsvCell(r.totalBytes),
          sanitizeCsvCell(r.countryCode || "UNKNOWN"),
          sanitizeCsvCell(r.countryName),
          sanitizeCsvCell(r.locationSource),
          sanitizeCsvCell(r.retrievalCount),
          sanitizeCsvCell(r.downloadRequestCount),
          sanitizeCsvCell(r.reports),
        ].join(",")
      ),
    ];

    await recordAuditLog({
      actor: req.adminUser.username,
      role: req.adminUser.role,
      action: "export_csv",
      targetType: "transfers",
      reason: `Exported ${rows.length} rows (${period})`,
      result: "success",
    });

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="fylshare-transfers-${getUtcDateKey()}.csv"`
    );
    res.send(csvLines.join("\n"));
  } catch (error) {
    res.status(500).json({ error: "Failed to export CSV" });
  }
});

// Admin Workspaces List (Includes PIN for Admin view)
app.get("/api/admin/workspaces", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const workspaces = await Workspace.find().sort({ createdAt: -1 }).lean();
    res.json(
      workspaces.map((w) => ({
        id: String(w._id),
        boxName: w.boxName,
        pin: w.pin || "—",
        fileCount: Array.isArray(w.files) ? w.files.length : 0,
        totalBytes: (w.files || []).reduce((sum, f) => sum + (Number(f.size) || 0), 0),
        createdAt: w.createdAt,
        updatedAt: w.updatedAt || w.createdAt,
      }))
    );
  } catch (error) {
    res.status(500).json({ error: "Admin workspace fetch error" });
  }
});

app.delete(
  "/api/admin/workspaces/:boxName",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const deleted = await Workspace.findOneAndDelete({ boxName: req.params.boxName });
      if (!deleted) return res.status(404).json({ error: "Box not found" });
      await deleteFromFirebase(deleted.files);

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: "delete_workspace",
        targetType: "workspace",
        targetId: req.params.boxName,
        reason: req.body?.reason || "Admin workspace deletion",
        result: "success",
      });

      res.json({ message: "Workspace and stored files deleted" });
    } catch (error) {
      res.status(500).json({ error: "Delete error" });
    }
  }
);

// Admin Moderation Queue (Abuse Reports)
app.get("/api/admin/reports", requireAdminAuth(["admin", "viewer"]), async (req, res) => {
  try {
    const reports = await AbuseReport.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json(reports);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch abuse reports" });
  }
});

app.post(
  "/api/admin/reports/:reportId/moderate",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { reportId } = req.params;
      const { action, resolutionNote } = req.body || {}; // action: "quarantine" | "remove" | "dismiss"
      const report = await AbuseReport.findOne({ reportId });
      if (!report) return res.status(404).json({ error: "Report not found" });

      if (report.transferId) {
        const transfer = await Upload.findById(report.transferId);
        if (transfer) {
          if (action === "quarantine") {
            transfer.status = "quarantined";
            await transfer.save();
            report.status = "quarantined";
          } else if (action === "remove") {
            await deleteFromFirebase(transfer.files);
            transfer.status = "deleted";
            transfer.storageDeletedAt = new Date();
            transfer.code = null;
            transfer.shareTokenHash = null;
            transfer.name = "[Removed after moderation]";
            transfer.labelRedacted = true;
            await transfer.save();
            report.status = "removed";
          } else if (action === "dismiss") {
            if (transfer.status === "quarantined") {
              transfer.status = "available";
              await transfer.save();
            }
            report.status = "dismissed";
          }
        }
      } else {
        report.status = action === "dismiss" ? "dismissed" : "removed";
      }

      report.reviewedBy = req.adminUser.username;
      report.reviewedAt = new Date();
      report.resolutionNote = resolutionNote ? String(resolutionNote).slice(0, 300) : null;
      await report.save();

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: `moderate_report_${action}`,
        targetType: "abuse_report",
        targetId: reportId,
        reason: report.resolutionNote || action,
        result: "success",
      });

      res.json({ message: "Moderation action recorded", report });
    } catch (error) {
      res.status(500).json({ error: "Failed to moderate report" });
    }
  }
);

// Admin Audit Log Endpoint
app.get("/api/admin/audit", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const logs = await AdminAuditLog.find().sort({ timestamp: -1 }).limit(150).lean();
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

// ===== STARTUP WHEN RUN DIRECTLY =====
if (require.main === module) {
  mongoose
    .connect(MONGO_URI)
    .then(() => {
      console.log("✅ Connected to MongoDB Atlas");
      app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
      });
    })
    .catch((err) => console.error("❌ MongoDB connection error:", err));
}

module.exports = {
  app,
  runStorageCleanupCycle,
  setStorageBucketForTesting,
  normalizeTransferForAdmin,
  getDateWindowBounds,
};
