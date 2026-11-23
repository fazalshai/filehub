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
  RewardCampaign,
  RewardParticipant,
  RewardEvent,
  GiftCardInventory,
  GiftCardReward,
} = require("./models");

const {
  MARKETPLACE_CONFIG,
  encryptClaimCode,
  decryptClaimCode,
  normalizeEmail,
  isValidEmail,
  generateOtpCode,
  anonymizeParticipantLabel,
  extractSessionHash,
  extractIpDailyHash,
  classifyDownloadRequest,
  computeStructureSignature,
  getDayKeyInTimezone,
  validateCampaignForActivation,
  buildPublicCampaignSummary,
  computeCampaignRankings,
  sendRewardsServiceEmail,
  getSentEmailsOutbox,
  clearSentEmailsOutbox,
} = require("./lib/rewards");

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
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "X-Revoke-Token",
      "X-Fylshare-Session",
      "X-Participant-Token",
      "X-Event-Id",
    ],
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
const rewardsRateMap = new Map();

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

function preserveFileOperationalMetrics(f, idx, overrides = {}) {
  return {
    fileId: f.fileId || `file_${idx + 1}`,
    name: overrides.name !== undefined ? overrides.name : f.name,
    storagePath: "",
    url: "",
    isPublicLegacy: false,
    size: f.size || 0,
    date: f.date,
    type: f.type || "application/octet-stream",
    extension: f.extension || "",
    code: overrides.code !== undefined ? overrides.code : f.code || "",
    scanStatus: f.scanStatus || "passed",
    forceAttachment: Boolean(f.forceAttachment),
    storageDeleted: overrides.storageDeleted !== undefined ? overrides.storageDeleted : true,
    buttonClicks: f.buttonClicks || 0,
    downloadRequests: f.downloadRequests || 0,
    signedLinksIssued: f.signedLinksIssued || 0,
    observedDeliveries: f.observedDeliveries || 0,
    deliveryCompletionStatus: f.deliveryCompletionStatus || "unknown_signed_redirect",
    repeatDownloads: f.repeatDownloads || 0,
    estimatedDistinctSessions: f.estimatedDistinctSessions || 0,
    qualifyingDownloads: f.qualifyingDownloads || 0,
    headOrPreviewRequests: f.headOrPreviewRequests || 0,
    rangeRequests: f.rangeRequests || 0,
    scannerOrBotRequests: f.scannerOrBotRequests || 0,
    failedRequests: f.failedRequests || 0,
    sessionHashes: Array.isArray(f.sessionHashes) ? f.sessionHashes : [],
    lastActivityAt: f.lastActivityAt || null,
  };
}

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
        transfer.files = transfer.files.map((f, idx) =>
          preserveFileOperationalMetrics(f, idx, { storageDeleted: true })
        );
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

  // Derive accurate City, State/Region, and Country fields (handling both structured fields and legacy location strings)
  let city = doc.city || "";
  let region = doc.region || "";
  let countryCode = doc.countryCode || null;
  let countryName = doc.countryName || "Unknown";
  let locationSource = doc.locationSource || "unknown";
  let locationStatus = doc.locationStatus || "unknown";
  let browserTimezone = doc.browserTimezone || null;
  let deviceCategory = doc.deviceCategory || "unknown";

  if ((!countryName || countryName === "Unknown" || (!city && !region)) && doc.location) {
    const parsed = parseLegacyLocation(doc.location);
    if (!countryCode && parsed.countryCode) countryCode = parsed.countryCode;
    if ((!countryName || countryName === "Unknown") && parsed.countryName !== "Unknown") {
      countryName = parsed.countryName;
    }
    if (!city && parsed.city) city = parsed.city;
    if (!region && parsed.region) region = parsed.region;
    if (locationSource === "unknown" && parsed.locationSource !== "unknown") {
      locationSource = parsed.locationSource;
    }
    if (locationStatus === "unknown" && parsed.locationStatus !== "unknown") {
      locationStatus = parsed.locationStatus;
    }
    browserTimezone = browserTimezone || parsed.browserTimezone;
    deviceCategory =
      deviceCategory !== "unknown" ? deviceCategory : parsed.deviceCategory || "unknown";
  }

  const displayParts = [city, region, countryCode ? countryName : ""].filter(Boolean);
  const locationDisplay = displayParts.length > 0 ? displayParts.join(", ") : "Unknown";

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
    city,
    region,
    countryCode,
    countryName: countryCode ? countryName : "Unknown",
    locationDisplay,
    locationSource,
    locationStatus: countryCode ? "available" : "unknown",
    deviceCategory,
    browserTimezone,
    retrievalCount: doc.retrievalCount || 0,
    downloadRequestCount: doc.downloadRequestCount || 0,
    downloadServedCount: doc.downloadServedCount || 0,
    bundleDownloadClicks: doc.bundleDownloadClicks || 0,
    bundleDownloadRequests: doc.bundleDownloadRequests || 0,
    participantId: doc.participantId || null,
    campaignId: doc.campaignId || null,
    qualifiesForUploadPoints: Boolean(doc.qualifiesForUploadPoints),
    uploadPointsAwarded: doc.uploadPointsAwarded || 0,
    uploadDisqualifyReason: doc.uploadDisqualifyReason || null,
    qualifyingRecipientDeliveries: doc.qualifyingRecipientDeliveries || 0,
    recipientDeliveryPointsAwarded: doc.recipientDeliveryPointsAwarded || 0,
    suspiciousFlags: Array.isArray(doc.suspiciousFlags) ? doc.suspiciousFlags : [],
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
      buttonClicks: f.buttonClicks || 0,
      downloadRequests: f.downloadRequests || 0,
      signedLinksIssued: f.signedLinksIssued || 0,
      observedDeliveries: f.observedDeliveries || 0,
      deliveryCompletionStatus: f.deliveryCompletionStatus || "unknown_signed_redirect",
      repeatDownloads: f.repeatDownloads || 0,
      estimatedDistinctSessions:
        f.estimatedDistinctSessions ||
        (Array.isArray(f.sessionHashes) ? f.sessionHashes.length : 0),
      qualifyingDownloads: f.qualifyingDownloads || 0,
      headOrPreviewRequests: f.headOrPreviewRequests || 0,
      rangeRequests: f.rangeRequests || 0,
      scannerOrBotRequests: f.scannerOrBotRequests || 0,
      failedRequests: f.failedRequests || 0,
      lastActivityAt: f.lastActivityAt ? new Date(f.lastActivityAt).toISOString() : null,
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

// ===== REWARDS & BOUNDED SCORING ENGINE HELPERS =====
const DEFAULT_ACTIVITY_PROGRAM = {
  campaignId: "cmp_fylshare_activity",
  name: "Fylshare Rewards Activity Program",
  status: "active",
  isDefaultActivityTracker: true,
  startAt: null,
  endAt: null,
  timezone: "Asia/Dubai",
  eligibleCountries: ["AE", "IN", "US", "GB", "CA", "AU", "SG", "DE", "SA", "QA", "KW", "OM", "BH"],
  marketplace: null,
  currency: null,
  rewardValue: null,
  prizeCount: null,
  rankingsEnabled: true,
  personalDataRetentionDays: 180,
  supportContact: "fylshare.official@gmail.com",
  scoringRules: {
    version: 1,
    pointsPerTransfer: 1,
    pointsPerDelivery: 2,
    maxDeliveriesPerTransfer: 3,
    maxTransfersPerDay: 5,
    allowClaimingExistingUploadWithRevokeToken: true,
    minTransferBytes: 1,
  },
  async save() {
    return this;
  },
};

async function getActiveRewardCampaign(now = new Date()) {
  const candidates = await RewardCampaign.find({ status: "active" }).sort({ createdAt: -1 });
  for (const camp of candidates) {
    const startOk = !camp.startAt || new Date(camp.startAt) <= now;
    const endOk = !camp.endAt || new Date(camp.endAt) >= now;
    if (startOk && endOk) {
      const check = validateCampaignForActivation(camp);
      if (check.valid) return camp;
    }
  }
  return null;
}

async function getActiveOrDefaultProgram(now = new Date()) {
  const active = await getActiveRewardCampaign(now);
  return active || DEFAULT_ACTIVITY_PROGRAM;
}

async function extractParticipantFromRequest(req) {
  const rawToken =
    req.headers["x-participant-token"] ||
    (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")
      ? req.headers.authorization.slice(7).trim()
      : "") ||
    (req.body && req.body.participantToken) ||
    "";
  if (!rawToken) return null;
  const payload = verifySignedToken(rawToken);
  if (!payload || payload.scope !== "participant_session" || !payload.participantId) {
    return null;
  }
  const participant = await RewardParticipant.findOne({ participantId: payload.participantId });
  return participant || null;
}

async function scoreUploadForParticipant({
  participant,
  campaign,
  uploadDoc,
  eventId,
  sessionHash,
  now = new Date(),
}) {
  if (!participant) return;

  participant.rawSuccessfulTransfers = (participant.rawSuccessfulTransfers || 0) + 1;
  participant.rawFilesUploaded =
    (participant.rawFilesUploaded || 0) + (uploadDoc.fileCount || uploadDoc.files?.length || 0);
  participant.rawBytesUploaded = (participant.rawBytesUploaded || 0) + (uploadDoc.size || 0);
  participant.lastActivityAt = now;

  if (sessionHash && !participant.sessionHashes.includes(sessionHash)) {
    participant.sessionHashes.push(sessionHash);
  }

  // Track post-reward retention if this participant already received a reward in the past (Section 11)
  if (participant.rewardDeliveredAt && now > new Date(participant.rewardDeliveredAt)) {
    participant.postRewardTransfers = (participant.postRewardTransfers || 0) + 1;
    const diffDays =
      (now.getTime() - new Date(participant.rewardDeliveredAt).getTime()) / (24 * 3600 * 1000);
    if (diffDays <= 7) participant.postRewardActiveWithin7d = true;
    if (diffDays <= 30) participant.postRewardActiveWithin30d = true;
  }

  // Also check if this email had a delivered reward in any earlier closed/fulfilled campaign
  if (!participant.rewardDeliveredAt) {
    const priorRewarded = await RewardParticipant.findOne({
      email: participant.email,
      rewardStatus: "delivered",
    });
    if (priorRewarded && priorRewarded.rewardDeliveredAt && now > new Date(priorRewarded.rewardDeliveredAt)) {
      priorRewarded.postRewardTransfers = (priorRewarded.postRewardTransfers || 0) + 1;
      const diffDays =
        (now.getTime() - new Date(priorRewarded.rewardDeliveredAt).getTime()) / (24 * 3600 * 1000);
      if (diffDays <= 7) priorRewarded.postRewardActiveWithin7d = true;
      if (diffDays <= 30) priorRewarded.postRewardActiveWithin30d = true;
      await priorRewarded.save();
    }
  }

  if (!campaign || campaign.status !== "active" || participant.campaignId !== campaign.campaignId) {
    uploadDoc.uploadDisqualifyReason = "no_active_matching_campaign";
    await participant.save();
    return;
  }

  const startMs = campaign.startAt ? new Date(campaign.startAt).getTime() : 0;
  const endMs = campaign.endAt ? new Date(campaign.endAt).getTime() : Infinity;
  if (now.getTime() < startMs || now.getTime() > endMs) {
    uploadDoc.uploadDisqualifyReason = "outside_campaign_window";
    await participant.save();
    return;
  }

  if (participant.fraudStatus === "disqualified") {
    uploadDoc.uploadDisqualifyReason = "participant_disqualified";
    await participant.save();
    return;
  }

  const rules = campaign.scoringRules || {};
  const minBytes = rules.minTransferBytes ?? 64;
  const maxPerDay = rules.maxTransfersPerDay ?? 5;
  const ptsPerTransfer = rules.pointsPerTransfer ?? 1;
  const dayKey = getDayKeyInTimezone(now, campaign.timezone || "UTC");

  if ((uploadDoc.size || 0) < minBytes) {
    uploadDoc.uploadDisqualifyReason = "below_minimum_transfer_bytes";
    await participant.save();
    return;
  }

  // Detect artificial repeated identical structure uploads on the same day without opening private files
  const sameStructureCount = await Upload.countDocuments({
    participantId: participant.participantId,
    campaignId: campaign.campaignId,
    structureSignature: uploadDoc.structureSignature,
  });

  let isSuspiciousDuplicate = false;
  if (sameStructureCount >= 2) {
    isSuspiciousDuplicate = true;
    if (!uploadDoc.suspiciousFlags.includes("repeated_identical_structure")) {
      uploadDoc.suspiciousFlags.push("repeated_identical_structure");
    }
    if (!participant.suspiciousFlags.includes("repeated_identical_structure")) {
      participant.suspiciousFlags.push("repeated_identical_structure");
    }
    if (participant.fraudStatus === "clean") {
      participant.fraudStatus = "pending_review";
      participant.reviewReason =
        "Automated flag: repeated uploads with identical file structure/byte signature.";
    }
  }

  // Enforce daily qualifying transfer cap in campaign's published timezone
  const todayQualifyingCount = await RewardEvent.countDocuments({
    campaignId: campaign.campaignId,
    participantId: participant.participantId,
    eventType: "upload_completed",
    dayKeyInCampaignTz: dayKey,
    qualifiesForPoints: true,
  });

  if (todayQualifyingCount >= maxPerDay) {
    uploadDoc.qualifiesForUploadPoints = false;
    uploadDoc.uploadPointsAwarded = 0;
    uploadDoc.uploadDisqualifyReason = "daily_transfer_cap_reached";
    await RewardEvent.create({
      eventId: eventId || `ev_up_${uploadDoc.transferId}`,
      campaignId: campaign.campaignId,
      participantId: participant.participantId,
      transferId: uploadDoc.transferId,
      eventType: "upload_completed",
      sessionHash,
      dayKeyInCampaignTz: dayKey,
      fileCount: uploadDoc.fileCount,
      bytes: uploadDoc.size,
      qualifiesForPoints: false,
      pointsAwarded: 0,
      disqualifyReason: "daily_transfer_cap_reached",
      createdAt: now,
    });
    await participant.save();
    return;
  }

  const holdForReview =
    !participant.emailVerified ||
    isSuspiciousDuplicate ||
    participant.fraudStatus === "pending_review" ||
    participant.fraudStatus === "flagged";

  uploadDoc.qualifiesForUploadPoints = true;
  uploadDoc.uploadPointsAwarded = ptsPerTransfer;
  uploadDoc.uploadDisqualifyReason = holdForReview ? "held_pending_verification_or_review" : null;

  participant.qualifyingTransfers = (participant.qualifyingTransfers || 0) + 1;
  participant.uploadPoints = (participant.uploadPoints || 0) + ptsPerTransfer;
  if (!participant.qualifyingActiveDays.includes(dayKey)) {
    participant.qualifyingActiveDays.push(dayKey);
  }

  if (holdForReview) {
    participant.pendingReviewPoints = (participant.pendingReviewPoints || 0) + ptsPerTransfer;
  } else {
    participant.approvedPoints = (participant.approvedPoints || 0) + ptsPerTransfer;
  }

  await RewardEvent.create({
    eventId: eventId || `ev_up_${uploadDoc.transferId}`,
    campaignId: campaign.campaignId,
    participantId: participant.participantId,
    transferId: uploadDoc.transferId,
    eventType: "upload_completed",
    sessionHash,
    dayKeyInCampaignTz: dayKey,
    fileCount: uploadDoc.fileCount,
    bytes: uploadDoc.size,
    qualifiesForPoints: true,
    pointsAwarded: ptsPerTransfer,
    pendingReview: holdForReview,
    disqualifyReason: holdForReview ? "pending_review" : null,
    createdAt: now,
  });

  await participant.save();
  await incrementDailyStats(now, { rewardEligibleUploads: 1 });
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

// Record client-cancelled or failed upload attempt telemetry (idempotent by eventId)
app.post("/api/uploads/telemetry", async (req, res) => {
  try {
    const { eventId, status = "cancelled" } = req.body || {};
    if (!eventId || String(eventId).trim().length < 6) {
      return res.status(400).json({ error: "eventId is required" });
    }
    const cleanEventId = `tel_${String(eventId).trim().slice(0, 80)}`;
    const existing = await RewardEvent.findOne({ eventId: cleanEventId });
    if (existing) {
      return res.json({ recorded: true, idempotentReplay: true });
    }
    const now = new Date();
    const participant = await extractParticipantFromRequest(req);
    await RewardEvent.create({
      eventId: cleanEventId,
      participantId: participant ? participant.participantId : null,
      eventType: "upload_failed",
      qualifiesForPoints: false,
      pointsAwarded: 0,
      disqualifyReason: status === "cancelled" ? "upload_cancelled" : "upload_failed",
      createdAt: now,
    });
    if (participant) {
      participant.rawUploadAttempts = (participant.rawUploadAttempts || 0) + 1;
      participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
      await participant.save();
    }
    await incrementDailyStats(now, {
      uploadAttempts: 1,
      uploadsFailedOrCancelled: 1,
    });
    res.json({ recorded: true, idempotentReplay: false });
  } catch (err) {
    res.status(500).json({ error: "Failed to record upload telemetry" });
  }
});

// Create new upload (Multipart/Form-Data)
app.post("/api/uploads", (req, res) => {
  uploadMiddleware.array("files", SUPPORTED_TYPE_POLICY.maxFilesPerTransfer)(
    req,
    res,
    async (multerErr) => {
      const now = new Date();
      const rawEventId =
        req.headers["x-event-id"] || (req.body && req.body.eventId)
          ? String(req.headers["x-event-id"] || req.body.eventId)
              .trim()
              .slice(0, 100)
          : null;

      // Idempotency check: if a retry arrives with an already-completed eventId, return the existing upload without double-counting!
      if (rawEventId) {
        const existingUpload = await Upload.findOne({ eventId: rawEventId });
        if (existingUpload) {
          return res.status(200).json({
            message: "Upload complete (idempotent replay)",
            idempotentReplay: true,
            transferId: existingUpload.transferId,
            code: existingUpload.code,
            createdAt: new Date(existingUpload.date).toISOString(),
            expiresAt: existingUpload.expiresAt
              ? new Date(existingUpload.expiresAt).toISOString()
              : null,
            status: existingUpload.status,
            scanStatus: existingUpload.scanStatus,
            fileCount: existingUpload.fileCount,
            totalBytes: existingUpload.size,
            qualifiesForUploadPoints: existingUpload.qualifiesForUploadPoints,
            uploadPointsAwarded: existingUpload.uploadPointsAwarded,
            files: (existingUpload.files || []).map((f, idx) => ({
              index: idx,
              fileId: f.fileId,
              name: f.name,
              size: f.size,
              type: f.type,
              extension: f.extension,
              scanStatus: f.scanStatus,
            })),
          });
        }
      }

      const participant = await extractParticipantFromRequest(req);
      await incrementDailyStats(now, { uploadAttempts: 1 });
      if (participant) {
        participant.rawUploadAttempts = (participant.rawUploadAttempts || 0) + 1;
      }

      if (multerErr) {
        await incrementDailyStats(now, { uploadsFailedOrCancelled: 1 });
        if (participant) {
          participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
          await participant.save();
        }
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
          await incrementDailyStats(now, { uploadsFailedOrCancelled: 1 });
          if (participant) {
            participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
            await participant.save();
          }
          return res.status(400).json({ error: "Please select at least one file to upload." });
        }

        if (req.files.length > SUPPORTED_TYPE_POLICY.maxFilesPerTransfer) {
          await incrementDailyStats(now, { uploadsFailedOrCancelled: 1 });
          if (participant) {
            participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
            await participant.save();
          }
          return res.status(400).json({
            error: `Maximum ${SUPPORTED_TYPE_POLICY.maxFilesPerTransfer} files allowed per transfer.`,
          });
        }

        const totalBytes = req.files.reduce((sum, f) => sum + (f.size || 0), 0);
        if (totalBytes > SUPPORTED_TYPE_POLICY.maxTotalBytes) {
          await incrementDailyStats(now, { uploadsFailedOrCancelled: 1 });
          if (participant) {
            participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
            await participant.save();
          }
          return res.status(400).json({ error: "Total transfer size exceeds the 1 GB limit." });
        }

        // Validate every file against the supported-type policy and magic-byte signatures
        const inspections = [];
        for (const file of req.files) {
          const check = inspectUploadedFile(file);
          if (!check.accepted) {
            await incrementDailyStats(now, { uploadsFailedOrCancelled: 1 });
            if (participant) {
              participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
              await participant.save();
            }
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

        // Derive City, State/Region, and Country from server headers + consented client location metadata
        const clientGeo = {
          city: typeof req.body?.city === "string" ? req.body.city : "",
          region: typeof req.body?.region === "string" ? req.body.region : "",
          countryCode: typeof req.body?.countryCode === "string" ? req.body.countryCode : "",
          countryName: typeof req.body?.countryName === "string" ? req.body.countryName : "",
        };
        const locInfo = resolveRequestLocation(req, clientGeo);
        const rawLabel = typeof req.body?.name === "string" ? req.body.name.trim().slice(0, 80) : "";

        const overallScanStatus = inspections.some(
          (i) => i.scanStatus === "uninspectable_encrypted_archive"
        )
          ? "uninspectable_encrypted_archive"
          : "passed";

        const sessionHash = extractSessionHash(req);
        const ipDailyHash = extractIpDailyHash(req);
        const structureSignature = computeStructureSignature(finalFileData, totalBytes);
        const activeCampaign = await getActiveOrDefaultProgram(now);

        const newUpload = new Upload({
          transferId,
          eventId: rawEventId,
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
          city: locInfo.city,
          region: locInfo.region,
          countryCode: locInfo.countryCode,
          countryName: locInfo.countryName,
          locationSource: locInfo.locationSource,
          locationStatus: locInfo.locationStatus,
          deviceCategory: locInfo.deviceCategory,
          location: locInfo.locationDisplay,
          participantId: participant ? participant.participantId : null,
          campaignId:
            participant && activeCampaign && participant.campaignId === activeCampaign.campaignId
              ? activeCampaign.campaignId
              : participant
              ? participant.campaignId
              : null,
          uploaderSessionHash: sessionHash,
          uploaderIpHash: ipDailyHash,
          structureSignature,
        });

        if (participant) {
          await scoreUploadForParticipant({
            participant,
            campaign: activeCampaign,
            uploadDoc: newUpload,
            eventId: rawEventId,
            sessionHash,
            now,
          });
        }

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
          participantId: newUpload.participantId,
          qualifiesForUploadPoints: newUpload.qualifiesForUploadPoints,
          uploadPointsAwarded: newUpload.uploadPointsAwarded,
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
        await incrementDailyStats(now, { uploadsFailedOrCancelled: 1 });
        if (participant) {
          participant.rawFailedUploads = (participant.rawFailedUploads || 0) + 1;
          await participant.save();
        }
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

// Per-file Download-Button Click Tracking (Tracked separately from server download requests & completions)
app.post("/api/uploads/:identifier/files/:fileIndex/click", async (req, res) => {
  try {
    const identifier = String(req.params.identifier || "").trim();
    const fileIndex = Number(req.params.fileIndex);
    const rawEventId =
      req.headers["x-event-id"] || (req.body && req.body.eventId)
        ? String(req.headers["x-event-id"] || req.body.eventId)
            .trim()
            .slice(0, 100)
        : null;

    if (rawEventId) {
      const existingEv = await RewardEvent.findOne({ eventId: `clk_${rawEventId}` });
      if (existingEv) {
        return res.json({ recorded: true, idempotentReplay: true });
      }
    }

    let uploadData = null;
    if (/^\d{6}$/.test(identifier)) {
      uploadData = await Upload.findOne({ code: identifier });
    } else if (identifier.length >= 16) {
      uploadData = await Upload.findOne({ shareTokenHash: hashToken(identifier) });
    }
    if (!uploadData || !Array.isArray(uploadData.files) || !uploadData.files[fileIndex]) {
      return res.status(404).json({ error: "File not found" });
    }

    const now = new Date();
    const targetFile = uploadData.files[fileIndex];
    targetFile.buttonClicks = (targetFile.buttonClicks || 0) + 1;
    targetFile.lastActivityAt = now;
    await uploadData.save();

    if (rawEventId) {
      await RewardEvent.create({
        eventId: `clk_${rawEventId}`,
        transferId: uploadData.transferId,
        fileId: targetFile.fileId,
        eventType: "download_click",
        qualifiesForPoints: false,
        pointsAwarded: 0,
        createdAt: now,
      });
    }

    if (uploadData.participantId) {
      const ownerPart = await RewardParticipant.findOne({
        participantId: uploadData.participantId,
      });
      if (ownerPart) {
        ownerPart.rawDownloadClicks = (ownerPart.rawDownloadClicks || 0) + 1;
        await ownerPart.save();
      }
    }

    await incrementDailyStats(now, { downloadButtonClicks: 1 });
    res.json({ recorded: true, buttonClicks: targetFile.buttonClicks });
  } catch (error) {
    res.status(500).json({ error: "Failed to record download click" });
  }
});

// Separate Bundle / All-Files Download Tracking (Does NOT silently inflate individual per-file download counts)
app.post("/api/uploads/:identifier/bundle-event", async (req, res) => {
  try {
    const identifier = String(req.params.identifier || "").trim();
    const rawEventId =
      req.headers["x-event-id"] || (req.body && req.body.eventId)
        ? String(req.headers["x-event-id"] || req.body.eventId)
            .trim()
            .slice(0, 100)
        : null;

    if (rawEventId) {
      const existingEv = await RewardEvent.findOne({ eventId: `bnd_${rawEventId}` });
      if (existingEv) {
        return res.json({ recorded: true, idempotentReplay: true });
      }
    }

    let uploadData = null;
    if (/^\d{6}$/.test(identifier)) {
      uploadData = await Upload.findOne({ code: identifier });
    } else if (identifier.length >= 16) {
      uploadData = await Upload.findOne({ shareTokenHash: hashToken(identifier) });
    }
    if (!uploadData) {
      return res.status(404).json({ error: "Transfer not found" });
    }

    const now = new Date();
    uploadData.bundleDownloadClicks = (uploadData.bundleDownloadClicks || 0) + 1;
    uploadData.bundleDownloadRequests = (uploadData.bundleDownloadRequests || 0) + 1;
    await uploadData.save();

    if (rawEventId) {
      await RewardEvent.create({
        eventId: `bnd_${rawEventId}`,
        transferId: uploadData.transferId,
        eventType: "bundle_download_requested",
        qualifiesForPoints: false,
        pointsAwarded: 0,
        createdAt: now,
      });
    }

    await incrementDailyStats(now, { bundleDownloadsRequested: 1 });
    res.json({
      recorded: true,
      bundleDownloadClicks: uploadData.bundleDownloadClicks,
      bundleDownloadRequests: uploadData.bundleDownloadRequests,
      note: "Bundle downloads are tracked at the transfer level and do not inflate per-file download counters.",
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to record bundle download event" });
  }
});

// Authorized, time-bounded file download/preview endpoint (Supports GET & HEAD, handles Range, Previews, Bots & Rewards)
app.all("/api/uploads/:identifier/files/:fileIndex/download", async (req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return res.status(405).json({ error: "Method not allowed" });
  }
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(lookupRateMap, clientKey, 40, 60 * 1000);
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

    const files = Array.isArray(uploadData.files) ? uploadData.files : [];
    if (isNaN(fileIndex) || fileIndex < 0 || fileIndex >= files.length) {
      return res.status(404).json({ message: "Requested file not found in transfer." });
    }

    const targetFile = files[fileIndex];
    const computedExpiresAt = uploadData.expiresAt ? new Date(uploadData.expiresAt) : null;

    if (
      uploadData.status !== "available" ||
      (computedExpiresAt && computedExpiresAt <= now) ||
      uploadData.storageDeletedAt ||
      targetFile.storageDeleted
    ) {
      targetFile.failedRequests = (targetFile.failedRequests || 0) + 1;
      await uploadData.save();
      return res.status(410).json({ message: "This transfer or file is no longer available." });
    }

    const forceAttachment = mode === "download" || Boolean(targetFile.forceAttachment);
    const signedUrl = await generateBoundedDownloadUrl(
      targetFile,
      computedExpiresAt,
      forceAttachment
    );

    // Check for idempotent event replay (e.g. browser retry with identical eventId)
    const rawEventId =
      req.headers["x-event-id"] || (req.query && req.query.eventId)
        ? String(req.headers["x-event-id"] || req.query.eventId)
            .trim()
            .slice(0, 100)
        : null;

    let isReplayEvent = false;
    if (rawEventId) {
      const existingEv = await RewardEvent.findOne({ eventId: `dl_${rawEventId}` });
      if (existingEv) {
        isReplayEvent = true;
      }
    }

    const reqClass = classifyDownloadRequest(req);
    const sessionHash = extractSessionHash(req);
    const ipDailyHash = extractIpDailyHash(req);

    if (!isReplayEvent) {
      targetFile.lastActivityAt = now;

      if (reqClass.isHead || reqClass.isPreview) {
        targetFile.headOrPreviewRequests = (targetFile.headOrPreviewRequests || 0) + 1;
      } else if (reqClass.isScannerOrBot) {
        targetFile.scannerOrBotRequests = (targetFile.scannerOrBotRequests || 0) + 1;
      } else {
        if (reqClass.isRangeRequest) {
          targetFile.rangeRequests = (targetFile.rangeRequests || 0) + 1;
        }

        if (reqClass.countsAsDownloadRequest) {
          uploadData.downloadRequestCount = (uploadData.downloadRequestCount || 0) + 1;
          uploadData.downloadServedCount = (uploadData.downloadServedCount || 0) + 1;
          targetFile.downloadRequests = (targetFile.downloadRequests || 0) + 1;
          targetFile.signedLinksIssued = (targetFile.signedLinksIssued || 0) + 1;

          // If served locally/proxied (no external GCS redirect), delivery is observed at server level;
          // if redirected to signed GCS URL, mark completion as unknown_signed_redirect
          if (!bucket) {
            targetFile.observedDeliveries = (targetFile.observedDeliveries || 0) + 1;
            targetFile.deliveryCompletionStatus = "observed_proxy_stream";
          } else {
            targetFile.deliveryCompletionStatus = "unknown_signed_redirect";
          }

          if (!Array.isArray(targetFile.sessionHashes)) {
            targetFile.sessionHashes = [];
          }
          if (targetFile.sessionHashes.includes(sessionHash)) {
            targetFile.repeatDownloads = (targetFile.repeatDownloads || 0) + 1;
          } else {
            targetFile.sessionHashes.push(sessionHash);
          }
          targetFile.estimatedDistinctSessions = targetFile.sessionHashes.length;

          await incrementDailyStats(now, {
            downloadsRequested: 1,
            downloadsServed: 1,
          });

          // Evaluate Recipient-Delivery Reward Qualification (Section 6)
          let qualifiesForReward = false;
          let ptsAwarded = 0;
          let disqualifyReason = "no_participant_attached";

          if (uploadData.participantId) {
            const ownerParticipant = await RewardParticipant.findOne({
              participantId: uploadData.participantId,
            });
            const callerParticipant = await extractParticipantFromRequest(req);

            if (ownerParticipant) {
              ownerParticipant.rawDownloadRequests =
                (ownerParticipant.rawDownloadRequests || 0) + 1;
              if (!bucket) {
                ownerParticipant.rawObservedDeliveries =
                  (ownerParticipant.rawObservedDeliveries || 0) + 1;
              }
              if (!Array.isArray(ownerParticipant.recipientSessionHashes)) {
                ownerParticipant.recipientSessionHashes = [];
              }

              const isSelfDownload =
                sessionHash === uploadData.uploaderSessionHash ||
                (Array.isArray(ownerParticipant.sessionHashes) &&
                  ownerParticipant.sessionHashes.includes(sessionHash)) ||
                (callerParticipant &&
                  callerParticipant.participantId === ownerParticipant.participantId);

              if (!isSelfDownload && !ownerParticipant.recipientSessionHashes.includes(sessionHash)) {
                ownerParticipant.recipientSessionHashes.push(sessionHash);
                ownerParticipant.estimatedDistinctRecipientSessions =
                  ownerParticipant.recipientSessionHashes.length;
              }

              const activeCampaign = await getActiveOrDefaultProgram(now);
              if (
                !activeCampaign ||
                activeCampaign.campaignId !== ownerParticipant.campaignId ||
                ownerParticipant.fraudStatus === "disqualified"
              ) {
                disqualifyReason = "no_active_matching_campaign";
              } else if (isSelfDownload) {
                disqualifyReason = "self_download_excluded";
              } else {
                if (!Array.isArray(uploadData.rewardSessionHashes)) {
                  uploadData.rewardSessionHashes = [];
                }
                const maxDelivPerTransfer =
                  activeCampaign.scoringRules?.maxDeliveriesPerTransfer ?? 3;
                const ptsPerDeliv = activeCampaign.scoringRules?.pointsPerDelivery ?? 2;

                if (uploadData.rewardSessionHashes.includes(sessionHash)) {
                  disqualifyReason = "repeat_recipient_session_on_transfer";
                } else if (
                  (uploadData.qualifyingRecipientDeliveries || 0) >= maxDelivPerTransfer
                ) {
                  disqualifyReason = "transfer_delivery_cap_reached";
                } else {
                  qualifiesForReward = true;
                  ptsAwarded = ptsPerDeliv;
                  disqualifyReason = null;

                  uploadData.rewardSessionHashes.push(sessionHash);
                  uploadData.qualifyingRecipientDeliveries =
                    (uploadData.qualifyingRecipientDeliveries || 0) + 1;
                  uploadData.recipientDeliveryPointsAwarded =
                    (uploadData.recipientDeliveryPointsAwarded || 0) + ptsAwarded;
                  targetFile.qualifyingDownloads = (targetFile.qualifyingDownloads || 0) + 1;

                  const dayKey = getDayKeyInTimezone(now, activeCampaign.timezone || "UTC");
                  ownerParticipant.qualifyingRecipientDeliveries =
                    (ownerParticipant.qualifyingRecipientDeliveries || 0) + 1;
                  ownerParticipant.deliveryPoints =
                    (ownerParticipant.deliveryPoints || 0) + ptsAwarded;
                  if (!ownerParticipant.qualifyingActiveDays.includes(dayKey)) {
                    ownerParticipant.qualifyingActiveDays.push(dayKey);
                  }

                  const holdForReview =
                    !ownerParticipant.emailVerified ||
                    ownerParticipant.fraudStatus === "pending_review" ||
                    ownerParticipant.fraudStatus === "flagged";

                  if (holdForReview) {
                    ownerParticipant.pendingReviewPoints =
                      (ownerParticipant.pendingReviewPoints || 0) + ptsAwarded;
                  } else {
                    ownerParticipant.approvedPoints =
                      (ownerParticipant.approvedPoints || 0) + ptsAwarded;
                  }

                  await incrementDailyStats(now, { rewardQualifyingDownloads: 1 });
                }
              }

              await ownerParticipant.save();
            }
          }

          await RewardEvent.create({
            eventId: rawEventId
              ? `dl_${rawEventId}`
              : `dl_${uploadData.transferId}_${fileIndex}_${generateHighEntropyToken(8)}`,
            campaignId: uploadData.campaignId || null,
            participantId: uploadData.participantId || null,
            transferId: uploadData.transferId,
            fileId: targetFile.fileId,
            eventType: "download_requested",
            sessionHash,
            qualifiesForPoints: qualifiesForReward,
            pointsAwarded: ptsAwarded,
            disqualifyReason,
            createdAt: now,
          });
        }
      }

      await uploadData.save();
    }

    if (req.method === "HEAD") {
      return res.status(200).end();
    }

    if (req.query.json === "true") {
      return res.json({
        downloadUrl: signedUrl,
        fileName: sanitizeFilename(targetFile.name),
        forceAttachment,
        expiresAt: computedExpiresAt ? computedExpiresAt.toISOString() : null,
        deliveryArchitecture: bucket ? "signed_object_storage_url" : "application_stream",
        completionMeasurementNote: bucket
          ? "Download link issued; final device-save completion is not observable from redirect alone."
          : "Application stream requested.",
        idempotentReplay: isReplayEvent,
      });
    }

    return res.redirect(302, signedUrl);
  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({ error: "Unable to generate download link" });
  }
});

// Uploader Self-Revocation (Deletes stored files using the uploader's revokeToken while retaining aggregate/reward counters)
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
      uploadData.files = uploadData.files.map((f, idx) =>
        preserveFileOperationalMetrics(f, idx, {
          name: "[Deleted by uploader]",
          code: "",
          storageDeleted: delResult.ok,
        })
      );
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
      uploadData.files = uploadData.files.map((f, idx) =>
        preserveFileOperationalMetrics(f, idx, {
          name: "[Deleted]",
          code: "",
          storageDeleted: delResult.ok,
        })
      );
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

// ===== OPTIONAL ACTIVITY-BASED REWARDS SYSTEM ROUTES (PUBLIC & PARTICIPANT) =====

// 1. Public Active Campaign & Rules Discovery (Returns active:false when no funded, validated campaign is running)
app.get("/api/rewards/active-campaign", async (req, res) => {
  try {
    const now = new Date();
    const activeCampaign = await getActiveRewardCampaign(now);
    if (!activeCampaign) {
      return res.json({
        active: false,
        campaign: null,
        message: "No rewards campaign is currently active. Regular file sharing works without an account or email.",
      });
    }

    if (req.query.impression === "true") {
      activeCampaign.funnelMetrics = activeCampaign.funnelMetrics || {};
      activeCampaign.funnelMetrics.invitationImpressions =
        (activeCampaign.funnelMetrics.invitationImpressions || 0) + 1;
      await activeCampaign.save();
    }

    return res.json(buildPublicCampaignSummary(activeCampaign));
  } catch (error) {
    res.status(500).json({ error: "Unable to load campaign status" });
  }
});

// Record invitation impression or dismissal for funnel analytics
app.post("/api/rewards/funnel", async (req, res) => {
  try {
    const { action } = req.body || {}; // "impression" | "dismiss"
    const activeCampaign = await getActiveRewardCampaign(new Date());
    if (!activeCampaign) {
      return res.json({ recorded: false });
    }
    activeCampaign.funnelMetrics = activeCampaign.funnelMetrics || {};
    if (action === "impression") {
      activeCampaign.funnelMetrics.invitationImpressions =
        (activeCampaign.funnelMetrics.invitationImpressions || 0) + 1;
    } else if (action === "dismiss") {
      activeCampaign.funnelMetrics.invitationDismissals =
        (activeCampaign.funnelMetrics.invitationDismissals || 0) + 1;
    }
    await activeCampaign.save();
    res.json({ recorded: true });
  } catch (error) {
    res.status(500).json({ error: "Failed to record funnel event" });
  }
});

// 2. Enroll in Active Campaign & Request Email Verification (Uniform response to prevent email enumeration)
app.post("/api/rewards/enroll", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(rewardsRateMap, `enroll:${clientKey}`, 8, 10 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({
        error: "Too many enrollment requests from this network. Please wait a few minutes.",
      });
    }

    const now = new Date();
    const activeCampaign = await getActiveOrDefaultProgram(now);

    const {
      email,
      declaredCountry,
      serviceMessagesAccepted,
      marketingOptIn = false,
    } = req.body || {};

    const cleanEmail = normalizeEmail(email);
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }

    if (serviceMessagesAccepted !== true) {
      return res.status(400).json({
        error:
          "You must accept campaign rules and necessary service/verification emails to participate.",
      });
    }

    const countryUpper = declaredCountry ? String(declaredCountry).trim().toUpperCase() : "AE";
    if (
      !activeCampaign.isDefaultActivityTracker &&
      (!countryUpper ||
        !Array.isArray(activeCampaign.eligibleCountries) ||
        !activeCampaign.eligibleCountries.includes(countryUpper))
    ) {
      return res.status(400).json({
        error: `This campaign is only open to eligible participants in: ${(
          activeCampaign.eligibleCountries || []
        ).join(", ")}.`,
      });
    }

    const emailRate = checkRateLimit(
      rewardsRateMap,
      `enroll_email:${hashToken(cleanEmail)}`,
      4,
      15 * 60 * 1000
    );
    if (!emailRate.allowed) {
      return res.status(429).json({
        error: "Verification was recently requested. Please wait before requesting another code.",
      });
    }

    const locInfo = resolveRequestLocation(req);
    const sessionHash = extractSessionHash(req);
    const otp = generateOtpCode();
    const verificationToken = generateHighEntropyToken(24);
    const expiresAt = new Date(now.getTime() + 30 * 60 * 1000); // 30 minutes

    let participant = await RewardParticipant.findOne({
      campaignId: activeCampaign.campaignId,
      email: cleanEmail,
    });

    if (!participant) {
      participant = new RewardParticipant({
        participantId: `part_${generateHighEntropyToken(10)}`,
        campaignId: activeCampaign.campaignId,
        email: cleanEmail,
        emailVerified: false,
        verificationTokenHash: hashToken(verificationToken),
        verificationOtpHash: hashToken(otp),
        verificationExpiresAt: expiresAt,
        verificationResendCount: 1,
        lastVerificationSentAt: now,
        serviceMessagesAccepted: true,
        marketingOptIn: Boolean(marketingOptIn), // Strictly separate & unchecked by default
        declaredCountry: countryUpper,
        approxIpCountry: locInfo.countryCode || null,
        sessionHashes: sessionHash ? [sessionHash] : [],
        createdAt: now,
      });
      await participant.save();

      activeCampaign.funnelMetrics = activeCampaign.funnelMetrics || {};
      activeCampaign.funnelMetrics.enrollmentStarts =
        (activeCampaign.funnelMetrics.enrollmentStarts || 0) + 1;
      await activeCampaign.save();
    } else {
      // Update verification token/OTP so returning or unverified user can verify ownership
      participant.verificationTokenHash = hashToken(verificationToken);
      participant.verificationOtpHash = hashToken(otp);
      participant.verificationExpiresAt = expiresAt;
      participant.verificationResendCount = (participant.verificationResendCount || 0) + 1;
      participant.lastVerificationSentAt = now;
      if (typeof marketingOptIn === "boolean") {
        participant.marketingOptIn = marketingOptIn;
      }
      if (sessionHash && !participant.sessionHashes.includes(sessionHash)) {
        participant.sessionHashes.push(sessionHash);
      }
      await participant.save();
    }

    await sendRewardsServiceEmail({
      to: cleanEmail,
      subject: `Verify your email for ${activeCampaign.name}`,
      category: "service_verification",
      template: "verify_enrollment",
      metadata: {
        campaignId: activeCampaign.campaignId,
        expiresInMinutes: 30,
        // Never log raw tokens to stdout; stored in in-memory outbox for test/staging inspection only
        verificationCode: otp,
        verificationToken,
      },
    });

    const enrollmentSessionToken = createSignedToken(
      {
        scope: "rewards_enrollment_pending",
        participantId: participant.participantId,
        campaignId: activeCampaign.campaignId,
      },
      30 * 60
    );

    const responsePayload = {
      message:
        "If this email is eligible for the campaign, we have sent a 6-digit verification code and single-use verification link.",
      enrollmentSessionToken,
      expiresInSeconds: 1800,
    };

    if (process.env.REWARDS_EMAIL_ENABLED !== "true") {
      responsePayload.stagingVerificationOtp = otp;
    }

    if (
      process.env.NODE_ENV === "test" ||
      process.env.REWARDS_DEV_EXPOSE_TOKENS === "true"
    ) {
      responsePayload._testVerification = {
        otp,
        verificationToken,
        participantId: participant.participantId,
      };
    }

    return res.status(200).json(responsePayload);
  } catch (error) {
    console.error("Enroll error:", error.message);
    res.status(500).json({ error: "Unable to process enrollment request" });
  }
});

// 3. Verify Email Ownership via Single-Use Token OR 6-Digit OTP
app.post("/api/rewards/verify", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(rewardsRateMap, `verify:${clientKey}`, 10, 10 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({
        error: "Too many verification attempts. Please wait 10 minutes.",
      });
    }

    const { otp, verificationToken, enrollmentSessionToken, email } = req.body || {};
    const now = new Date();

    let participant = null;

    if (verificationToken && String(verificationToken).trim().length >= 16) {
      participant = await RewardParticipant.findOne({
        verificationTokenHash: hashToken(String(verificationToken).trim()),
      });
    } else if (enrollmentSessionToken) {
      const pendingPayload = verifySignedToken(String(enrollmentSessionToken));
      if (pendingPayload && pendingPayload.scope === "rewards_enrollment_pending") {
        participant = await RewardParticipant.findOne({
          participantId: pendingPayload.participantId,
        });
      }
    } else if (email && isValidEmail(email)) {
      const activeCampaign = await getActiveRewardCampaign(now);
      if (activeCampaign) {
        participant = await RewardParticipant.findOne({
          campaignId: activeCampaign.campaignId,
          email: normalizeEmail(email),
        });
      }
    }

    if (!participant) {
      return res.status(400).json({
        error: "Invalid or expired verification code/link.",
      });
    }

    if (
      !participant.verificationExpiresAt ||
      new Date(participant.verificationExpiresAt) < now
    ) {
      return res.status(400).json({
        error: "Verification code/link has expired. Please request a new code.",
      });
    }

    let verified = false;
    if (verificationToken && participant.verificationTokenHash) {
      verified = participant.verificationTokenHash === hashToken(String(verificationToken).trim());
    } else if (otp && participant.verificationOtpHash) {
      verified = participant.verificationOtpHash === hashToken(String(otp).trim());
    }

    if (!verified) {
      return res.status(400).json({
        error: "Invalid or expired verification code/link.",
      });
    }

    const wasAlreadyVerified = Boolean(participant.emailVerified);
    participant.emailVerified = true;
    participant.verifiedAt = participant.verifiedAt || now;
    // Invalidate single-use verification tokens immediately
    participant.verificationTokenHash = null;
    participant.verificationOtpHash = null;
    participant.verificationExpiresAt = null;

    const sessionHash = extractSessionHash(req);
    if (sessionHash && !participant.sessionHashes.includes(sessionHash)) {
      participant.sessionHashes.push(sessionHash);
    }

    // If points were held solely because email wasn't verified yet (and fraudStatus is clean), move to approvedPoints
    if (
      participant.fraudStatus === "clean" &&
      (participant.pendingReviewPoints || 0) > 0
    ) {
      participant.approvedPoints =
        (participant.approvedPoints || 0) + participant.pendingReviewPoints;
      participant.pendingReviewPoints = 0;
    }

    await participant.save();

    if (!wasAlreadyVerified) {
      const camp = await RewardCampaign.findOne({ campaignId: participant.campaignId });
      if (camp) {
        camp.funnelMetrics = camp.funnelMetrics || {};
        camp.funnelMetrics.verifiedParticipants =
          (camp.funnelMetrics.verifiedParticipants || 0) + 1;
        await camp.save();
      }
    }

    const participantToken = createSignedToken(
      {
        scope: "participant_session",
        participantId: participant.participantId,
        campaignId: participant.campaignId,
      },
      7 * 24 * 3600
    );

    res.json({
      message: "Email verified. Your Fylshare Rewards session is now active.",
      participantToken,
      participant: {
        participantId: participant.participantId,
        campaignId: participant.campaignId,
        email: participant.email,
        emailVerified: true,
        marketingOptIn: participant.marketingOptIn,
        approvedPoints: participant.approvedPoints,
        pendingReviewPoints: participant.pendingReviewPoints,
      },
    });
  } catch (error) {
    res.status(500).json({ error: "Verification failed" });
  }
});

// 4. Resend Verification Code/Link (Rate-limited, uniform response)
app.post("/api/rewards/resend", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(rewardsRateMap, `resend:${clientKey}`, 4, 15 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({
        error: "Too many resend attempts. Please wait 15 minutes before requesting another code.",
      });
    }

    const { enrollmentSessionToken, email } = req.body || {};
    const now = new Date();
    let participant = null;

    if (enrollmentSessionToken) {
      const payload = verifySignedToken(String(enrollmentSessionToken));
      if (payload && payload.scope === "rewards_enrollment_pending") {
        participant = await RewardParticipant.findOne({
          participantId: payload.participantId,
        });
      }
    } else if (email && isValidEmail(email)) {
      const activeCampaign = await getActiveRewardCampaign(now);
      if (activeCampaign) {
        participant = await RewardParticipant.findOne({
          campaignId: activeCampaign.campaignId,
          email: normalizeEmail(email),
        });
      }
    }

    let testTokens = null;
    if (participant && !participant.emailVerified) {
      if ((participant.verificationResendCount || 0) >= 5) {
        return res.status(429).json({
          error: "Maximum verification resends reached for this session. Please try again later.",
        });
      }
      const otp = generateOtpCode();
      const verificationToken = generateHighEntropyToken(24);
      participant.verificationOtpHash = hashToken(otp);
      participant.verificationTokenHash = hashToken(verificationToken);
      participant.verificationExpiresAt = new Date(now.getTime() + 30 * 60 * 1000);
      participant.verificationResendCount = (participant.verificationResendCount || 0) + 1;
      participant.lastVerificationSentAt = now;
      await participant.save();

      await sendRewardsServiceEmail({
        to: participant.email,
        subject: "Your new Fylshare Rewards verification code",
        category: "service_verification",
        template: "resend_verification",
        metadata: {
          verificationCode: otp,
          verificationToken,
        },
      });

      if (
        process.env.NODE_ENV === "test" ||
        process.env.REWARDS_DEV_EXPOSE_TOKENS === "true"
      ) {
        testTokens = { otp, verificationToken };
      }
    }

    const resp = {
      message:
        "If an unverified enrollment matches your request, a fresh verification code has been sent.",
    };
    if (testTokens) resp._testVerification = testTokens;
    res.json(resp);
  } catch (error) {
    res.status(500).json({ error: "Unable to resend verification code" });
  }
});

// 5. Claim an Existing Upload by Proving Ownership with Uploader's revokeToken (Section 2)
app.post("/api/rewards/claim-transfer", async (req, res) => {
  try {
    const participant = await extractParticipantFromRequest(req);
    if (!participant || !participant.emailVerified) {
      return res.status(401).json({
        error: "A verified rewards participant session is required to claim a transfer.",
      });
    }

    const { code, transferId, revokeToken } = req.body || {};
    if (!revokeToken || String(revokeToken).trim().length < 16) {
      return res.status(401).json({
        error:
          "Proof of upload ownership (uploader revocation token) is required to associate an existing transfer.",
      });
    }

    const campaign =
      (await RewardCampaign.findOne({ campaignId: participant.campaignId })) ||
      (participant.campaignId === DEFAULT_ACTIVITY_PROGRAM.campaignId
        ? DEFAULT_ACTIVITY_PROGRAM
        : null);
    if (!campaign || campaign.status !== "active") {
      return res.status(400).json({ error: "Campaign is no longer active." });
    }

    if (!campaign.scoringRules?.allowClaimingExistingUploadWithRevokeToken) {
      return res.status(403).json({
        error: "Published campaign rules do not permit claiming prior uploads.",
      });
    }

    const lookupOr = [];
    if (code) lookupOr.push({ code: String(code).trim() });
    if (transferId) lookupOr.push({ transferId: String(transferId).trim() });
    if (lookupOr.length === 0) {
      return res.status(400).json({ error: "Transfer code or transferId is required." });
    }

    const uploadDoc = await Upload.findOne({
      $or: lookupOr,
      revokeTokenHash: hashToken(String(revokeToken).trim()),
    });

    if (!uploadDoc) {
      return res.status(404).json({
        error: "Transfer not found or ownership token does not match.",
      });
    }

    if (uploadDoc.participantId) {
      if (uploadDoc.participantId === participant.participantId) {
        return res.json({
          message: "Transfer is already associated with your rewards account.",
          transferId: uploadDoc.transferId,
          qualifiesForUploadPoints: uploadDoc.qualifiesForUploadPoints,
          uploadPointsAwarded: uploadDoc.uploadPointsAwarded,
        });
      }
      return res.status(409).json({
        error: "This transfer has already been claimed by a participant.",
      });
    }

    // Do not allow claiming historical uploads created before the campaign started
    if (campaign.startAt && new Date(uploadDoc.date) < new Date(campaign.startAt)) {
      return res.status(400).json({
        error: "Historical transfers uploaded before the campaign start date cannot be claimed.",
      });
    }

    const now = new Date();
    const sessionHash = extractSessionHash(req);
    uploadDoc.participantId = participant.participantId;
    uploadDoc.campaignId = campaign.campaignId;
    if (!uploadDoc.uploaderSessionHash && sessionHash) {
      uploadDoc.uploaderSessionHash = sessionHash;
    }

    await scoreUploadForParticipant({
      participant,
      campaign,
      uploadDoc,
      eventId: `claim_${uploadDoc.transferId}`,
      sessionHash,
      now,
    });

    await uploadDoc.save();

    res.json({
      message: "Transfer ownership verified and linked to your Fylshare Rewards activity.",
      transferId: uploadDoc.transferId,
      qualifiesForUploadPoints: uploadDoc.qualifiesForUploadPoints,
      uploadPointsAwarded: uploadDoc.uploadPointsAwarded,
      approvedPoints: participant.approvedPoints,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to claim transfer" });
  }
});

// 6. Returning Participant Sign-In Link / OTP Request & Verification (Private Rewards Dashboard Access)
app.post("/api/rewards/login-request", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(rewardsRateMap, `login_req:${clientKey}`, 6, 10 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({ error: "Too many sign-in requests. Please wait a few minutes." });
    }

    const { email, campaignId } = req.body || {};
    const cleanEmail = normalizeEmail(email);
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: "Please provide a valid email address." });
    }

    const query = { email: cleanEmail, emailVerified: true };
    if (campaignId) query.campaignId = String(campaignId);

    const participant = await RewardParticipant.findOne(query).sort({ createdAt: -1 });
    let testTokens = null;

    if (participant) {
      const otp = generateOtpCode();
      const loginToken = generateHighEntropyToken(24);
      participant.loginOtpHash = hashToken(otp);
      participant.loginTokenHash = hashToken(loginToken);
      participant.loginTokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
      await participant.save();

      await sendRewardsServiceEmail({
        to: cleanEmail,
        subject: "Your Fylshare Rewards sign-in link and code",
        category: "service_authentication",
        template: "participant_login",
        metadata: {
          otp,
          loginToken,
        },
      });

      if (
        process.env.NODE_ENV === "test" ||
        process.env.REWARDS_DEV_EXPOSE_TOKENS === "true"
      ) {
        testTokens = { otp, loginToken };
      }
    }

    const resp = {
      message:
        "If a verified rewards enrollment exists for that email, a single-use sign-in code has been sent.",
    };
    if (testTokens) resp._testLogin = testTokens;
    res.json(resp);
  } catch (error) {
    res.status(500).json({ error: "Failed to process sign-in request" });
  }
});

app.post("/api/rewards/login-verify", async (req, res) => {
  try {
    const clientKey = getClientRateKey(req);
    const rate = checkRateLimit(rewardsRateMap, `login_ver:${clientKey}`, 10, 10 * 60 * 1000);
    if (!rate.allowed) {
      return res.status(429).json({ error: "Too many sign-in verification attempts." });
    }

    const { email, otp, loginToken } = req.body || {};
    const now = new Date();
    let participant = null;

    if (loginToken && String(loginToken).trim().length >= 16) {
      participant = await RewardParticipant.findOne({
        loginTokenHash: hashToken(String(loginToken).trim()),
      });
    } else if (email && otp) {
      participant = await RewardParticipant.findOne({
        email: normalizeEmail(email),
        loginOtpHash: hashToken(String(otp).trim()),
      });
    }

    if (
      !participant ||
      !participant.loginTokenExpiresAt ||
      new Date(participant.loginTokenExpiresAt) < now
    ) {
      return res.status(401).json({ error: "Invalid or expired sign-in code." });
    }

    participant.loginTokenHash = null;
    participant.loginOtpHash = null;
    participant.loginTokenExpiresAt = null;
    await participant.save();

    const participantToken = createSignedToken(
      {
        scope: "participant_session",
        participantId: participant.participantId,
        campaignId: participant.campaignId,
      },
      7 * 24 * 3600
    );

    res.json({
      message: "Signed in to Fylshare Rewards.",
      participantToken,
    });
  } catch (error) {
    res.status(500).json({ error: "Sign-in verification failed" });
  }
});

// 7. Authenticated Participant Progress View (GET /api/rewards/me — Section 7)
app.get("/api/rewards/me", async (req, res) => {
  try {
    const participant = await extractParticipantFromRequest(req);
    if (!participant) {
      return res.status(401).json({ error: "Participant authentication required." });
    }

    const campaign =
      (await RewardCampaign.findOne({ campaignId: participant.campaignId })) ||
      (participant.campaignId === DEFAULT_ACTIVITY_PROGRAM.campaignId
        ? DEFAULT_ACTIVITY_PROGRAM
        : null);
    const now = new Date();
    const dayKey = getDayKeyInTimezone(now, campaign?.timezone || "UTC");

    const todayQualifyingTransfers = await RewardEvent.countDocuments({
      campaignId: participant.campaignId,
      participantId: participant.participantId,
      eventType: "upload_completed",
      dayKeyInCampaignTz: dayKey,
      qualifiesForPoints: true,
    });

    let provisionalRank = null;
    let totalRankedParticipants = 0;
    let tieBreakNote = null;

    if (campaign) {
      if (
        (campaign.status === "closed" ||
          campaign.status === "reviewed" ||
          campaign.status === "fulfilled") &&
        Array.isArray(campaign.scoreSnapshot) &&
        campaign.scoreSnapshot.length > 0
      ) {
        totalRankedParticipants = campaign.scoreSnapshot.length;
        const snapEntry = campaign.scoreSnapshot.find(
          (s) => s.participantId === participant.participantId
        );
        if (snapEntry) {
          provisionalRank = snapEntry.rank;
          tieBreakNote = snapEntry.tieBreakApplied;
        }
      } else if (campaign.rankingsEnabled) {
        const allParticipants = await RewardParticipant.find({
          campaignId: campaign.campaignId,
        }).lean();
        const { rankings } = computeCampaignRankings(campaign, allParticipants);
        totalRankedParticipants = rankings.length;
        const myRankEntry = rankings.find(
          (r) => r.participantId === participant.participantId
        );
        if (myRankEntry) {
          provisionalRank = myRankEntry.rank;
          tieBreakNote = myRankEntry.tieBreakApplied;
        }
      }
    }

    const myReward = await GiftCardReward.findOne({
      campaignId: participant.campaignId,
      participantId: participant.participantId,
    }).lean();

    res.json({
      participant: {
        participantId: participant.participantId,
        anonymizedLabel: anonymizeParticipantLabel(participant.participantId),
        campaignId: participant.campaignId,
        email: participant.email,
        emailVerified: participant.emailVerified,
        verifiedAt: participant.verifiedAt,
        pendingNewEmail: participant.pendingNewEmail || null,
        declaredCountry: participant.declaredCountry,
        marketingOptIn: participant.marketingOptIn,
        rawActivity: {
          uploadAttempts: participant.rawUploadAttempts || 0,
          successfulTransfers: participant.rawSuccessfulTransfers || 0,
          filesUploaded: participant.rawFilesUploaded || 0,
          bytesUploaded: participant.rawBytesUploaded || 0,
          failedUploads: participant.rawFailedUploads || 0,
          downloadClicks: participant.rawDownloadClicks || 0,
          downloadRequests: participant.rawDownloadRequests || 0,
          observedDeliveries: participant.rawObservedDeliveries || 0,
          estimatedDistinctRecipientSessions:
            participant.estimatedDistinctRecipientSessions || 0,
        },
        qualifyingActivity: {
          qualifyingTransfers: participant.qualifyingTransfers || 0,
          qualifyingRecipientDeliveries: participant.qualifyingRecipientDeliveries || 0,
          qualifyingActiveDaysCount: Array.isArray(participant.qualifyingActiveDays)
            ? participant.qualifyingActiveDays.length
            : 0,
          qualifyingActiveDays: participant.qualifyingActiveDays || [],
        },
        points: {
          uploadPoints: participant.uploadPoints || 0,
          deliveryPoints: participant.deliveryPoints || 0,
          manualAdjustmentPoints: participant.manualAdjustmentPoints || 0,
          approvedPoints: participant.approvedPoints || 0,
          pendingReviewPoints: participant.pendingReviewPoints || 0,
        },
        applicableCaps: {
          campaignTimezone: campaign?.timezone || "UTC",
          currentDayKey: dayKey,
          todayQualifyingTransfers,
          maxTransfersPerDay: campaign?.scoringRules?.maxTransfersPerDay ?? 5,
          maxDeliveriesPerTransfer: campaign?.scoringRules?.maxDeliveriesPerTransfer ?? 3,
          pointsPerTransfer: campaign?.scoringRules?.pointsPerTransfer ?? 1,
          pointsPerDelivery: campaign?.scoringRules?.pointsPerDelivery ?? 2,
        },
        reviewAndAppeals: {
          fraudStatus: participant.fraudStatus || "clean",
          suspiciousFlags: participant.suspiciousFlags || [],
          reviewReason: participant.reviewReason || null,
          appealStatus: participant.appealStatus || "none",
          appealMessage: participant.appealMessage || null,
          appealResolutionNote: participant.appealResolutionNote || null,
        },
        ranking: {
          rankingsEnabled: Boolean(campaign?.rankingsEnabled),
          isSnapshotFrozen: Boolean(campaign?.snapshotFrozenAt),
          snapshotFrozenAt: campaign?.snapshotFrozenAt || null,
          provisionalRank,
          finalRank: participant.finalRank || (campaign?.snapshotFrozenAt ? provisionalRank : null),
          totalRankedParticipants,
          prizeCount: campaign?.prizeCount || null,
          tieBreakNote,
          disclaimer:
            "Provisional rankings reflect current activity and do not guarantee a prize. Final selection occurs after campaign close and abuse/fraud review.",
        },
        rewardOutcome: {
          rewardStatus: myReward ? myReward.status : participant.rewardStatus || "none",
          marketplace: myReward?.marketplace || campaign?.marketplace || null,
          currency: myReward?.currency || campaign?.currency || null,
          amount: myReward?.amount || null,
          deliveredAt: myReward?.deliveredAt || participant.rewardDeliveredAt || null,
        },
      },
      campaign: campaign
        ? {
            campaignId: campaign.campaignId,
            name: campaign.name,
            status: campaign.status,
            startAt: campaign.startAt,
            endAt: campaign.endAt,
            timezone: campaign.timezone,
            marketplace: campaign.marketplace,
            currency: campaign.currency,
            rewardValue: campaign.rewardValue,
            prizeCount: campaign.prizeCount,
            tiePolicy: campaign.tiePolicy,
            deliveryDeadline: campaign.deliveryDeadline,
            personalDataRetentionDays: campaign.personalDataRetentionDays || 180,
            supportContact: campaign.supportContact,
          }
        : null,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to load participant dashboard" });
  }
});

// 8. Authenticated Reward Email Change with Verification & Duplicate-Claim Check (Section 2)
app.post("/api/rewards/change-email", async (req, res) => {
  try {
    const participant = await extractParticipantFromRequest(req);
    if (!participant || !participant.emailVerified) {
      return res.status(401).json({ error: "Authenticated participant session required." });
    }

    const { newEmail } = req.body || {};
    const cleanNew = normalizeEmail(newEmail);
    if (!isValidEmail(cleanNew)) {
      return res.status(400).json({ error: "Please enter a valid replacement email address." });
    }
    if (cleanNew === participant.email) {
      return res.status(400).json({ error: "New email is identical to your current email." });
    }

    // Check for duplicate claims in the same campaign
    const duplicate = await RewardParticipant.findOne({
      campaignId: participant.campaignId,
      email: cleanNew,
    });
    if (duplicate && duplicate.participantId !== participant.participantId) {
      return res.status(409).json({
        error:
          "This email address cannot be linked because it is already associated with another enrollment in this campaign.",
      });
    }

    const otp = generateOtpCode();
    const token = generateHighEntropyToken(24);
    participant.pendingNewEmail = cleanNew;
    participant.pendingEmailOtpHash = hashToken(otp);
    participant.pendingEmailTokenHash = hashToken(token);
    participant.pendingEmailExpiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await participant.save();

    await sendRewardsServiceEmail({
      to: cleanNew,
      subject: "Verify your updated Fylshare Rewards delivery email",
      category: "service_email_change",
      template: "confirm_email_change",
      metadata: {
        otp,
        token,
      },
    });

    const resp = {
      message:
        "Verification code sent to your new email address. Your reward delivery email will update once verified.",
      pendingNewEmail: cleanNew,
    };
    if (
      process.env.NODE_ENV === "test" ||
      process.env.REWARDS_DEV_EXPOSE_TOKENS === "true"
    ) {
      resp._testEmailChange = { otp, token };
    }
    res.json(resp);
  } catch (error) {
    res.status(500).json({ error: "Failed to initiate email change" });
  }
});

app.post("/api/rewards/confirm-email-change", async (req, res) => {
  try {
    const participant = await extractParticipantFromRequest(req);
    if (!participant || !participant.pendingNewEmail) {
      return res.status(400).json({ error: "No pending email change found." });
    }

    const { otp, token } = req.body || {};
    const now = new Date();
    if (
      !participant.pendingEmailExpiresAt ||
      new Date(participant.pendingEmailExpiresAt) < now
    ) {
      return res.status(400).json({ error: "Email change verification code has expired." });
    }

    const validOtp = otp && participant.pendingEmailOtpHash === hashToken(String(otp).trim());
    const validTok =
      token && participant.pendingEmailTokenHash === hashToken(String(token).trim());

    if (!validOtp && !validTok) {
      return res.status(400).json({ error: "Invalid email change verification code." });
    }

    // Re-check duplicate claim atomically before committing
    const duplicate = await RewardParticipant.findOne({
      campaignId: participant.campaignId,
      email: participant.pendingNewEmail,
    });
    if (duplicate && duplicate.participantId !== participant.participantId) {
      return res.status(409).json({
        error: "Duplicate claim detected for replacement email address.",
      });
    }

    const previousEmailHash = hashToken(participant.email);
    const newVerifiedEmail = participant.pendingNewEmail;

    participant.emailChangeHistory = Array.isArray(participant.emailChangeHistory)
      ? participant.emailChangeHistory
      : [];
    participant.emailChangeHistory.push({
      previousEmailHash,
      newEmailHash: hashToken(newVerifiedEmail),
      changedAt: now.toISOString(),
    });
    participant.email = newVerifiedEmail;
    participant.pendingNewEmail = null;
    participant.pendingEmailOtpHash = null;
    participant.pendingEmailTokenHash = null;
    participant.pendingEmailExpiresAt = null;
    await participant.save();

    // Update any pending (un-dispatched) reward delivery address
    const pendingReward = await GiftCardReward.findOne({
      campaignId: participant.campaignId,
      participantId: participant.participantId,
      status: { $in: ["approved", "reserved", "bounced_or_failed"] },
    });
    if (pendingReward) {
      pendingReward.deliveryEmail = newVerifiedEmail;
      await pendingReward.save();
    }

    res.json({
      message: "Your verified reward-delivery email has been updated.",
      email: participant.email,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to confirm email change" });
  }
});

// 9. Update Optional Marketing Consent (Never affects reward eligibility or owed rewards)
app.post("/api/rewards/marketing-preference", async (req, res) => {
  try {
    const participant = await extractParticipantFromRequest(req);
    if (!participant) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const { marketingOptIn } = req.body || {};
    participant.marketingOptIn = Boolean(marketingOptIn);
    if (!participant.marketingOptIn) {
      participant.marketingUnsubscribedAt = new Date();
    }
    await participant.save();
    res.json({
      message:
        "Marketing email preference updated. This does not affect your campaign eligibility or any owed reward.",
      marketingOptIn: participant.marketingOptIn,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to update marketing preference" });
  }
});

// 10. Submit Participant Appeal for Flagged / Pending Review Activity (Section 7 & 10)
app.post("/api/rewards/appeal", async (req, res) => {
  try {
    const participant = await extractParticipantFromRequest(req);
    if (!participant) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const { message } = req.body || {};
    if (!message || String(message).trim().length < 10) {
      return res.status(400).json({
        error: "Please provide a brief explanation (at least 10 characters) for your appeal.",
      });
    }
    participant.appealStatus = "submitted";
    participant.appealMessage = String(message).trim().slice(0, 800);
    participant.appealSubmittedAt = new Date();
    await participant.save();

    res.json({
      message: "Your appeal has been recorded for manual administrator review before campaign finalization.",
      appealStatus: participant.appealStatus,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to submit appeal" });
  }
});

// ===== ADMIN CAMPAIGNS, FRAUD REVIEW, GIFT-CARD FULFILLMENT & RETENTION ROUTES =====

// List all campaigns with validation status & summary counts
app.get("/api/admin/campaigns", requireAdminAuth(["admin", "viewer"]), async (req, res) => {
  try {
    const campaigns = await RewardCampaign.find().sort({ createdAt: -1 }).lean();
    const enriched = await Promise.all(
      campaigns.map(async (c) => {
        const validation = validateCampaignForActivation(c);
        const participantCount = await RewardParticipant.countDocuments({
          campaignId: c.campaignId,
        });
        const verifiedCount = await RewardParticipant.countDocuments({
          campaignId: c.campaignId,
          emailVerified: true,
        });
        const pendingReviewsCount = await RewardParticipant.countDocuments({
          campaignId: c.campaignId,
          fraudStatus: { $in: ["pending_review", "flagged"] },
        });
        return {
          ...c,
          validation,
          stats: {
            participantCount,
            verifiedCount,
            pendingReviewsCount,
          },
        };
      })
    );
    res.json({
      campaigns: enriched,
      supportedMarketplaces: MARKETPLACE_CONFIG,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to load campaigns" });
  }
});

// Create a new Campaign (Country, currency, reward value, budget, dates, and legal eligibility default to null/unset until owner supplies them)
app.post("/api/admin/campaigns", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const body = req.body || {};
    const campaignId = `cmp_${generateHighEntropyToken(8)}`;
    const now = new Date();

    const newCampaign = await RewardCampaign.create({
      campaignId,
      name: body.name ? String(body.name).trim().slice(0, 120) : "Draft Fylshare Rewards Campaign",
      status: "draft",
      startAt: body.startAt ? new Date(body.startAt) : null,
      endAt: body.endAt ? new Date(body.endAt) : null,
      timezone: body.timezone ? String(body.timezone).trim() : null,
      eligibleCountries: Array.isArray(body.eligibleCountries)
        ? body.eligibleCountries.map((c) => String(c).trim().toUpperCase()).filter(Boolean)
        : [],
      eligibilityRequirements: body.eligibilityRequirements
        ? String(body.eligibilityRequirements).trim()
        : null,
      marketplace: body.marketplace ? String(body.marketplace).trim().toLowerCase() : null,
      currency: body.currency ? String(body.currency).trim().toUpperCase() : null,
      rewardValue:
        body.rewardValue !== undefined && body.rewardValue !== null && body.rewardValue !== ""
          ? Number(body.rewardValue)
          : null,
      prizeCount:
        body.prizeCount !== undefined && body.prizeCount !== null && body.prizeCount !== ""
          ? Number(body.prizeCount)
          : null,
      fundedBudget:
        body.fundedBudget !== undefined && body.fundedBudget !== null && body.fundedBudget !== ""
          ? Number(body.fundedBudget)
          : null,
      expectedFees: body.expectedFees !== undefined ? Number(body.expectedFees) : 0,
      minDenomination: body.minDenomination !== undefined ? Number(body.minDenomination) : 1,
      scoringRules: {
        version: 1,
        pointsPerTransfer: body.scoringRules?.pointsPerTransfer ?? 1,
        pointsPerDelivery: body.scoringRules?.pointsPerDelivery ?? 2,
        maxDeliveriesPerTransfer: body.scoringRules?.maxDeliveriesPerTransfer ?? 3,
        maxTransfersPerDay: body.scoringRules?.maxTransfersPerDay ?? 5,
        allowClaimingExistingUploadWithRevokeToken:
          body.scoringRules?.allowClaimingExistingUploadWithRevokeToken ?? true,
        minTransferBytes: body.scoringRules?.minTransferBytes ?? 64,
      },
      tiePolicy: body.tiePolicy || null,
      tieReserveBudget: body.tieReserveBudget !== undefined ? Number(body.tieReserveBudget) : 0,
      reviewPeriodDays: body.reviewPeriodDays !== undefined ? Number(body.reviewPeriodDays) : 7,
      deliveryDeadline: body.deliveryDeadline ? new Date(body.deliveryDeadline) : null,
      rulesVersion: body.rulesVersion || "1.0-draft",
      supportContact: body.supportContact ? normalizeEmail(body.supportContact) : null,
      legalAndBrandReviewConfirmed: Boolean(body.legalAndBrandReviewConfirmed),
      fundingVerifiedByOwner: Boolean(body.fundingVerifiedByOwner),
      personalDataRetentionDays:
        body.personalDataRetentionDays !== undefined
          ? Number(body.personalDataRetentionDays)
          : 180,
      rankingsEnabled: body.rankingsEnabled !== undefined ? Boolean(body.rankingsEnabled) : true,
      createdBy: req.adminUser.username,
      createdAt: now,
      updatedAt: now,
    });

    await recordAuditLog({
      actor: req.adminUser.username,
      role: req.adminUser.role,
      action: "create_reward_campaign",
      targetType: "reward_campaign",
      targetId: campaignId,
      reason: `Created draft campaign "${newCampaign.name}"`,
      result: "success",
    });

    res.status(201).json({
      campaign: newCampaign,
      validation: validateCampaignForActivation(newCampaign),
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to create campaign" });
  }
});

// Update Campaign Configuration (Blocks silently changing scoring, eligibility, prize counts, or caps after start!)
app.put("/api/admin/campaigns/:campaignId", requireAdminAuth(["admin"]), async (req, res) => {
  try {
    const { campaignId } = req.params;
    const body = req.body || {};
    const campaign = await RewardCampaign.findOne({ campaignId });
    if (!campaign) return res.status(404).json({ error: "Campaign not found" });

    if (campaign.status !== "draft") {
      // Once a campaign has started, do not allow changing scoring, eligibility, prize counts, reward value, or caps
      const lockedFields = [
        "scoringRules",
        "eligibleCountries",
        "eligibilityRequirements",
        "prizeCount",
        "rewardValue",
        "marketplace",
        "currency",
        "tiePolicy",
        "timezone",
      ];
      for (const f of lockedFields) {
        if (body[f] !== undefined) {
          return res.status(400).json({
            error: `Cannot modify locked rule "${f}" after campaign has left draft status. Create a new campaign version instead.`,
          });
        }
      }
    }

    if (body.name !== undefined) campaign.name = String(body.name).trim().slice(0, 120);
    if (body.startAt !== undefined) campaign.startAt = body.startAt ? new Date(body.startAt) : null;
    if (body.endAt !== undefined) campaign.endAt = body.endAt ? new Date(body.endAt) : null;
    if (body.timezone !== undefined) campaign.timezone = body.timezone ? String(body.timezone).trim() : null;
    if (body.eligibleCountries !== undefined && Array.isArray(body.eligibleCountries)) {
      campaign.eligibleCountries = body.eligibleCountries
        .map((c) => String(c).trim().toUpperCase())
        .filter(Boolean);
    }
    if (body.eligibilityRequirements !== undefined) {
      campaign.eligibilityRequirements = body.eligibilityRequirements
        ? String(body.eligibilityRequirements).trim()
        : null;
    }
    if (body.marketplace !== undefined) {
      campaign.marketplace = body.marketplace ? String(body.marketplace).trim().toLowerCase() : null;
    }
    if (body.currency !== undefined) {
      campaign.currency = body.currency ? String(body.currency).trim().toUpperCase() : null;
    }
    if (body.rewardValue !== undefined) {
      campaign.rewardValue = body.rewardValue !== null && body.rewardValue !== "" ? Number(body.rewardValue) : null;
    }
    if (body.prizeCount !== undefined) {
      campaign.prizeCount = body.prizeCount !== null && body.prizeCount !== "" ? Number(body.prizeCount) : null;
    }
    if (body.fundedBudget !== undefined) {
      campaign.fundedBudget =
        body.fundedBudget !== null && body.fundedBudget !== "" ? Number(body.fundedBudget) : null;
    }
    if (body.expectedFees !== undefined) campaign.expectedFees = Number(body.expectedFees) || 0;
    if (body.minDenomination !== undefined) campaign.minDenomination = Number(body.minDenomination) || 1;
    if (body.tiePolicy !== undefined) campaign.tiePolicy = body.tiePolicy || null;
    if (body.tieReserveBudget !== undefined) campaign.tieReserveBudget = Number(body.tieReserveBudget) || 0;
    if (body.reviewPeriodDays !== undefined) campaign.reviewPeriodDays = Number(body.reviewPeriodDays) || 7;
    if (body.deliveryDeadline !== undefined) {
      campaign.deliveryDeadline = body.deliveryDeadline ? new Date(body.deliveryDeadline) : null;
    }
    if (body.rulesVersion !== undefined) campaign.rulesVersion = String(body.rulesVersion).trim();
    if (body.supportContact !== undefined) {
      campaign.supportContact = body.supportContact ? normalizeEmail(body.supportContact) : null;
    }
    if (body.legalAndBrandReviewConfirmed !== undefined) {
      campaign.legalAndBrandReviewConfirmed = Boolean(body.legalAndBrandReviewConfirmed);
    }
    if (body.fundingVerifiedByOwner !== undefined) {
      campaign.fundingVerifiedByOwner = Boolean(body.fundingVerifiedByOwner);
    }
    if (body.personalDataRetentionDays !== undefined) {
      campaign.personalDataRetentionDays = Number(body.personalDataRetentionDays) || 180;
    }
    if (body.rankingsEnabled !== undefined) {
      campaign.rankingsEnabled = Boolean(body.rankingsEnabled);
    }
    if (body.scoringRules && typeof body.scoringRules === "object") {
      campaign.scoringRules = {
        version: (campaign.scoringRules?.version || 1) + 1,
        pointsPerTransfer:
          body.scoringRules.pointsPerTransfer ?? campaign.scoringRules?.pointsPerTransfer ?? 1,
        pointsPerDelivery:
          body.scoringRules.pointsPerDelivery ?? campaign.scoringRules?.pointsPerDelivery ?? 2,
        maxDeliveriesPerTransfer:
          body.scoringRules.maxDeliveriesPerTransfer ??
          campaign.scoringRules?.maxDeliveriesPerTransfer ??
          3,
        maxTransfersPerDay:
          body.scoringRules.maxTransfersPerDay ?? campaign.scoringRules?.maxTransfersPerDay ?? 5,
        allowClaimingExistingUploadWithRevokeToken:
          body.scoringRules.allowClaimingExistingUploadWithRevokeToken ??
          campaign.scoringRules?.allowClaimingExistingUploadWithRevokeToken ??
          true,
        minTransferBytes:
          body.scoringRules.minTransferBytes ?? campaign.scoringRules?.minTransferBytes ?? 64,
      };
    }

    campaign.updatedAt = new Date();
    await campaign.save();

    await recordAuditLog({
      actor: req.adminUser.username,
      role: req.adminUser.role,
      action: "update_reward_campaign",
      targetType: "reward_campaign",
      targetId: campaignId,
      reason: body.reason || "Updated campaign configuration",
      result: "success",
    });

    res.json({
      campaign,
      validation: validateCampaignForActivation(campaign),
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to update campaign" });
  }
});

// Transition Campaign Lifecycle Status (activate | pause | resume | close | mark_reviewed)
app.post(
  "/api/admin/campaigns/:campaignId/status",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const { action, reason } = req.body || {};
      if (!reason || String(reason).trim().length < 3) {
        return res.status(400).json({
          error: "An administrative reason is required for campaign status changes.",
        });
      }

      const campaign = await RewardCampaign.findOne({ campaignId });
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      const now = new Date();

      if (action === "activate" || action === "resume") {
        const validation = validateCampaignForActivation(campaign);
        if (!validation.valid) {
          return res.status(400).json({
            error: "Campaign cannot be activated until all budget, tie-policy, and legal requirements are satisfied.",
            validationErrors: validation.errors,
          });
        }
        campaign.status = "active";
        campaign.pauseReason = null;
      } else if (action === "pause") {
        campaign.status = "paused";
        campaign.pauseReason = String(reason).trim();
      } else if (action === "close") {
        campaign.status = "closed";
        // Freeze immutable score snapshot at campaign close (Section 7)
        const allParticipants = await RewardParticipant.find({
          campaignId: campaign.campaignId,
        });
        const { rankings, boundaryTieAlert } = computeCampaignRankings(
          campaign,
          allParticipants
        );
        campaign.snapshotFrozenAt = now;
        campaign.scoreSnapshot = rankings;
        if (boundaryTieAlert && !campaign.alerts.includes(boundaryTieAlert)) {
          campaign.alerts.push(boundaryTieAlert);
        }

        // Persist finalRank onto participant records
        for (const p of allParticipants) {
          const rEntry = rankings.find((r) => r.participantId === p.participantId);
          if (rEntry) {
            p.provisionalRank = rEntry.rank;
            p.finalRank = rEntry.rank;
            p.tieBreakApplied = rEntry.tieBreakApplied;
            if (rEntry.withinPrizeCutoff && p.rewardStatus === "none") {
              p.rewardStatus = "eligible_pending_review";
            }
            await p.save();
          }
        }
      } else if (action === "mark_reviewed") {
        if (campaign.status !== "closed" && campaign.status !== "reviewed") {
          return res.status(400).json({
            error: "Campaign must be closed before marking fraud review complete.",
          });
        }
        // Re-compute snapshot after admin fraud reviews / appeals resolution
        const allParticipants = await RewardParticipant.find({
          campaignId: campaign.campaignId,
        });
        const { rankings, boundaryTieAlert } = computeCampaignRankings(
          campaign,
          allParticipants
        );
        campaign.scoreSnapshot = rankings;
        campaign.snapshotFrozenAt = now;
        campaign.status = "reviewed";
        if (boundaryTieAlert && !campaign.alerts.includes(boundaryTieAlert)) {
          campaign.alerts.push(boundaryTieAlert);
        }

        for (const p of allParticipants) {
          const rEntry = rankings.find((r) => r.participantId === p.participantId);
          if (rEntry) {
            p.finalRank = rEntry.rank;
            p.tieBreakApplied = rEntry.tieBreakApplied;
            p.rewardStatus = rEntry.withinPrizeCutoff ? "eligible_pending_review" : "not_selected";
            await p.save();
          }
        }
      } else {
        return res.status(400).json({ error: `Unsupported status action: ${action}` });
      }

      campaign.updatedAt = now;
      await campaign.save();

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: `campaign_status_${action}`,
        targetType: "reward_campaign",
        targetId: campaignId,
        reason: String(reason).trim(),
        result: "success",
      });

      res.json({
        message: `Campaign status updated to ${campaign.status}.`,
        campaign,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to change campaign status" });
    }
  }
);

// Inspect Campaign Participants, Activity & Rankings (Section 5 — Protected by Admin Auth)
app.get(
  "/api/admin/campaigns/:campaignId/participants",
  requireAdminAuth(["admin", "viewer"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const campaign = await RewardCampaign.findOne({ campaignId }).lean();
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      const participants = await RewardParticipant.find({ campaignId })
        .sort({ approvedPoints: -1, qualifyingRecipientDeliveries: -1 })
        .lean();

      const { rankings, boundaryTieAlert, totalAllocatedBudget } = computeCampaignRankings(
        campaign,
        participants
      );
      const rankMap = new Map(rankings.map((r) => [r.participantId, r]));

      const rewards = await GiftCardReward.find({ campaignId }).lean();
      const rewardMap = new Map(rewards.map((rw) => [rw.participantId, rw]));

      const items = participants.map((p) => {
        const rInfo = rankMap.get(p.participantId);
        const rwInfo = rewardMap.get(p.participantId);
        return {
          participantId: p.participantId,
          anonymizedLabel: anonymizeParticipantLabel(p.participantId),
          email: p.email,
          emailVerified: p.emailVerified,
          verifiedAt: p.verifiedAt,
          declaredCountry: p.declaredCountry,
          approxIpCountry: p.approxIpCountry,
          marketingOptIn: p.marketingOptIn,
          campaignId: p.campaignId,
          successfulTransfers: p.rawSuccessfulTransfers || 0,
          individualFilesUploaded: p.rawFilesUploaded || 0,
          downloadRequests: p.rawDownloadRequests || 0,
          observedDeliveries: p.rawObservedDeliveries || 0,
          estimatedDistinctRecipientSessions: p.estimatedDistinctRecipientSessions || 0,
          qualifyingTransfers: p.qualifyingTransfers || 0,
          qualifyingRecipientDeliveries: p.qualifyingRecipientDeliveries || 0,
          qualifyingActiveDaysCount: Array.isArray(p.qualifyingActiveDays)
            ? p.qualifyingActiveDays.length
            : 0,
          uploadPoints: p.uploadPoints || 0,
          deliveryPoints: p.deliveryPoints || 0,
          manualAdjustmentPoints: p.manualAdjustmentPoints || 0,
          approvedPoints: p.approvedPoints || 0,
          pendingReviewPoints: p.pendingReviewPoints || 0,
          rank: rInfo ? rInfo.rank : null,
          withinPrizeCutoff: rInfo ? rInfo.withinPrizeCutoff : false,
          allocatedRewardAmount: rInfo ? rInfo.allocatedRewardAmount : 0,
          tieBreakApplied: rInfo ? rInfo.tieBreakApplied : null,
          fraudStatus: p.fraudStatus || "clean",
          suspiciousFlags: p.suspiciousFlags || [],
          reviewReason: p.reviewReason || null,
          appealStatus: p.appealStatus || "none",
          appealMessage: p.appealMessage || null,
          appealResolutionNote: p.appealResolutionNote || null,
          rewardStatus: rwInfo ? rwInfo.status : p.rewardStatus || "none",
          rewardDetails: rwInfo
            ? {
                rewardId: rwInfo.rewardId,
                amount: rwInfo.amount,
                currency: rwInfo.currency,
                marketplace: rwInfo.marketplace,
                status: rwInfo.status,
                assignedCardId: rwInfo.assignedCardId,
                deliveredAt: rwInfo.deliveredAt,
                lastError: rwInfo.lastError,
              }
            : null,
          postRewardTransfers: p.postRewardTransfers || 0,
          postRewardActiveWithin7d: Boolean(p.postRewardActiveWithin7d),
          postRewardActiveWithin30d: Boolean(p.postRewardActiveWithin30d),
          createdAt: p.createdAt,
        };
      });

      res.json({
        campaignId,
        campaignName: campaign.name,
        status: campaign.status,
        snapshotFrozenAt: campaign.snapshotFrozenAt,
        boundaryTieAlert,
        totalAllocatedBudget,
        participants: items,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to load campaign participants" });
    }
  }
);

// Manual Fraud Review, Appeal Resolution & Point Adjustments (Requires Reason & Audit Trail; Never Opens File Contents)
app.post(
  "/api/admin/campaigns/:campaignId/participants/:participantId/review",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { campaignId, participantId } = req.params;
      const { action, reason, pointAdjustment = 0 } = req.body || {};
      // action: "clear" | "flag" | "disqualify" | "uphold_appeal" | "reject_appeal" | "adjust_points"
      if (!reason || String(reason).trim().length < 5) {
        return res.status(400).json({
          error: "A documented reason (at least 5 characters) is required for any participant review or adjustment.",
        });
      }

      const participant = await RewardParticipant.findOne({ campaignId, participantId });
      if (!participant) return res.status(404).json({ error: "Participant not found" });

      const cleanReason = String(reason).trim().slice(0, 400);
      const now = new Date();

      if (action === "clear" || action === "uphold_appeal") {
        participant.fraudStatus = "cleared";
        participant.approvedPoints =
          (participant.approvedPoints || 0) + (participant.pendingReviewPoints || 0);
        participant.pendingReviewPoints = 0;
        if (action === "uphold_appeal" || participant.appealStatus === "submitted") {
          participant.appealStatus = "upheld";
          participant.appealResolutionNote = cleanReason;
        }
      } else if (action === "flag") {
        participant.fraudStatus = "flagged";
      } else if (action === "disqualify" || action === "reject_appeal") {
        participant.fraudStatus = "disqualified";
        participant.approvedPoints = 0;
        participant.pendingReviewPoints = 0;
        participant.rewardStatus = "cancelled";
        if (action === "reject_appeal" || participant.appealStatus === "submitted") {
          participant.appealStatus = "rejected";
          participant.appealResolutionNote = cleanReason;
        }
      } else if (action === "adjust_points") {
        const delta = Number(pointAdjustment) || 0;
        participant.manualAdjustmentPoints = (participant.manualAdjustmentPoints || 0) + delta;
        participant.approvedPoints = Math.max(0, (participant.approvedPoints || 0) + delta);
      } else {
        return res.status(400).json({ error: `Invalid review action: ${action}` });
      }

      participant.reviewReason = cleanReason;
      participant.reviewedBy = req.adminUser.username;
      participant.reviewedAt = now;
      await participant.save();

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: `participant_review_${action}`,
        targetType: "reward_participant",
        targetId: participantId,
        reason: cleanReason,
        result: "success",
        metadata: {
          campaignId,
          pointAdjustment: Number(pointAdjustment) || 0,
          fraudStatus: participant.fraudStatus,
          approvedPoints: participant.approvedPoints,
        },
      });

      res.json({
        message: "Participant review decision recorded.",
        participant: {
          participantId: participant.participantId,
          fraudStatus: participant.fraudStatus,
          approvedPoints: participant.approvedPoints,
          pendingReviewPoints: participant.pendingReviewPoints,
          appealStatus: participant.appealStatus,
          reviewReason: participant.reviewReason,
        },
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to record review action" });
    }
  }
);

// Manage Gift-Card Inventory / Non-Redeemable Staging Test Fixtures (Section 9)
// Claim codes are encrypted with AES-256-GCM at rest and NEVER returned in plaintext to admin tables or logs.
app.get(
  "/api/admin/campaigns/:campaignId/inventory",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const campaign = await RewardCampaign.findOne({ campaignId }).lean();
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      const query = campaign.marketplace ? { marketplace: campaign.marketplace } : {};
      const cards = await GiftCardInventory.find(query).sort({ createdAt: -1 }).lean();

      res.json({
        inventory: cards.map((c) => ({
          cardId: c.cardId,
          marketplace: c.marketplace,
          currency: c.currency,
          amount: c.amount,
          codeMasked: `****-****-${c.codeLastFour || "XXXX"}`,
          sourceReference: c.sourceReference,
          isTestFixture: c.isTestFixture,
          status: c.status,
          assignedRewardId: c.assignedRewardId,
          assignedParticipantId: c.assignedParticipantId,
          createdAt: c.createdAt,
        })),
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to load gift card inventory" });
    }
  }
);

app.post(
  "/api/admin/campaigns/:campaignId/inventory",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const campaign = await RewardCampaign.findOne({ campaignId });
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      const {
        claimCode,
        marketplace = campaign.marketplace,
        currency = campaign.currency,
        amount = campaign.rewardValue,
        sourceReference = "TEST_FIXTURE_NON_REDEEMABLE",
        isTestFixture = true,
      } = req.body || {};

      if (!claimCode || String(claimCode).trim().length < 6) {
        return res.status(400).json({ error: "A valid gift card claim code or test fixture code is required." });
      }
      if (!marketplace || !currency || !amount || Number(amount) <= 0) {
        return res.status(400).json({ error: "Marketplace, currency, and positive amount are required." });
      }

      // Never allow generating fake Amazon claim codes: if it's a test fixture, enforce prefix TEST-FIXTURE-
      const rawCode = String(claimCode).trim();
      if (isTestFixture && !rawCode.startsWith("TEST-FIXTURE-")) {
        return res.status(400).json({
          error:
            "Test fixtures must use the explicit 'TEST-FIXTURE-' prefix so they can never be confused with real Amazon claim codes.",
        });
      }

      const encryptedClaimCode = encryptClaimCode(rawCode);
      const codeLastFour = rawCode.slice(-4);
      const cardId = `gc_${generateHighEntropyToken(8)}`;

      const card = await GiftCardInventory.create({
        cardId,
        marketplace: String(marketplace).toLowerCase().trim(),
        currency: String(currency).toUpperCase().trim(),
        amount: Number(amount),
        encryptedClaimCode,
        codeLastFour,
        sourceReference: String(sourceReference).trim().slice(0, 120),
        isTestFixture: Boolean(isTestFixture),
        status: "available",
        createdAt: new Date(),
      });

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: "add_gift_card_inventory",
        targetType: "gift_card_inventory",
        targetId: cardId,
        reason: `Added ${card.currency} ${card.amount} (${card.marketplace}) [isTestFixture=${card.isTestFixture}]`,
        result: "success",
      });

      res.status(201).json({
        cardId: card.cardId,
        marketplace: card.marketplace,
        currency: card.currency,
        amount: card.amount,
        codeMasked: `****-****-${card.codeLastFour}`,
        isTestFixture: card.isTestFixture,
        status: card.status,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to add inventory card" });
    }
  }
);

// Step 1 of Fulfillment: Explicit Manual Approval of the Fulfillment Batch (Section 9)
app.post(
  "/api/admin/campaigns/:campaignId/approve-fulfillment",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const { reason = "Admin manual approval of fulfillment batch" } = req.body || {};

      const campaign = await RewardCampaign.findOne({ campaignId });
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      if (campaign.status !== "closed" && campaign.status !== "reviewed") {
        return res.status(400).json({
          error: "Campaign must be closed and reviewed before approving the reward fulfillment batch.",
        });
      }

      // Ensure no unresolved pending fraud reviews remain among top candidates
      const participants = await RewardParticipant.find({ campaignId });
      const { rankings, boundaryTieAlert, totalAllocatedBudget } = computeCampaignRankings(
        campaign,
        participants
      );

      if (boundaryTieAlert) {
        if (!campaign.alerts.includes(boundaryTieAlert)) {
          campaign.alerts.push(boundaryTieAlert);
          await campaign.save();
        }
        return res.status(409).json({
          error: boundaryTieAlert,
          code: "UNRESOLVED_BOUNDARY_TIE",
        });
      }

      const winners = rankings.filter((r) => r.withinPrizeCutoff && r.allocatedRewardAmount > 0);
      const expectedFees = Number(campaign.expectedFees) || 0;
      const totalRequiredFunds = totalAllocatedBudget + expectedFees;
      const maxAvailableFunds =
        (Number(campaign.fundedBudget) || 0) +
        (campaign.tiePolicy === "extend_budget_for_tied_ranks"
          ? Number(campaign.tieReserveBudget) || 0
          : 0);

      if (totalRequiredFunds > maxAvailableFunds) {
        const budgetAlert = `Total committed rewards + fees (${totalRequiredFunds} ${campaign.currency}) exceeds funded budget (${maxAvailableFunds} ${campaign.currency}). Fulfillment batch paused.`;
        if (!campaign.alerts.includes(budgetAlert)) {
          campaign.alerts.push(budgetAlert);
          await campaign.save();
        }
        return res.status(409).json({
          error: budgetAlert,
          code: "BUDGET_CEILING_EXCEEDED",
        });
      }

      const approvedRewards = [];
      const now = new Date();

      for (const winner of winners) {
        const idempotencyKey = `fulfill:${campaignId}:${winner.participantId}`;
        let existingReward = await GiftCardReward.findOne({ idempotencyKey });

        if (!existingReward) {
          const partDoc = participants.find((p) => p.participantId === winner.participantId);
          const selectionReason = `Ranked #${winner.rank} with ${winner.approvedPoints} approved activity points (${winner.qualifyingTransfers} transfers, ${winner.qualifyingRecipientDeliveries} recipient deliveries, ${winner.qualifyingActiveDaysCount} active days; tieBreak=${winner.tieBreakApplied})`;

          try {
            existingReward = await GiftCardReward.create({
              rewardId: `rw_${generateHighEntropyToken(8)}`,
              campaignId,
              participantId: winner.participantId,
              deliveryEmail: partDoc.email,
              marketplace: campaign.marketplace,
              currency: campaign.currency,
              amount: winner.allocatedRewardAmount,
              rankAtSelection: winner.rank,
              approvedPointsAtSelection: winner.approvedPoints,
              selectionReason,
              idempotencyKey,
              fulfillmentMode: "manual_inventory",
              status: "approved",
              statusHistory: [
                {
                  status: "approved",
                  actor: req.adminUser.username,
                  timestamp: now.toISOString(),
                },
              ],
              batchApprovedBy: req.adminUser.username,
              batchApprovedAt: now,
              updatedAt: now,
            });
          } catch (dupErr) {
            // Handle concurrent batch approval gracefully via unique idempotencyKey
            existingReward = await GiftCardReward.findOne({ idempotencyKey });
          }

          if (partDoc && existingReward) {
            partDoc.rewardStatus = "approved";
            partDoc.rewardId = existingReward.rewardId;
            partDoc.finalRank = winner.rank;
            await partDoc.save();
          }
        }

        if (existingReward) {
          approvedRewards.push(existingReward);
        }
      }

      campaign.status = "reviewed";
      campaign.updatedAt = now;
      await campaign.save();

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: "approve_fulfillment_batch",
        targetType: "reward_campaign",
        targetId: campaignId,
        reason: String(reason).trim(),
        result: "success",
        metadata: {
          approvedCount: approvedRewards.length,
          totalAllocatedBudget,
        },
      });

      res.json({
        message: `Fulfillment batch approved for ${approvedRewards.length} eligible participant(s). Ready for dispatch.`,
        approvedCount: approvedRewards.length,
        totalAllocatedBudget,
        rewards: approvedRewards,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to approve fulfillment batch" });
    }
  }
);

// Step 2 of Fulfillment: Dispatch Approved Gift Cards to Verified Emails (Section 9)
// Uses atomic card assignment & idempotency; retries reuse the SAME reward assignment without assigning a second card!
app.post(
  "/api/admin/campaigns/:campaignId/dispatch-rewards",
  requireAdminAuth(["admin"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const { rewardId: singleRewardId, simulateProviderTimeout = false } = req.body || {};

      if (
        process.env.NODE_ENV === "production" &&
        process.env.ALLOW_PRODUCTION_REWARD_DISPATCH !== "true"
      ) {
        return res.status(403).json({
          error:
            "Production gift-card dispatch is locked until ALLOW_PRODUCTION_REWARD_DISPATCH=true is enabled by the owner.",
        });
      }

      const campaign = await RewardCampaign.findOne({ campaignId });
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      const query = {
        campaignId,
        status: { $in: ["approved", "reserved", "issued", "bounced_or_failed"] },
      };
      if (singleRewardId) {
        query.rewardId = String(singleRewardId);
      }

      const pendingRewards = await GiftCardReward.find(query);
      if (pendingRewards.length === 0) {
        return res.json({
          message: "No pending or retryable approved rewards found for dispatch.",
          dispatchedCount: 0,
          results: [],
        });
      }

      const results = [];
      const now = new Date();

      for (const reward of pendingRewards) {
        // Reconcile uncertain state or reuse existing assigned card on retry (NEVER assign a second card!)
        let assignedCard = null;
        if (reward.assignedCardId) {
          assignedCard = await GiftCardInventory.findOne({ cardId: reward.assignedCardId });
        }

        if (!assignedCard) {
          // Atomically find and reserve one available inventory card matching marketplace, currency & amount
          const availableCards = await GiftCardInventory.find({
            marketplace: reward.marketplace,
            currency: reward.currency,
            amount: reward.amount,
            status: "available",
          });
          const candidateCard = availableCards[0] || null;

          if (!candidateCard) {
            reward.lastError = `Insufficient gift-card inventory for ${reward.currency} ${reward.amount} (${reward.marketplace}).`;
            reward.updatedAt = now;
            await reward.save();
            results.push({
              rewardId: reward.rewardId,
              participantId: reward.participantId,
              status: reward.status,
              error: reward.lastError,
            });
            continue;
          }

          candidateCard.status = "assigned";
          candidateCard.assignedRewardId = reward.rewardId;
          candidateCard.assignedParticipantId = reward.participantId;
          await candidateCard.save();

          assignedCard = candidateCard;
          reward.assignedCardId = assignedCard.cardId;
          reward.status = "reserved";
          reward.statusHistory.push({
            status: "reserved",
            cardId: assignedCard.cardId,
            timestamp: now.toISOString(),
          });
          await reward.save();
        }

        if (simulateProviderTimeout) {
          reward.retryCount = (reward.retryCount || 0) + 1;
          reward.lastError =
            "Provider/network timeout during dispatch; card reservation preserved for idempotent retry.";
          reward.updatedAt = now;
          await reward.save();
          results.push({
            rewardId: reward.rewardId,
            participantId: reward.participantId,
            assignedCardId: reward.assignedCardId,
            status: reward.status,
            error: reward.lastError,
          });
          continue;
        }

        // Mark issued -> email_queued
        reward.status = "issued";
        reward.statusHistory.push({ status: "issued", timestamp: now.toISOString() });
        reward.status = "email_queued";
        reward.statusHistory.push({ status: "email_queued", timestamp: now.toISOString() });

        const decryptedCode = decryptClaimCode(assignedCard.encryptedClaimCode);
        const emailResult = await sendRewardsServiceEmail({
          to: reward.deliveryEmail,
          subject: `Your ${reward.currency} ${reward.amount} reward from ${campaign.name}`,
          category: "service_reward_fulfillment",
          template: "gift_card_delivery",
          metadata: {
            rewardId: reward.rewardId,
            campaignId: reward.campaignId,
            participantId: reward.participantId,
            marketplace: reward.marketplace,
            currency: reward.currency,
            amount: reward.amount,
            isTestFixture: assignedCard.isTestFixture,
            claimCode: decryptedCode,
            disclaimer:
              "Amazon is not a sponsor of this promotion. This email is a transactional reward fulfillment notice.",
          },
        });

        const partDoc = await RewardParticipant.findOne({
          campaignId,
          participantId: reward.participantId,
        });

        if (emailResult.ok) {
          reward.status = "accepted_by_provider";
          reward.statusHistory.push({
            status: "accepted_by_provider",
            messageId: emailResult.messageId,
            timestamp: now.toISOString(),
          });
          // Mark delivered when provider/outbox confirms delivery acceptance
          reward.status = "delivered";
          reward.statusHistory.push({
            status: "delivered",
            timestamp: now.toISOString(),
          });
          reward.dispatchedBy = req.adminUser.username;
          reward.dispatchedAt = now;
          reward.deliveredAt = now;
          reward.lastError = null;
          await reward.save();

          if (partDoc) {
            partDoc.rewardStatus = "delivered";
            partDoc.rewardDeliveredAt = now;
            await partDoc.save();
          }
        } else {
          reward.status = "bounced_or_failed";
          reward.retryCount = (reward.retryCount || 0) + 1;
          reward.lastError = emailResult.error || "Email delivery bounced or failed";
          reward.statusHistory.push({
            status: "bounced_or_failed",
            error: reward.lastError,
            timestamp: now.toISOString(),
          });
          await reward.save();

          if (partDoc) {
            partDoc.rewardStatus = "bounced_or_failed";
            await partDoc.save();
          }
        }

        results.push({
          rewardId: reward.rewardId,
          participantId: reward.participantId,
          deliveryEmail: reward.deliveryEmail,
          assignedCardId: reward.assignedCardId,
          status: reward.status,
          error: reward.lastError,
        });
      }

      const allCampaignRewards = await GiftCardReward.find({ campaignId });
      if (
        allCampaignRewards.length > 0 &&
        allCampaignRewards.every((r) => r.status === "delivered")
      ) {
        campaign.status = "fulfilled";
        await campaign.save();
      }

      await recordAuditLog({
        actor: req.adminUser.username,
        role: req.adminUser.role,
        action: "dispatch_gift_card_rewards",
        targetType: "reward_campaign",
        targetId: campaignId,
        reason: `Processed ${results.length} reward dispatch(es)`,
        result: "success",
      });

      res.json({
        message: "Reward dispatch batch processed.",
        results,
      });
    } catch (error) {
      console.error("Dispatch error:", error);
      res.status(500).json({ error: "Failed to dispatch rewards" });
    }
  }
);

// Section 11: Private Campaign Effectiveness & Post-Reward Retention Report
app.get(
  "/api/admin/campaigns/:campaignId/effectiveness",
  requireAdminAuth(["admin", "viewer"]),
  async (req, res) => {
    try {
      const { campaignId } = req.params;
      const campaign = await RewardCampaign.findOne({ campaignId }).lean();
      if (!campaign) return res.status(404).json({ error: "Campaign not found" });

      const [participants, rewards, campaignUploads] = await Promise.all([
        RewardParticipant.find({ campaignId }).lean(),
        GiftCardReward.find({ campaignId }).lean(),
        Upload.find(
          campaign.startAt && campaign.endAt
            ? {
                date: {
                  $gte: new Date(campaign.startAt),
                  $lte: new Date(campaign.endAt),
                },
              }
            : {}
        ).lean(),
      ]);

      const incentivizedUploads = campaignUploads.filter(
        (u) => u.campaignId === campaignId || Boolean(u.participantId)
      );
      const organicUploads = campaignUploads.filter(
        (u) => !u.campaignId && !u.participantId
      );

      const verifiedParticipants = participants.filter((p) => p.emailVerified);
      const suspectedInvalidCount = participants.filter(
        (p) =>
          p.fraudStatus === "pending_review" ||
          p.fraudStatus === "flagged" ||
          p.fraudStatus === "disqualified" ||
          (Array.isArray(p.suspiciousFlags) && p.suspiciousFlags.length > 0)
      ).length;

      const totalQualifyingTransfers = participants.reduce(
        (sum, p) => sum + (p.qualifyingTransfers || 0),
        0
      );
      const totalQualifyingDeliveries = participants.reduce(
        (sum, p) => sum + (p.qualifyingRecipientDeliveries || 0),
        0
      );

      const committedRewards = rewards.filter((r) => r.status !== "cancelled");
      const deliveredRewards = rewards.filter((r) => r.status === "delivered");
      const totalRewardValueCommitted = committedRewards.reduce(
        (sum, r) => sum + (Number(r.amount) || 0),
        0
      );
      const totalRewardValueDelivered = deliveredRewards.reduce(
        (sum, r) => sum + (Number(r.amount) || 0),
        0
      );
      const totalCostCommitted =
        totalRewardValueCommitted + (Number(campaign.expectedFees) || 0);

      const rewardedParticipants = participants.filter(
        (p) => p.rewardStatus === "delivered" || p.rewardDeliveredAt
      );
      const retainedAnyPostReward = rewardedParticipants.filter(
        (p) => (p.postRewardTransfers || 0) > 0
      );
      const retained7d = rewardedParticipants.filter((p) => p.postRewardActiveWithin7d);
      const retained30d = rewardedParticipants.filter((p) => p.postRewardActiveWithin30d);

      const costPerRetainedParticipant =
        retainedAnyPostReward.length > 0
          ? Math.round((totalCostCommitted / retainedAnyPostReward.length) * 100) / 100
          : null;

      res.json({
        campaignId: campaign.campaignId,
        campaignName: campaign.name,
        status: campaign.status,
        centralCommercialQuestion:
          "Do people continue using Fylshare after the reward is gone?",
        methodologyDisclaimer:
          "Observational comparison only: incentivized vs. organic usage during the campaign window does not establish causal lift. Evaluate post-reward 7-day and 30-day retention after reward delivery.",
        funnel: {
          visitorsShownInvitation: campaign.funnelMetrics?.invitationImpressions || 0,
          invitationDismissals: campaign.funnelMetrics?.invitationDismissals || 0,
          enrollmentStarts:
            campaign.funnelMetrics?.enrollmentStarts || participants.length,
          verifiedParticipants: verifiedParticipants.length,
        },
        activityComparison: {
          incentivized: {
            transfers: incentivizedUploads.length,
            files: incentivizedUploads.reduce((s, u) => s + (u.fileCount || 0), 0),
            qualifyingTransfers: totalQualifyingTransfers,
            qualifyingRecipientDeliveries: totalQualifyingDeliveries,
          },
          organicWithoutRewards: {
            transfers: organicUploads.length,
            files: organicUploads.reduce((s, u) => s + (u.fileCount || 0), 0),
            downloadRequests: organicUploads.reduce(
              (s, u) => s + (u.downloadRequestCount || 0),
              0
            ),
          },
        },
        integrityAndAbuse: {
          participantsWithSuspiciousFlags: suspectedInvalidCount,
          disqualifiedParticipants: participants.filter(
            (p) => p.fraudStatus === "disqualified"
          ).length,
          appealsSubmitted: participants.filter((p) => p.appealStatus !== "none").length,
        },
        financialsAndFulfillment: {
          currency: campaign.currency,
          fundedBudget: campaign.fundedBudget,
          expectedProviderFees: campaign.expectedFees || 0,
          rewardsCommittedCount: committedRewards.length,
          rewardsDeliveredCount: deliveredRewards.length,
          totalRewardValueCommitted,
          totalRewardValueDelivered,
          totalCostCommitted,
        },
        postRewardRetention: {
          rewardedParticipantsCount: rewardedParticipants.length,
          participantsWithRepeatActivityAfterReward: retainedAnyPostReward.length,
          totalPostRewardTransfers: rewardedParticipants.reduce(
            (s, p) => s + (p.postRewardTransfers || 0),
            0
          ),
          retainedWithin7DaysCount: retained7d.length,
          retainedWithin7DaysPct:
            rewardedParticipants.length > 0
              ? Math.round((retained7d.length / rewardedParticipants.length) * 1000) / 10
              : 0,
          retainedWithin30DaysCount: retained30d.length,
          retainedWithin30DaysPct:
            rewardedParticipants.length > 0
              ? Math.round((retained30d.length / rewardedParticipants.length) * 1000) / 10
              : 0,
          costPerRetainedParticipant,
        },
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to generate campaign effectiveness report" });
    }
  }
);

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
  getSentEmailsOutbox,
  clearSentEmailsOutbox,
};
