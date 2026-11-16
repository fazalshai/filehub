const crypto = require("crypto");

// ISO 3166-1 alpha-2 Country Name Lookup
const COUNTRY_NAMES = {
  AE: "United Arab Emirates",
  IN: "India",
  US: "United States",
  GB: "United Kingdom",
  AU: "Australia",
  CA: "Canada",
  DE: "Germany",
  FR: "France",
  SG: "Singapore",
  SA: "Saudi Arabia",
  QA: "Qatar",
  KW: "Kuwait",
  OM: "Oman",
  BH: "Bahrain",
  LK: "Sri Lanka",
  VN: "Viet Nam",
  PK: "Pakistan",
  BD: "Bangladesh",
  NP: "Nepal",
  MY: "Malaysia",
  ID: "Indonesia",
  PH: "Philippines",
  JP: "Japan",
  KR: "South Korea",
  CN: "China",
  BR: "Brazil",
  ZA: "South Africa",
  NG: "Nigeria",
  KE: "Kenya",
  EG: "Egypt",
  NL: "Netherlands",
  SE: "Sweden",
  CH: "Switzerland",
  IE: "Ireland",
  NZ: "New Zealand",
};

const LEGACY_COUNTRY_MAP = {
  india: { code: "IN", name: "India" },
  "united arab emirates": { code: "AE", name: "United Arab Emirates" },
  uae: { code: "AE", name: "United Arab Emirates" },
  "sri lanka": { code: "LK", name: "Sri Lanka" },
  "viet nam": { code: "VN", name: "Viet Nam" },
  vietnam: { code: "VN", name: "Viet Nam" },
  australia: { code: "AU", name: "Australia" },
  "united states": { code: "US", name: "United States" },
  usa: { code: "US", name: "United States" },
  "united kingdom": { code: "GB", name: "United Kingdom" },
  uk: { code: "GB", name: "United Kingdom" },
  canada: { code: "CA", name: "Canada" },
  singapore: { code: "SG", name: "Singapore" },
  "saudi arabia": { code: "SA", name: "Saudi Arabia" },
  germany: { code: "DE", name: "Germany" },
};

// Explicit Supported-Type Policy
const SUPPORTED_TYPE_POLICY = {
  maxFilesPerTransfer: 10,
  maxTotalBytes: 1024 * 1024 * 1024, // 1 GB
  maxZipEntries: 500,
  maxZipUncompressedBytes: 2 * 1024 * 1024 * 1024, // 2 GB
  maxCompressionRatio: 100,
  blockedExtensions: new Set([
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".scr",
    ".vbs",
    ".vbe",
    ".js", // Raw .js is allowed ONLY as text/code attachment, but .jse/.wsf/.wsh/.msi/.com/.pif/.cpl/.hta/.ps1 are blocked
    ".jse",
    ".wsf",
    ".wsh",
    ".msi",
    ".msp",
    ".com",
    ".pif",
    ".cpl",
    ".hta",
    ".ps1",
    ".reg",
    ".apk",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".iso",
    ".img",
  ]),
  allowedExtensions: new Set([
    // Documents
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
    ".txt",
    ".rtf",
    ".csv",
    ".tsv",
    ".md",
    // Images
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".bmp",
    ".ico",
    ".tif",
    ".tiff",
    // Audio & Video
    ".mp4",
    ".mov",
    ".webm",
    ".mkv",
    ".avi",
    ".mp3",
    ".wav",
    ".ogg",
    ".m4a",
    ".flac",
    // Archives
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".7z",
    // Code, Design, Engineering & Data
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".mjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".ipynb",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".sql",
    ".sh",
    ".cad",
    ".dwg",
    ".dxf",
    ".stl",
    ".obj",
    ".psd",
    ".ai",
    ".eps",
    ".fig",
    ".bin",
    ".dat",
  ]),
  // Force Content-Disposition: attachment and sandbox headers on active web/script types
  activeContentExtensions: new Set([
    ".html",
    ".htm",
    ".svg",
    ".xml",
    ".js",
    ".mjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".css",
    ".sh",
    ".php",
  ]),
};

// Keep .js in allowedExtensions (served strictly as non-executing text attachment)
SUPPORTED_TYPE_POLICY.blockedExtensions.delete(".js");

function generateRetrievalCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

function generateHighEntropyToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function hashToken(token) {
  if (!token) return null;
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function hashSecret(secret, existingSalt = null) {
  const salt = existingSalt || crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(String(secret), salt, 64).toString("hex");
  return { hash: derived, salt };
}

function verifySecret(secret, storedHash, storedSalt) {
  if (!secret || !storedHash || !storedSalt) return false;
  try {
    const { hash } = hashSecret(secret, storedSalt);
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(storedHash, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// Signed stateless/verifiable Admin & Workspace session token (HMAC-SHA256)
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash("sha256").update(process.env.MONGO_URI || "fylshare-dev-session-secret").digest("hex");

function createSignedToken(payload, ttlSeconds = 8 * 3600) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const body = Buffer.from(JSON.stringify({ ...payload, exp })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifySignedToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expectedSig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function sanitizeFilename(rawName) {
  if (!rawName || typeof rawName !== "string") return "unnamed_file";
  // Strip path components, null bytes, and control characters
  const base = rawName
    .replace(/\0/g, "")
    .replace(/\\/g, "/")
    .split("/")
    .pop()
    .replace(/[\x00-\x1F\x7F]/g, "")
    .trim();
  if (!base || base === "." || base === "..") return "unnamed_file";
  return base.slice(0, 200);
}

function getExtension(filename) {
  const clean = sanitizeFilename(filename).toLowerCase();
  const lastDot = clean.lastIndexOf(".");
  if (lastDot <= 0) return "";
  return clean.slice(lastDot);
}

// Detect dangerous executable signatures and validate known magic bytes
function detectBufferSignature(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { kind: "empty" };
  }
  // Windows PE / DOS MZ header: "MZ" (0x4D 0x5A)
  if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
    return { kind: "executable", detail: "Windows PE/MZ executable signature" };
  }
  // ELF binary: 0x7F 'E' 'L' 'F'
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x7f &&
    buffer[1] === 0x45 &&
    buffer[2] === 0x4c &&
    buffer[3] === 0x46
  ) {
    return { kind: "executable", detail: "ELF binary signature" };
  }
  // Mach-O binary headers
  if (buffer.length >= 4) {
    const magic32 = buffer.readUInt32BE(0);
    if (
      magic32 === 0xfeedface ||
      magic32 === 0xcefaedfe ||
      magic32 === 0xfeedfacf ||
      magic32 === 0xcffaedfe ||
      magic32 === 0xcafebabe
    ) {
      return { kind: "executable", detail: "Mach-O binary signature" };
    }
  }
  // PDF: "%PDF-"
  if (buffer.length >= 5 && buffer.slice(0, 5).toString("ascii") === "%PDF-") {
    return { kind: "pdf" };
  }
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47
  ) {
    return { kind: "png" };
  }
  // JPEG: FF D8 FF
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { kind: "jpeg" };
  }
  // GIF: "GIF87a" or "GIF89a"
  if (
    buffer.length >= 6 &&
    (buffer.slice(0, 6).toString("ascii") === "GIF87a" ||
      buffer.slice(0, 6).toString("ascii") === "GIF89a")
  ) {
    return { kind: "gif" };
  }
  // ZIP / OOXML (DOCX, XLSX, PPTX): "PK\x03\x04" or "PK\x05\x06"
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    (buffer[2] === 0x03 || buffer[2] === 0x05) &&
    (buffer[3] === 0x04 || buffer[3] === 0x06)
  ) {
    return { kind: "zip" };
  }
  return { kind: "generic" };
}

// Inspect ZIP buffer local headers for zip bombs, nested executables, or encrypted entries
function inspectZipBuffer(buffer) {
  let offset = 0;
  let entryCount = 0;
  let totalUncompressed = 0;
  let totalCompressed = 0;
  let hasEncryptedEntries = false;

  while (offset + 30 <= buffer.length) {
    const sig = buffer.readUInt32LE(offset);
    if (sig !== 0x04034b50) {
      break; // Reached central directory or non-local header
    }
    entryCount += 1;
    if (entryCount > SUPPORTED_TYPE_POLICY.maxZipEntries) {
      return {
        valid: false,
        reason: `Archive exceeds maximum supported entry count (${SUPPORTED_TYPE_POLICY.maxZipEntries}).`,
      };
    }

    const flags = buffer.readUInt16LE(offset + 6);
    if ((flags & 0x0001) !== 0) {
      hasEncryptedEntries = true;
    }

    const compressedSize = buffer.readUInt32LE(offset + 18);
    const uncompressedSize = buffer.readUInt32LE(offset + 22);
    const fileNameLen = buffer.readUInt16LE(offset + 26);
    const extraLen = buffer.readUInt16LE(offset + 28);

    totalCompressed += compressedSize;
    totalUncompressed += uncompressedSize;

    if (totalUncompressed > SUPPORTED_TYPE_POLICY.maxZipUncompressedBytes) {
      return {
        valid: false,
        reason: "Archive uncompressed size exceeds safety limit (potential zip bomb).",
      };
    }

    if (
      totalCompressed > 0 &&
      totalUncompressed > 10 * 1024 * 1024 &&
      totalUncompressed / totalCompressed > SUPPORTED_TYPE_POLICY.maxCompressionRatio
    ) {
      return {
        valid: false,
        reason: "Archive compression ratio exceeds safety threshold.",
      };
    }

    const nameEnd = offset + 30 + fileNameLen;
    if (nameEnd <= buffer.length) {
      const entryName = buffer.slice(offset + 30, nameEnd).toString("utf8");
      if (entryName.includes("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
        return {
          valid: false,
          reason: "Archive contains unsafe path traversal entry.",
        };
      }
      const depth = entryName.split("/").filter(Boolean).length;
      if (depth > 12) {
        return {
          valid: false,
          reason: "Archive directory nesting depth exceeds maximum limit (12).",
        };
      }
      const entryExt = getExtension(entryName);
      if (SUPPORTED_TYPE_POLICY.blockedExtensions.has(entryExt)) {
        return {
          valid: false,
          reason: `Archive contains prohibited executable or installer file (${ sanitizeFilename(entryName) }).`,
        };
      }
    }

    if (compressedSize === 0 && (flags & 0x0008) !== 0) {
      // Data descriptor used; stop linear local-header walk
      break;
    }
    offset = offset + 30 + fileNameLen + extraLen + compressedSize;
  }

  return {
    valid: true,
    entryCount,
    hasEncryptedEntries,
  };
}

function inspectUploadedFile(file) {
  const originalName = sanitizeFilename(file.originalname || "file");
  const ext = getExtension(originalName);
  const buffer = file.buffer || Buffer.alloc(0);

  if (!ext) {
    return {
      accepted: false,
      reason: `File "${originalName}" must have a supported file extension.`,
      scanStatus: "rejected",
    };
  }

  if (SUPPORTED_TYPE_POLICY.blockedExtensions.has(ext)) {
    return {
      accepted: false,
      reason: `File type "${ext}" (${originalName}) is not permitted by our supported file policy.`,
      scanStatus: "rejected",
    };
  }

  if (!SUPPORTED_TYPE_POLICY.allowedExtensions.has(ext)) {
    return {
      accepted: false,
      reason: `Unsupported file extension "${ext}" (${originalName}).`,
      scanStatus: "rejected",
    };
  }

  const sig = detectBufferSignature(buffer);

  // Never allow executable binary signatures regardless of extension (.pdf, .bin, .jpg, etc.)
  if (sig.kind === "executable") {
    return {
      accepted: false,
      reason: `File "${originalName}" was rejected because its binary signature matches an executable program (${sig.detail}).`,
      scanStatus: "rejected",
    };
  }

  // Enforce signature consistency for strict formats to block extension spoofing
  if (ext === ".pdf" && sig.kind !== "pdf") {
    return {
      accepted: false,
      reason: `File "${originalName}" has a .pdf extension but does not contain a valid PDF header.`,
      scanStatus: "rejected",
    };
  }
  if (ext === ".png" && sig.kind !== "png") {
    return {
      accepted: false,
      reason: `File "${originalName}" has a .png extension but does not contain a valid PNG header.`,
      scanStatus: "rejected",
    };
  }
  if ((ext === ".jpg" || ext === ".jpeg") && sig.kind !== "jpeg") {
    return {
      accepted: false,
      reason: `File "${originalName}" has a ${ext} extension but does not contain a valid JPEG header.`,
      scanStatus: "rejected",
    };
  }
  if (ext === ".gif" && sig.kind !== "gif") {
    return {
      accepted: false,
      reason: `File "${originalName}" has a .gif extension but does not contain a valid GIF header.`,
      scanStatus: "rejected",
    };
  }
  if ((ext === ".zip" || ext === ".docx" || ext === ".xlsx" || ext === ".pptx") && sig.kind !== "zip") {
    return {
      accepted: false,
      reason: `File "${originalName}" has a ${ext} extension but is not a valid ZIP/OOXML container.`,
      scanStatus: "rejected",
    };
  }

  let scanStatus = "passed";
  let scanDetail = "Signature and extension verified";

  if (ext === ".zip") {
    const zipCheck = inspectZipBuffer(buffer);
    if (!zipCheck.valid) {
      return {
        accepted: false,
        reason: zipCheck.reason,
        scanStatus: "rejected",
      };
    }
    if (zipCheck.hasEncryptedEntries) {
      scanStatus = "uninspectable_encrypted_archive";
      scanDetail = "Password-protected/encrypted ZIP entries cannot be inspected inside the archive";
    }
  }

  const forceAttachment =
    SUPPORTED_TYPE_POLICY.activeContentExtensions.has(ext) ||
    ext === ".bin" ||
    ext === ".dat" ||
    ext === ".zip" ||
    scanStatus === "uninspectable_encrypted_archive";

  return {
    accepted: true,
    sanitizedName: originalName,
    extension: ext,
    detectedKind: sig.kind,
    scanStatus,
    scanDetail,
    forceAttachment,
  };
}

// Parse legacy location strings without treating timezones or device labels as countries
function parseLegacyLocation(rawLocation) {
  if (!rawLocation || typeof rawLocation !== "string") {
    return {
      countryCode: null,
      countryName: "Unknown",
      locationSource: "unknown",
      locationStatus: "unknown",
      browserTimezone: null,
      deviceCategory: null,
    };
  }
  const trimmed = rawLocation.trim();
  if (!trimmed || trimmed.toLowerCase() === "unknown" || trimmed === "—") {
    return {
      countryCode: null,
      countryName: "Unknown",
      locationSource: "unknown",
      locationStatus: "unknown",
      browserTimezone: null,
      deviceCategory: null,
    };
  }

  // Check if it's an IANA timezone like "Asia/Calcutta" or "Asia/Dubai"
  if (/^[A-Za-z_]+\/[A-Za-z_]+/.test(trimmed)) {
    return {
      countryCode: null,
      countryName: "Unknown",
      locationSource: "unknown",
      locationStatus: "unknown",
      browserTimezone: trimmed,
      deviceCategory: null,
    };
  }

  // Check if it's a device label
  if (/^(mobile|desktop|tablet|system)$/i.test(trimmed)) {
    return {
      countryCode: null,
      countryName: "Unknown",
      locationSource: "unknown",
      locationStatus: "unknown",
      browserTimezone: null,
      deviceCategory: trimmed.toLowerCase(),
    };
  }

  // Strip flag emojis and coordinates "(12.345, 67.890)"
  const withoutCoords = trimmed.replace(/\([^)]*\)/g, "").trim();
  const parts = withoutCoords.split(",").map((s) => s.replace(/[^\w\s-]/g, "").trim().toLowerCase());
  const lastPart = parts[parts.length - 1] || "";

  if (LEGACY_COUNTRY_MAP[lastPart]) {
    return {
      countryCode: LEGACY_COUNTRY_MAP[lastPart].code,
      countryName: LEGACY_COUNTRY_MAP[lastPart].name,
      locationSource: "legacy_record",
      locationStatus: "available",
      browserTimezone: null,
      deviceCategory: null,
    };
  }

  return {
    countryCode: null,
    countryName: "Unknown",
    locationSource: "unknown",
    locationStatus: "unknown",
    browserTimezone: null,
    deviceCategory: null,
  };
}

// Derive country strictly from trusted CDN/hosting headers when available; never trust arbitrary client strings
function resolveRequestLocation(req) {
  const trustProxy = process.env.TRUST_PROXY !== "false"; // Render / Vercel / Cloudflare proxy headers
  let countryCode = null;
  let locationSource = "unknown";

  if (trustProxy && req && req.headers) {
    const cfCountry = req.headers["cf-ipcountry"];
    const vercelCountry = req.headers["x-vercel-ip-country"];
    const renderCountry = req.headers["x-country-code"];
    const rawHeader = (cfCountry || vercelCountry || renderCountry || "").toString().trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(rawHeader) && rawHeader !== "XX" && rawHeader !== "T1") {
      countryCode = rawHeader;
      locationSource = cfCountry
        ? "cloudflare_header"
        : vercelCountry
        ? "vercel_header"
        : "proxy_header";
    }
  }

  const countryName = countryCode ? COUNTRY_NAMES[countryCode] || countryCode : "Unknown";
  const locationStatus = countryCode ? "available" : "unknown";

  // Coarse device category from User-Agent (optional, kept separate from country)
  const ua = ((req && req.headers && req.headers["user-agent"]) || "").toLowerCase();
  let deviceCategory = "unknown";
  if (ua) {
    if (/ipad|tablet|kindle|playbook|silk/.test(ua)) deviceCategory = "tablet";
    else if (/mobile|iphone|ipod|android.*mobile|windows phone/.test(ua)) deviceCategory = "mobile";
    else if (/mozilla|chrome|safari|firefox|edg|macintosh|windows nt|linux/.test(ua))
      deviceCategory = "desktop";
  }

  return {
    countryCode,
    countryName,
    locationSource,
    locationStatus,
    deviceCategory,
  };
}

// Prevent spreadsheet formula injection in CSV exports
function sanitizeCsvCell(value) {
  if (value === null || value === undefined) return "";
  let str = String(value).replace(/\r?\n/g, " ");
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (str.includes(",") || str.includes('"') || str.includes("'")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

module.exports = {
  COUNTRY_NAMES,
  SUPPORTED_TYPE_POLICY,
  generateRetrievalCode,
  generateHighEntropyToken,
  hashToken,
  hashSecret,
  verifySecret,
  createSignedToken,
  verifySignedToken,
  sanitizeFilename,
  getExtension,
  detectBufferSignature,
  inspectUploadedFile,
  parseLegacyLocation,
  resolveRequestLocation,
  sanitizeCsvCell,
};
