const mongoose = require("mongoose");

const fileSchema = new mongoose.Schema(
  {
    fileId: { type: String, default: "" },
    name: { type: String, default: "" }, // Cleared/redacted when identifying metadata is minimized after expiry
    storagePath: { type: String, default: "" },
    url: { type: String, default: "" }, // Legacy public URL or empty for private storage objects
    isPublicLegacy: { type: Boolean, default: false },
    size: { type: Number, default: 0 },
    date: { type: Date, default: Date.now },
    type: { type: String, default: "application/octet-stream" },
    extension: { type: String, default: "" },
    code: { type: String, default: "" },
    scanStatus: {
      type: String,
      enum: [
        "pending",
        "passed",
        "rejected",
        "failed",
        "unavailable",
        "uninspectable_encrypted_archive",
      ],
      default: "passed",
    },
    forceAttachment: { type: Boolean, default: false },
    storageDeleted: { type: Boolean, default: false },
  },
  { _id: false }
);

const uploadSchema = new mongoose.Schema({
  transferId: { type: String, index: true },
  transferType: {
    type: String,
    enum: ["anonymous", "workspace"],
    default: "anonymous",
    index: true,
  },
  workspaceName: { type: String, default: null },

  // Optional label ("Transfer label", formerly "name")
  name: { type: String, default: "" },
  labelRedacted: { type: Boolean, default: false },

  // Short 6-digit retrieval code (cleared once expired/revoked/deleted) + SHA-256 hash for audit lookup
  code: { type: String, index: true },
  codeHash: { type: String, index: true },

  // High-entropy tokens (stored as SHA-256 hashes only; raw token returned once to client)
  shareTokenHash: { type: String, index: true },
  revokeTokenHash: { type: String },

  files: [fileSchema],
  fileCount: { type: Number, default: 0 },
  size: { type: Number, default: 0 },

  // Explicit Lifecycle State
  status: {
    type: String,
    enum: [
      "uploading",
      "processing",
      "available",
      "expired",
      "deletion_pending",
      "deleted",
      "revoked",
      "quarantined",
      "rejected",
      "failed",
    ],
    default: "available",
    index: true,
  },

  scanStatus: {
    type: String,
    enum: [
      "pending",
      "passed",
      "rejected",
      "failed",
      "unavailable",
      "uninspectable_encrypted_archive",
    ],
    default: "passed",
  },

  // Timestamps (UTC internally)
  date: { type: Date, default: Date.now, index: true },
  expiresAt: { type: Date, index: true },
  storageDeletedAt: { type: Date, default: null },
  metadataMinimizedAt: { type: Date, default: null },

  // Idempotent Cleanup & Observability
  cleanupAttempts: { type: Number, default: 0 },
  lastCleanupAttemptAt: { type: Date, default: null },
  lastCleanupError: { type: String, default: null },

  // Accurate, Distinct Country & Device Reporting (Never mixes timezone or device into country)
  location: { type: String, default: "" }, // Legacy field preserved for backward compatibility
  countryCode: { type: String, default: null, index: true },
  countryName: { type: String, default: "Unknown" },
  locationSource: {
    type: String,
    enum: [
      "cloudflare_header",
      "vercel_header",
      "proxy_header",
      "legacy_record",
      "unknown",
    ],
    default: "unknown",
  },
  locationStatus: {
    type: String,
    enum: ["available", "unknown"],
    default: "unknown",
  },
  deviceCategory: {
    type: String,
    enum: ["mobile", "desktop", "tablet", "unknown"],
    default: "unknown",
  },
  browserTimezone: { type: String, default: null },

  // Operational Counters (First-party authoritative)
  retrievalCount: { type: Number, default: 0 },
  downloadRequestCount: { type: Number, default: 0 },
  downloadServedCount: { type: Number, default: 0 },
  failedLookupCount: { type: Number, default: 0 },

  // Moderation & Abuse Reports
  reports: { type: Number, default: 0 },
  reportReasons: [String],
  moderationNote: { type: String, default: null },
});

// Compound index for deterministic server-side pagination and date-window queries
uploadSchema.index({ date: -1, _id: -1 });
uploadSchema.index({ status: 1, expiresAt: 1 });

const workspaceSchema = new mongoose.Schema({
  boxName: { type: String, unique: true, required: true, index: true },
  pin: { type: String, default: null }, // Legacy plaintext PIN (migrated to pinHash + pinSalt on login)
  pinHash: { type: String, default: null },
  pinSalt: { type: String, default: null },
  failedAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  files: [fileSchema],
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now },
});

const abuseReportSchema = new mongoose.Schema({
  reportId: { type: String, required: true, unique: true, index: true },
  transferId: { type: mongoose.Schema.Types.ObjectId, ref: "Upload", default: null },
  codeHash: { type: String, index: true },
  category: {
    type: String,
    enum: ["copyright", "malware", "privacy", "unlawful", "other"],
    default: "other",
  },
  reason: { type: String, required: true },
  reporterContact: { type: String, default: null },
  status: {
    type: String,
    enum: ["open", "quarantined", "removed", "dismissed"],
    default: "open",
    index: true,
  },
  createdAt: { type: Date, default: Date.now, index: true },
  reviewedBy: { type: String, default: null },
  reviewedAt: { type: Date, default: null },
  resolutionNote: { type: String, default: null },
});

const adminAuditLogSchema = new mongoose.Schema({
  actor: { type: String, required: true, index: true },
  role: { type: String, required: true },
  action: { type: String, required: true, index: true },
  targetType: { type: String, required: true },
  targetId: { type: String, default: null },
  reason: { type: String, default: null },
  result: { type: String, enum: ["success", "denied", "error"], default: "success" },
  metadata: { type: Object, default: {} },
  timestamp: { type: Date, default: Date.now, index: true },
});

const dailyStatsSchema = new mongoose.Schema({
  dateKey: { type: String, required: true, unique: true, index: true }, // YYYY-MM-DD in UTC
  transfersCreated: { type: Number, default: 0 },
  filesUploaded: { type: Number, default: 0 },
  bytesUploaded: { type: Number, default: 0 },
  transfersExpired: { type: Number, default: 0 },
  filesDeleted: { type: Number, default: 0 },
  transfersRevoked: { type: Number, default: 0 },
  retrievalsSucceeded: { type: Number, default: 0 },
  downloadsRequested: { type: Number, default: 0 },
  downloadsServed: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now },
});

const Upload = mongoose.models.Upload || mongoose.model("Upload", uploadSchema);
const Workspace = mongoose.models.Workspace || mongoose.model("Workspace", workspaceSchema);
const AbuseReport = mongoose.models.AbuseReport || mongoose.model("AbuseReport", abuseReportSchema);
const AdminAuditLog =
  mongoose.models.AdminAuditLog || mongoose.model("AdminAuditLog", adminAuditLogSchema);
const DailyStats = mongoose.models.DailyStats || mongoose.model("DailyStats", dailyStatsSchema);

module.exports = {
  Upload,
  Workspace,
  AbuseReport,
  AdminAuditLog,
  DailyStats,
};

