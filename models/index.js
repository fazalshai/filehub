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

    // Per-File Operational & Rewards Download Counters (Section 4)
    buttonClicks: { type: Number, default: 0 },
    downloadRequests: { type: Number, default: 0 },
    signedLinksIssued: { type: Number, default: 0 },
    observedDeliveries: { type: Number, default: 0 },
    deliveryCompletionStatus: {
      type: String,
      enum: ["unknown_signed_redirect", "observed_proxy_stream", "observed_storage_log"],
      default: "unknown_signed_redirect",
    },
    repeatDownloads: { type: Number, default: 0 },
    estimatedDistinctSessions: { type: Number, default: 0 },
    qualifyingDownloads: { type: Number, default: 0 },
    headOrPreviewRequests: { type: Number, default: 0 },
    rangeRequests: { type: Number, default: 0 },
    scannerOrBotRequests: { type: Number, default: 0 },
    failedRequests: { type: Number, default: 0 },
    sessionHashes: { type: [String], default: [] },
    lastActivityAt: { type: Date, default: null },
  },
  { _id: false }
);

const uploadSchema = new mongoose.Schema({
  transferId: { type: String, index: true },
  eventId: { type: String, index: true, default: null },
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

  // Short 6-digit retrieval code (cleared once expired/revoked/deleted) + SHA-256 hash & revokedCode for admin/legal audit
  code: { type: String, index: true },
  revokedCode: { type: String, index: true, default: null },
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

  // Accurate Country, State/Region & City Reporting for Quality & Security Monitoring
  location: { type: String, default: "" },
  city: { type: String, default: "" },
  region: { type: String, default: "" },
  countryCode: { type: String, default: null, index: true },
  countryName: { type: String, default: "Unknown" },
  locationSource: {
    type: String,
    enum: [
      "cloudflare_header",
      "vercel_header",
      "proxy_header",
      "client_geo_consent",
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
  bundleDownloadClicks: { type: Number, default: 0 },
  bundleDownloadRequests: { type: Number, default: 0 },
  failedLookupCount: { type: Number, default: 0 },

  // Optional Activity-Based Rewards Association & Bounded Scoring Metadata
  participantId: { type: String, index: true, default: null },
  campaignId: { type: String, index: true, default: null },
  uploaderSessionHash: { type: String, default: null },
  uploaderIpHash: { type: String, default: null },
  structureSignature: { type: String, index: true, default: null },
  qualifiesForUploadPoints: { type: Boolean, default: false },
  uploadPointsAwarded: { type: Number, default: 0 },
  uploadDisqualifyReason: { type: String, default: null },
  qualifyingRecipientDeliveries: { type: Number, default: 0 },
  recipientDeliveryPointsAwarded: { type: Number, default: 0 },
  rewardSessionHashes: { type: [String], default: [] },
  suspiciousFlags: { type: [String], default: [] },

  // Legal Accountability & Compliance Audit Metadata (Admin-only, retained across revocation)
  uploaderIp: { type: String, default: null },
  revokerIp: { type: String, default: null },
  uploaderUserAgent: { type: String, default: null },
  termsAccepted: { type: Boolean, default: true },
  termsAcceptedAt: { type: Date, default: null },
  termsVersion: { type: String, default: null },
  revokedAt: { type: Date, default: null },

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
  uploadAttempts: { type: Number, default: 0 },
  transfersCreated: { type: Number, default: 0 },
  filesUploaded: { type: Number, default: 0 },
  bytesUploaded: { type: Number, default: 0 },
  uploadsFailedOrCancelled: { type: Number, default: 0 },
  rewardEligibleUploads: { type: Number, default: 0 },
  transfersExpired: { type: Number, default: 0 },
  filesDeleted: { type: Number, default: 0 },
  transfersRevoked: { type: Number, default: 0 },
  retrievalsSucceeded: { type: Number, default: 0 },
  downloadButtonClicks: { type: Number, default: 0 },
  downloadsRequested: { type: Number, default: 0 },
  downloadsServed: { type: Number, default: 0 },
  bundleDownloadsRequested: { type: Number, default: 0 },
  rewardQualifyingDownloads: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now },
});

const rewardCampaignSchema = new mongoose.Schema({
  campaignId: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  status: {
    type: String,
    enum: ["draft", "active", "paused", "closed", "reviewed", "fulfilled"],
    default: "draft",
    index: true,
  },
  // Country, currency, reward value, budget, dates, and legal eligibility remain unset (null/[]) until supplied by owner
  startAt: { type: Date, default: null },
  endAt: { type: Date, default: null },
  timezone: { type: String, default: null },
  eligibleCountries: { type: [String], default: [] },
  eligibilityRequirements: { type: String, default: null },
  marketplace: { type: String, default: null },
  currency: { type: String, default: null },
  rewardValue: { type: Number, default: null },
  prizeCount: { type: Number, default: null },
  fundedBudget: { type: Number, default: null },
  expectedFees: { type: Number, default: 0 },
  minDenomination: { type: Number, default: 1 },

  // Versioned, Bounded Activity Scoring Rules (Draft default: 1pt/transfer, 2pt/delivery, max 3/transfer, max 5/day)
  scoringRules: {
    version: { type: Number, default: 1 },
    pointsPerTransfer: { type: Number, default: 1 },
    pointsPerDelivery: { type: Number, default: 2 },
    maxDeliveriesPerTransfer: { type: Number, default: 3 },
    maxTransfersPerDay: { type: Number, default: 5 },
    allowClaimingExistingUploadWithRevokeToken: { type: Boolean, default: true },
    minTransferBytes: { type: Number, default: 64 },
  },

  // Tie Policy (never earliest registration or random draw)
  tiePolicy: {
    type: String,
    enum: [
      null,
      "split_equally_within_budget",
      "extend_budget_for_tied_ranks",
      "strict_secondary_metrics_then_split",
    ],
    default: null,
  },
  tieReserveBudget: { type: Number, default: 0 },

  reviewPeriodDays: { type: Number, default: 7 },
  deliveryDeadline: { type: Date, default: null },
  rulesVersion: { type: String, default: "1.0-draft" },
  supportContact: { type: String, default: null },
  legalAndBrandReviewConfirmed: { type: Boolean, default: false },
  fundingVerifiedByOwner: { type: Boolean, default: false },
  personalDataRetentionDays: { type: Number, default: 180 },
  rankingsEnabled: { type: Boolean, default: true },
  pauseReason: { type: String, default: null },
  alerts: { type: [String], default: [] },

  // Frozen Immutable Score Snapshot at Campaign Close
  snapshotFrozenAt: { type: Date, default: null },
  scoreSnapshot: { type: Array, default: [] },

  // Funnel & Commercial Effectiveness Metrics
  funnelMetrics: {
    invitationImpressions: { type: Number, default: 0 },
    invitationDismissals: { type: Number, default: 0 },
    enrollmentStarts: { type: Number, default: 0 },
    verifiedParticipants: { type: Number, default: 0 },
  },

  createdBy: { type: String, default: "system" },
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now },
});

const rewardParticipantSchema = new mongoose.Schema({
  participantId: { type: String, required: true, unique: true, index: true },
  campaignId: { type: String, required: true, index: true },
  email: { type: String, required: true, index: true },
  emailVerified: { type: Boolean, default: false, index: true },
  verifiedAt: { type: Date, default: null },
  verificationTokenHash: { type: String, default: null },
  verificationOtpHash: { type: String, default: null },
  verificationExpiresAt: { type: Date, default: null },
  verificationResendCount: { type: Number, default: 0 },
  lastVerificationSentAt: { type: Date, default: null },

  loginTokenHash: { type: String, default: null },
  loginOtpHash: { type: String, default: null },
  loginTokenExpiresAt: { type: Date, default: null },

  pendingNewEmail: { type: String, default: null },
  pendingEmailTokenHash: { type: String, default: null },
  pendingEmailOtpHash: { type: String, default: null },
  pendingEmailExpiresAt: { type: Date, default: null },
  emailChangeHistory: { type: Array, default: [] },

  // Consent Separation (Section 2: Marketing must be unchecked by default and never affect eligibility)
  serviceMessagesAccepted: { type: Boolean, default: true },
  marketingOptIn: { type: Boolean, default: false },
  marketingUnsubscribedAt: { type: Date, default: null },

  // Separate self-declared eligibility from approximate IP country (Section 8)
  declaredCountry: { type: String, default: null },
  approxIpCountry: { type: String, default: null },
  sessionHashes: { type: [String], default: [] },

  // Raw Activity vs. Qualifying Activity & Bounded Points
  rawUploadAttempts: { type: Number, default: 0 },
  rawSuccessfulTransfers: { type: Number, default: 0 },
  rawFilesUploaded: { type: Number, default: 0 },
  rawBytesUploaded: { type: Number, default: 0 },
  rawFailedUploads: { type: Number, default: 0 },
  rawDownloadClicks: { type: Number, default: 0 },
  rawDownloadRequests: { type: Number, default: 0 },
  rawObservedDeliveries: { type: Number, default: 0 },
  estimatedDistinctRecipientSessions: { type: Number, default: 0 },
  recipientSessionHashes: { type: [String], default: [] },

  qualifyingTransfers: { type: Number, default: 0 },
  qualifyingRecipientDeliveries: { type: Number, default: 0 },
  qualifyingActiveDays: { type: [String], default: [] },

  uploadPoints: { type: Number, default: 0 },
  deliveryPoints: { type: Number, default: 0 },
  manualAdjustmentPoints: { type: Number, default: 0 },
  approvedPoints: { type: Number, default: 0 },
  pendingReviewPoints: { type: Number, default: 0 },

  // Fraud Review & Appeals (Sections 7, 10)
  fraudStatus: {
    type: String,
    enum: ["clean", "pending_review", "flagged", "cleared", "disqualified"],
    default: "clean",
    index: true,
  },
  suspiciousFlags: { type: [String], default: [] },
  reviewReason: { type: String, default: null },
  reviewedBy: { type: String, default: null },
  reviewedAt: { type: Date, default: null },
  appealStatus: {
    type: String,
    enum: ["none", "submitted", "upheld", "rejected"],
    default: "none",
  },
  appealMessage: { type: String, default: null },
  appealSubmittedAt: { type: Date, default: null },
  appealResolutionNote: { type: String, default: null },

  // Ranking & Fulfillment Status
  provisionalRank: { type: Number, default: null },
  finalRank: { type: Number, default: null },
  tieBreakApplied: { type: String, default: null },
  rewardStatus: {
    type: String,
    enum: [
      "none",
      "eligible_pending_review",
      "approved",
      "reserved",
      "issued",
      "email_queued",
      "accepted_by_provider",
      "delivered",
      "bounced_or_failed",
      "cancelled",
      "not_selected",
    ],
    default: "none",
  },
  rewardId: { type: String, default: null },
  rewardDeliveredAt: { type: Date, default: null },

  // Post-Reward Retention (Section 11)
  postRewardTransfers: { type: Number, default: 0 },
  postRewardActiveWithin7d: { type: Boolean, default: false },
  postRewardActiveWithin30d: { type: Boolean, default: false },
  lastActivityAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now, index: true },
});

const rewardEventSchema = new mongoose.Schema({
  eventId: { type: String, required: true, unique: true, index: true },
  campaignId: { type: String, index: true, default: null },
  participantId: { type: String, index: true, default: null },
  transferId: { type: String, index: true, default: null },
  fileId: { type: String, default: null },
  eventType: {
    type: String,
    enum: [
      "upload_attempt",
      "upload_completed",
      "upload_failed",
      "download_click",
      "download_requested",
      "delivery_observed",
      "bundle_download_requested",
      "transfer_claimed",
    ],
    required: true,
    index: true,
  },
  sessionHash: { type: String, default: null },
  dayKeyInCampaignTz: { type: String, default: null },
  fileCount: { type: Number, default: 0 },
  bytes: { type: Number, default: 0 },
  qualifiesForPoints: { type: Boolean, default: false },
  pointsAwarded: { type: Number, default: 0 },
  pendingReview: { type: Boolean, default: false },
  disqualifyReason: { type: String, default: null },
  createdAt: { type: Date, default: Date.now, index: true },
});

const giftCardInventorySchema = new mongoose.Schema({
  cardId: { type: String, required: true, unique: true, index: true },
  marketplace: { type: String, required: true, index: true },
  currency: { type: String, required: true },
  amount: { type: Number, required: true },
  encryptedClaimCode: { type: String, required: true },
  codeLastFour: { type: String, default: "" },
  sourceReference: { type: String, default: "" },
  isTestFixture: { type: Boolean, default: true },
  status: {
    type: String,
    enum: ["available", "reserved", "assigned", "cancelled"],
    default: "available",
    index: true,
  },
  assignedRewardId: { type: String, default: null, index: true },
  assignedParticipantId: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
});

const giftCardRewardSchema = new mongoose.Schema({
  rewardId: { type: String, required: true, unique: true, index: true },
  campaignId: { type: String, required: true, index: true },
  participantId: { type: String, required: true, index: true },
  deliveryEmail: { type: String, required: true },
  marketplace: { type: String, required: true },
  currency: { type: String, required: true },
  amount: { type: Number, required: true },
  rankAtSelection: { type: Number, required: true },
  approvedPointsAtSelection: { type: Number, required: true },
  selectionReason: { type: String, required: true },
  idempotencyKey: { type: String, required: true, unique: true, index: true },
  fulfillmentMode: {
    type: String,
    enum: ["manual_inventory", "provider_api_sandbox", "provider_api_live"],
    default: "manual_inventory",
  },
  assignedCardId: { type: String, default: null },
  providerOrderId: { type: String, default: null },
  providerFee: { type: Number, default: 0 },
  status: {
    type: String,
    enum: [
      "approved",
      "reserved",
      "issued",
      "email_queued",
      "accepted_by_provider",
      "delivered",
      "bounced_or_failed",
      "cancelled",
    ],
    default: "approved",
    index: true,
  },
  statusHistory: { type: Array, default: [] },
  batchApprovedBy: { type: String, required: true },
  batchApprovedAt: { type: Date, default: Date.now },
  dispatchedBy: { type: String, default: null },
  dispatchedAt: { type: Date, default: null },
  deliveredAt: { type: Date, default: null },
  lastError: { type: String, default: null },
  retryCount: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now },
});

const Upload = mongoose.models.Upload || mongoose.model("Upload", uploadSchema);
const Workspace = mongoose.models.Workspace || mongoose.model("Workspace", workspaceSchema);
const AbuseReport = mongoose.models.AbuseReport || mongoose.model("AbuseReport", abuseReportSchema);
const AdminAuditLog =
  mongoose.models.AdminAuditLog || mongoose.model("AdminAuditLog", adminAuditLogSchema);
const DailyStats = mongoose.models.DailyStats || mongoose.model("DailyStats", dailyStatsSchema);
const RewardCampaign =
  mongoose.models.RewardCampaign || mongoose.model("RewardCampaign", rewardCampaignSchema);
const RewardParticipant =
  mongoose.models.RewardParticipant || mongoose.model("RewardParticipant", rewardParticipantSchema);
const RewardEvent =
  mongoose.models.RewardEvent || mongoose.model("RewardEvent", rewardEventSchema);
const GiftCardInventory =
  mongoose.models.GiftCardInventory || mongoose.model("GiftCardInventory", giftCardInventorySchema);
const GiftCardReward =
  mongoose.models.GiftCardReward || mongoose.model("GiftCardReward", giftCardRewardSchema);

module.exports = {
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
};
