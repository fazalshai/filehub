const crypto = require("crypto");
const { hashToken, generateHighEntropyToken } = require("./security");

// Supported Amazon Marketplaces & Expected Currencies + Minimum Denominations
const MARKETPLACE_CONFIG = {
  "amazon.ae": { currency: "AED", minDenomination: 10, countryCode: "AE", label: "Amazon.ae (UAE)" },
  "amazon.com": { currency: "USD", minDenomination: 5, countryCode: "US", label: "Amazon.com (US)" },
  "amazon.in": { currency: "INR", minDenomination: 100, countryCode: "IN", label: "Amazon.in (India)" },
  "amazon.co.uk": { currency: "GBP", minDenomination: 5, countryCode: "GB", label: "Amazon.co.uk (UK)" },
  "amazon.de": { currency: "EUR", minDenomination: 5, countryCode: "DE", label: "Amazon.de (Germany)" },
  "amazon.ca": { currency: "CAD", minDenomination: 5, countryCode: "CA", label: "Amazon.ca (Canada)" },
  "amazon.com.au": { currency: "AUD", minDenomination: 10, countryCode: "AU", label: "Amazon.com.au (Australia)" },
  "amazon.sg": { currency: "SGD", minDenomination: 10, countryCode: "SG", label: "Amazon.sg (Singapore)" },
};

// AES-256-GCM Encryption for Stored Gift-Card Claim Codes
function getEncryptionKey() {
  const secret =
    process.env.REWARDS_ENCRYPTION_KEY ||
    process.env.SESSION_SECRET ||
    "fylshare-dev-rewards-key-do-not-use-in-prod";
  return crypto.scryptSync(secret, "fylshare-giftcard-vault-v1", 32);
}

function encryptClaimCode(plainCode) {
  if (!plainCode || typeof plainCode !== "string") {
    throw new Error("Claim code is required for encryption");
  }
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plainCode.trim(), "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("base64url")}.${authTag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

function decryptClaimCode(encryptedPayload) {
  if (!encryptedPayload || typeof encryptedPayload !== "string") return null;
  const parts = encryptedPayload.split(".");
  if (parts.length !== 3) return null;
  const [ivB64, tagB64, dataB64] = parts;
  const key = getEncryptionKey();
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64url")
  );
  decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64url")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

function normalizeEmail(rawEmail) {
  if (!rawEmail || typeof rawEmail !== "string") return "";
  return rawEmail.trim().toLowerCase();
}

function isValidEmail(email) {
  const clean = normalizeEmail(email);
  if (!clean || clean.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(clean);
}

function generateOtpCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

function anonymizeParticipantLabel(participantId) {
  if (!participantId) return "Participant";
  const digest = hashToken(participantId).slice(0, 6).toUpperCase();
  return `Participant #${digest}`;
}

// Extract or derive a short-lived first-party session hash (no invasive fingerprinting)
function extractSessionHash(req, explicitSessionId = "") {
  const headerToken =
    explicitSessionId ||
    (req && req.headers && (req.headers["x-fylshare-session"] || req.headers["x-participant-session"])) ||
    (req && req.query && req.query.sid) ||
    "";
  const dayBucket = new Date().toISOString().slice(0, 10);
  if (headerToken && String(headerToken).trim().length >= 8) {
    return hashToken(`s1:${String(headerToken).trim().slice(0, 128)}`);
  }
  // Fallback short-lived daily operational session hash when browser does not send X-Fylshare-Session
  const ip =
    (req && req.headers && req.headers["x-forwarded-for"]
      ? String(req.headers["x-forwarded-for"]).split(",")[0].trim()
      : req?.socket?.remoteAddress) || "local";
  const ua = ((req && req.headers && req.headers["user-agent"]) || "unknown").slice(0, 80);
  return hashToken(`s1_fallback:${dayBucket}:${ip}:${ua}`);
}

function extractIpDailyHash(req) {
  const dayBucket = new Date().toISOString().slice(0, 10);
  const ip =
    (req && req.headers && req.headers["x-forwarded-for"]
      ? String(req.headers["x-forwarded-for"]).split(",")[0].trim()
      : req?.socket?.remoteAddress) || "local";
  return hashToken(`ip:${dayBucket}:${ip}`);
}

// Classify download requests to separate human downloads from HEAD, previews, link scanners, and multi-range chunks
function classifyDownloadRequest(req) {
  const method = ((req && req.method) || "GET").toUpperCase();
  const mode = req && req.query && req.query.mode === "inline" ? "inline" : "download";
  const rangeHeader = (req && req.headers && req.headers.range) ? String(req.headers.range).trim() : "";
  const ua = ((req && req.headers && req.headers["user-agent"]) || "").toLowerCase();
  const purpose = (
    (req && req.headers && (req.headers.purpose || req.headers["x-purpose"] || req.headers["sec-purpose"])) ||
    ""
  ).toLowerCase();

  const isHead = method === "HEAD";
  const isPreview = mode === "inline" || purpose.includes("preview") || purpose.includes("prefetch");

  const scannerPattern =
    /slackbot|whatsapp|telegrambot|discordbot|twitterbot|facebookexternalhit|linkedinbot|googlebot|bingbot|yandexbot|baiduspider|duckduckbot|applebot|pinterest|skypeuripreview|vkshare|w3c_validator|headlesschrome|phantomjs|uptimerobot|statuscake|pingdom|curl\/|wget\/|python-requests|go-http-client|axios\/|postmanruntime/i;
  const isScannerOrBot = scannerPattern.test(ua);

  let isRangeRequest = false;
  let isContinuationRange = false;
  if (rangeHeader.startsWith("bytes=")) {
    isRangeRequest = true;
    const match = /^bytes=(\d+)-/.exec(rangeHeader);
    if (match && Number(match[1]) > 0) {
      isContinuationRange = true;
    }
  }

  // Determine whether this request counts as a primary human download request
  const countsAsDownloadRequest =
    !isHead && !isPreview && !isScannerOrBot && !isContinuationRange;

  let disqualifyReason = null;
  if (isHead) disqualifyReason = "head_request";
  else if (isPreview) disqualifyReason = "inline_preview_or_prefetch";
  else if (isScannerOrBot) disqualifyReason = "automated_scanner_or_bot";
  else if (isContinuationRange) disqualifyReason = "range_continuation_chunk";

  return {
    isHead,
    isPreview,
    isScannerOrBot,
    isRangeRequest,
    isContinuationRange,
    countsAsDownloadRequest,
    disqualifyReason,
  };
}

// Compute a non-invasive transfer structure signature (file count + total size + extensions)
// to detect repeated artificial identical uploads without opening private files or storing content hashes
function computeStructureSignature(files = [], totalBytes = 0) {
  const extSummary = (files || [])
    .map((f) => `${(f.extension || "").toLowerCase()}:${Number(f.size) || 0}`)
    .sort()
    .join("|");
  return hashToken(`struct:${files.length}:${totalBytes}:${extSummary}`).slice(0, 24);
}

// Format date as YYYY-MM-DD in the campaign's published timezone
function getDayKeyInTimezone(date = new Date(), timezone = "UTC") {
  let tz = timezone || "UTC";
  try {
    Intl.DateTimeFormat("en-US", { timeZone: tz });
  } catch {
    tz = "UTC";
  }
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(date));
}

// Validate Campaign Configuration & Budget Before Activation (Section 8)
function validateCampaignForActivation(campaign) {
  const errors = [];
  const warnings = [];

  if (!campaign) {
    return { valid: false, errors: ["Campaign not found."], warnings: [] };
  }

  if (!campaign.name || String(campaign.name).trim().length < 3) {
    errors.push("Campaign name is required.");
  }

  if (!campaign.startAt || !campaign.endAt) {
    errors.push("Campaign start and end timestamps must be configured before activation.");
  } else {
    const startMs = new Date(campaign.startAt).getTime();
    const endMs = new Date(campaign.endAt).getTime();
    if (isNaN(startMs) || isNaN(endMs) || endMs <= startMs) {
      errors.push("Campaign end time must be after the start time.");
    }
  }

  if (!campaign.timezone) {
    errors.push("Campaign timezone must be explicitly set (e.g. Asia/Dubai, UTC, America/New_York).");
  } else {
    try {
      Intl.DateTimeFormat("en-US", { timeZone: campaign.timezone });
    } catch {
      errors.push(`Invalid IANA timezone: "${campaign.timezone}".`);
    }
  }

  if (!Array.isArray(campaign.eligibleCountries) || campaign.eligibleCountries.length === 0) {
    errors.push("At least one eligible country (ISO 3166-1 alpha-2) must be specified. Worldwide eligibility is not permitted.");
  } else if (
    campaign.eligibleCountries.some(
      (c) => !/^[A-Z]{2}$/.test(String(c).toUpperCase()) || String(c).toUpperCase() === "WW" || String(c).toUpperCase() === "ALL"
    )
  ) {
    errors.push("Eligible countries must be valid 2-letter ISO country codes (no worldwide/ALL wildcard).");
  }

  if (!campaign.eligibilityRequirements || String(campaign.eligibilityRequirements).trim().length < 10) {
    errors.push("Legal eligibility requirements (e.g. age and residency rules) must be supplied before activation.");
  }

  const mkt = campaign.marketplace ? String(campaign.marketplace).toLowerCase().trim() : "";
  const mktSpec = MARKETPLACE_CONFIG[mkt];
  if (!mktSpec) {
    errors.push(
      `Unsupported or missing Amazon marketplace. Supported marketplaces: ${Object.keys(MARKETPLACE_CONFIG).join(", ")}.`
    );
  } else {
    if (!campaign.currency || String(campaign.currency).toUpperCase() !== mktSpec.currency) {
      errors.push(
        `Marketplace ${mkt} requires currency ${mktSpec.currency} (configured: ${campaign.currency || "unset"}).`
      );
    }
    const minDenom = Math.max(mktSpec.minDenomination, Number(campaign.minDenomination) || 1);
    if (!campaign.rewardValue || Number(campaign.rewardValue) < minDenom) {
      errors.push(
        `Reward value (${campaign.rewardValue || 0}) must meet or exceed the minimum denomination (${minDenom} ${mktSpec.currency}) for ${mkt}.`
      );
    }
  }

  const rewardValue = Number(campaign.rewardValue);
  const prizeCount = Number(campaign.prizeCount);
  const fundedBudget = Number(campaign.fundedBudget);
  const expectedFees = Number(campaign.expectedFees || 0);
  const tieReserveBudget = Number(campaign.tieReserveBudget || 0);

  if (!rewardValue || rewardValue <= 0) {
    errors.push("Reward value must be a positive number.");
  }
  if (!prizeCount || !Number.isInteger(prizeCount) || prizeCount < 1) {
    errors.push("Number of prizes must be a positive integer.");
  }
  if (!fundedBudget || fundedBudget <= 0) {
    errors.push("Total funded reward budget must be set before activation.");
  }

  if (!campaign.tiePolicy) {
    errors.push(
      "A fair, pre-published tie-resolution policy must be configured (split_equally_within_budget, extend_budget_for_tied_ranks, or strict_secondary_metrics_then_split)."
    );
  }

  if (rewardValue > 0 && prizeCount > 0 && fundedBudget > 0) {
    const baseCommitment = rewardValue * prizeCount + expectedFees;
    if (fundedBudget < baseCommitment) {
      errors.push(
        `Total committed rewards plus fees (${baseCommitment} ${campaign.currency || ""}) exceeds funded budget (${fundedBudget} ${campaign.currency || ""}).`
      );
    }

    if (campaign.tiePolicy === "extend_budget_for_tied_ranks") {
      if (tieReserveBudget < rewardValue) {
        errors.push(
          `Tie policy "extend_budget_for_tied_ranks" requires tieReserveBudget >= ${rewardValue} so boundary ties can be funded.`
        );
      }
      if (fundedBudget < baseCommitment + tieReserveBudget) {
        errors.push(
          `Funded budget (${fundedBudget}) must cover base prizes + fees + tie reserve (${baseCommitment + tieReserveBudget}).`
        );
      }
    } else if (
      campaign.tiePolicy === "split_equally_within_budget" ||
      campaign.tiePolicy === "strict_secondary_metrics_then_split"
    ) {
      const minDenom = mktSpec
        ? Math.max(mktSpec.minDenomination, Number(campaign.minDenomination) || 1)
        : Number(campaign.minDenomination) || 1;
      if (rewardValue / 2 < minDenom) {
        errors.push(
          `Tie policy "${campaign.tiePolicy}" cannot split a ${rewardValue} ${campaign.currency || ""} reward between 2 tied participants without falling below the minimum gift-card denomination (${minDenom} ${campaign.currency || ""}). Increase rewardValue or use extend_budget_for_tied_ranks with a funded reserve.`
        );
      }
    }
  }

  if (!campaign.deliveryDeadline) {
    errors.push("Reward delivery deadline date must be configured.");
  }
  if (!campaign.supportContact || !isValidEmail(campaign.supportContact)) {
    errors.push("A valid support contact email must be configured.");
  }
  if (!campaign.legalAndBrandReviewConfirmed) {
    errors.push("Legal promotion rules and brand-use compliance review must be confirmed.");
  }
  if (!campaign.fundingVerifiedByOwner) {
    errors.push("Owner funding verification must be confirmed before campaign activation.");
  }

  if (
    process.env.NODE_ENV === "production" &&
    process.env.ALLOW_PRODUCTION_CAMPAIGN_ACTIVATION !== "true"
  ) {
    errors.push(
      "Production campaign activation is locked until ALLOW_PRODUCTION_CAMPAIGN_ACTIVATION=true is enabled by the owner."
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// Generate Truthful Public Copy from Real Campaign Configuration (Section 12)
function buildPublicCampaignSummary(campaign) {
  if (!campaign || campaign.status !== "active") {
    return {
      active: false,
      campaign: null,
    };
  }

  const validation = validateCampaignForActivation(campaign);
  if (!validation.valid) {
    return {
      active: false,
      campaign: null,
    };
  }

  const mktSpec = MARKETPLACE_CONFIG[String(campaign.marketplace).toLowerCase()] || {
    label: campaign.marketplace,
    currency: campaign.currency,
  };

  const startStr = new Date(campaign.startAt).toISOString().slice(0, 10);
  const endStr = new Date(campaign.endAt).toISOString().slice(0, 10);
  const deliveryStr = campaign.deliveryDeadline
    ? new Date(campaign.deliveryDeadline).toISOString().slice(0, 10)
    : "within the published review window";

  const rules = campaign.scoringRules || {};

  return {
    active: true,
    campaign: {
      campaignId: campaign.campaignId,
      name: campaign.name,
      status: campaign.status,
      startAt: new Date(campaign.startAt).toISOString(),
      endAt: new Date(campaign.endAt).toISOString(),
      timezone: campaign.timezone,
      eligibleCountries: campaign.eligibleCountries,
      eligibilityRequirements: campaign.eligibilityRequirements,
      marketplace: campaign.marketplace,
      marketplaceLabel: mktSpec.label,
      currency: campaign.currency,
      rewardValue: campaign.rewardValue,
      prizeCount: campaign.prizeCount,
      scoringRules: {
        version: rules.version || 1,
        pointsPerTransfer: rules.pointsPerTransfer ?? 1,
        pointsPerDelivery: rules.pointsPerDelivery ?? 2,
        maxDeliveriesPerTransfer: rules.maxDeliveriesPerTransfer ?? 3,
        maxTransfersPerDay: rules.maxTransfersPerDay ?? 5,
        allowClaimingExistingUploadWithRevokeToken: Boolean(
          rules.allowClaimingExistingUploadWithRevokeToken
        ),
      },
      tiePolicy: campaign.tiePolicy,
      reviewPeriodDays: campaign.reviewPeriodDays || 7,
      deliveryDeadline: campaign.deliveryDeadline
        ? new Date(campaign.deliveryDeadline).toISOString()
        : null,
      rulesVersion: campaign.rulesVersion,
      supportContact: campaign.supportContact,
      personalDataRetentionDays: campaign.personalDataRetentionDays || 180,
      rankingsEnabled: Boolean(campaign.rankingsEnabled),
      generatedCopy: {
        headline: "Optional: join Fylshare Rewards",
        summary: `Earn points from qualifying file transfers and recipient downloads from ${startStr} to ${endStr} (${campaign.timezone}). ${campaign.prizeCount} eligible participants will receive ${campaign.currency} ${campaign.rewardValue} ${mktSpec.label} gift cards under the published activity ranking rules.`,
        pointsExplanation: `${rules.pointsPerTransfer ?? 1} point per qualifying transfer (up to ${rules.maxTransfersPerDay ?? 5}/day) and ${rules.pointsPerDelivery ?? 2} points per qualifying distinct recipient download (up to ${rules.maxDeliveriesPerTransfer ?? 3} per transfer).`,
        disclaimers: [
          "Registration alone does not guarantee a reward; winners are ranked by verified qualifying activity, never by signup order.",
          "All activity is checked for self-downloads, repeat sessions, and automated abuse before finalization.",
          `Approved rewards are scheduled for delivery to verified participant emails by ${deliveryStr}.`,
          "Amazon is not a sponsor of, and is not affiliated with, Fylshare or this promotion.",
        ],
      },
    },
  };
}

// Rank Eligible Participants Strictly by Activity & Published Tie-Breakers (Section 7)
// Never uses signup order (createdAt/verifiedAt) or random selection!
function computeCampaignRankings(campaign, participants = []) {
  const prizeCount = Number(campaign?.prizeCount) || 0;
  const baseRewardValue = Number(campaign?.rewardValue) || 0;
  const tiePolicy = campaign?.tiePolicy || "strict_secondary_metrics_then_split";
  const mktSpec = MARKETPLACE_CONFIG[String(campaign?.marketplace || "").toLowerCase()];
  const minDenom = mktSpec
    ? Math.max(mktSpec.minDenomination, Number(campaign?.minDenomination) || 1)
    : Number(campaign?.minDenomination) || 1;

  // Separate eligible active participants from unverified or disqualified ones
  const eligible = participants.filter(
    (p) => p.emailVerified && p.fraudStatus !== "disqualified" && (p.approvedPoints || 0) > 0
  );

  // Deterministic Activity Sort:
  // 1. approvedPoints DESC
  // 2. qualifyingRecipientDeliveries DESC
  // 3. qualifyingActiveDays.length DESC
  // If all 3 activity metrics are identical, they are genuinely tied and share the exact same rank!
  const sorted = [...eligible].sort((a, b) => {
    const ptsDiff = (b.approvedPoints || 0) - (a.approvedPoints || 0);
    if (ptsDiff !== 0) return ptsDiff;

    const delivDiff =
      (b.qualifyingRecipientDeliveries || 0) - (a.qualifyingRecipientDeliveries || 0);
    if (delivDiff !== 0) return delivDiff;

    const daysA = Array.isArray(a.qualifyingActiveDays) ? a.qualifyingActiveDays.length : 0;
    const daysB = Array.isArray(b.qualifyingActiveDays) ? b.qualifyingActiveDays.length : 0;
    if (daysB !== daysA) return daysB - daysA;

    // Stable display sort by participantId (both get the exact same numerical rank below!)
    return String(a.participantId).localeCompare(String(b.participantId));
  });

  // Group by identical (approvedPoints, qualifyingRecipientDeliveries, activeDaysCount)
  const rankedList = [];
  let currentRank = 1;

  for (let i = 0; i < sorted.length; i++) {
    const p = sorted[i];
    const daysCount = Array.isArray(p.qualifyingActiveDays) ? p.qualifyingActiveDays.length : 0;

    if (i > 0) {
      const prev = sorted[i - 1];
      const prevDays = Array.isArray(prev.qualifyingActiveDays)
        ? prev.qualifyingActiveDays.length
        : 0;
      const isExactTie =
        (p.approvedPoints || 0) === (prev.approvedPoints || 0) &&
        (p.qualifyingRecipientDeliveries || 0) === (prev.qualifyingRecipientDeliveries || 0) &&
        daysCount === prevDays;

      if (!isExactTie) {
        currentRank = i + 1;
      }
    }

    rankedList.push({
      participantId: p.participantId,
      anonymizedLabel: anonymizeParticipantLabel(p.participantId),
      email: p.email,
      emailVerified: p.emailVerified,
      fraudStatus: p.fraudStatus,
      approvedPoints: p.approvedPoints || 0,
      pendingReviewPoints: p.pendingReviewPoints || 0,
      qualifyingTransfers: p.qualifyingTransfers || 0,
      qualifyingRecipientDeliveries: p.qualifyingRecipientDeliveries || 0,
      qualifyingActiveDaysCount: daysCount,
      rank: currentRank,
      tieBreakApplied: "none",
      withinPrizeCutoff: prizeCount > 0 && currentRank <= prizeCount,
      allocatedRewardAmount: 0,
    });
  }

  // Annotate when secondary tie-breakers separated participants with equal points
  for (let i = 0; i < rankedList.length; i++) {
    const curr = rankedList[i];
    const samePointsGroup = rankedList.filter((r) => r.approvedPoints === curr.approvedPoints);
    if (samePointsGroup.length > 1) {
      const sameRankGroup = rankedList.filter((r) => r.rank === curr.rank);
      if (sameRankGroup.length === 1) {
        curr.tieBreakApplied = "resolved_by_secondary_activity_metrics";
      } else {
        curr.tieBreakApplied = `exact_tie_of_${sameRankGroup.length}`;
      }
    }
  }

  // Evaluate prize allocation and boundary ties
  let boundaryTieAlert = null;
  let totalAllocatedBudget = 0;

  if (prizeCount > 0 && baseRewardValue > 0) {
    const winners = rankedList.filter((r) => r.rank <= prizeCount);
    if (winners.length <= prizeCount) {
      // No tie overflows the prizeCount boundary
      for (const w of winners) {
        w.allocatedRewardAmount = baseRewardValue;
        totalAllocatedBudget += baseRewardValue;
      }
    } else {
      // A tie at the cutoff rank causes winners.length > prizeCount
      const boundaryRank = Math.max(...winners.map((w) => w.rank));
      const strictlyAboveCutoff = winners.filter((w) => w.rank < boundaryRank);
      const tiedAtCutoff = winners.filter((w) => w.rank === boundaryRank);
      const remainingPrizeSlots = Math.max(0, prizeCount - strictlyAboveCutoff.length);

      for (const w of strictlyAboveCutoff) {
        w.allocatedRewardAmount = baseRewardValue;
        totalAllocatedBudget += baseRewardValue;
      }

      if (tiePolicy === "extend_budget_for_tied_ranks") {
        const neededExtra = (tiedAtCutoff.length - remainingPrizeSlots) * baseRewardValue;
        const reserveAvailable = Number(campaign?.tieReserveBudget) || 0;
        if (neededExtra <= reserveAvailable) {
          for (const w of tiedAtCutoff) {
            w.allocatedRewardAmount = baseRewardValue;
            w.tieBreakApplied = "tie_extended_via_reserve_budget";
            totalAllocatedBudget += baseRewardValue;
          }
        } else {
          boundaryTieAlert = `Boundary tie of ${tiedAtCutoff.length} participants at rank #${boundaryRank} requires ${neededExtra} extra budget, exceeding tieReserveBudget (${reserveAvailable}). Fulfillment paused pending owner review.`;
        }
      } else {
        // split_equally_within_budget or strict_secondary_metrics_then_split
        const poolToSplit = remainingPrizeSlots * baseRewardValue;
        const splitAmount = Math.floor((poolToSplit / tiedAtCutoff.length) * 100) / 100;
        if (splitAmount >= minDenom) {
          for (const w of tiedAtCutoff) {
            w.allocatedRewardAmount = splitAmount;
            w.tieBreakApplied = `split_pool_${remainingPrizeSlots}_slots_among_${tiedAtCutoff.length}`;
            totalAllocatedBudget += splitAmount;
          }
        } else {
          boundaryTieAlert = `Boundary tie of ${tiedAtCutoff.length} participants at rank #${boundaryRank} would split ${poolToSplit} into ${splitAmount} each, which is below minimum denomination (${minDenom}). Fulfillment paused pending owner review.`;
        }
      }
    }
  }

  return {
    rankings: rankedList,
    boundaryTieAlert,
    totalAllocatedBudget,
  };
}

// In-Memory Service Email Outbox for Dev/Staging/Tests (Real Email Disabled Until Configured & Approved)
const sentEmailsOutbox = [];

function getSentEmailsOutbox() {
  return sentEmailsOutbox;
}

function clearSentEmailsOutbox() {
  sentEmailsOutbox.length = 0;
}

async function sendRewardsServiceEmail({
  to,
  subject,
  category = "service_Transactional",
  template,
  metadata = {},
  simulateFailure = false,
}) {
  const cleanTo = normalizeEmail(to);
  if (!isValidEmail(cleanTo)) {
    return { ok: false, status: "bounced_or_failed", error: "Invalid recipient email address" };
  }

  if (simulateFailure || cleanTo.startsWith("bounce@") || cleanTo.startsWith("fail@")) {
    return {
      ok: false,
      status: "bounced_or_failed",
      error: "Simulated SMTP/provider delivery bounce or failure",
    };
  }

  const emailEnabled = process.env.REWARDS_EMAIL_ENABLED === "true";
  const fromAddress = process.env.REWARDS_FROM_EMAIL || "rewards-noreply@fylshare.com";

  // Record in outbox without logging sensitive raw tokens to stdout
  const record = {
    messageId: `msg_${generateHighEntropyToken(10)}`,
    to: cleanTo,
    from: fromAddress,
    subject,
    category,
    template,
    metadata,
    liveDispatchEnabled: emailEnabled,
    status: emailEnabled ? "accepted_by_provider" : "queued_in_staging_outbox",
    sentAt: new Date().toISOString(),
  };

  sentEmailsOutbox.push(record);

  return {
    ok: true,
    messageId: record.messageId,
    status: "accepted_by_provider",
    liveDispatchEnabled: emailEnabled,
  };
}

module.exports = {
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
};

