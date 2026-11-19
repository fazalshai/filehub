process.env.NODE_ENV = "test";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  computeCampaignRankings,
  validateCampaignForActivation,
  getDayKeyInTimezone,
  classifyDownloadRequest,
  encryptClaimCode,
  decryptClaimCode,
  buildPublicCampaignSummary,
} = require("../lib/rewards");

const baseCampaign = {
  name: "Unit Campaign",
  status: "active",
  startAt: new Date(Date.now() - 3600e3),
  endAt: new Date(Date.now() + 86400e3),
  timezone: "Asia/Dubai",
  eligibleCountries: ["AE"],
  eligibilityRequirements: "UAE residents aged 18 and over.",
  marketplace: "amazon.ae",
  currency: "AED",
  rewardValue: 50,
  prizeCount: 1,
  fundedBudget: 100,
  expectedFees: 0,
  tiePolicy: "extend_budget_for_tied_ranks",
  tieReserveBudget: 50,
  deliveryDeadline: new Date(Date.now() + 10 * 86400e3),
  supportContact: "support@fylshare.com",
  legalAndBrandReviewConfirmed: true,
  fundingVerifiedByOwner: true,
};

function p(id, pts, deliv, days, createdAt) {
  return {
    participantId: id,
    email: `${id}@x.com`,
    emailVerified: true,
    fraudStatus: "clean",
    approvedPoints: pts,
    qualifyingRecipientDeliveries: deliv,
    qualifyingActiveDays: Array.from({ length: days }, (_, i) => `2026-11-${10 + i}`),
    createdAt,
  };
}

test("Ranking ignores signup order and uses published tie-breakers", () => {
  const early = p("early", 10, 2, 1, new Date("2026-01-01"));
  const late = p("late", 10, 3, 1, new Date("2026-11-30"));
  const { rankings } = computeCampaignRankings(baseCampaign, [early, late]);
  assert.equal(rankings[0].participantId, "late"); // more deliveries wins, despite later signup
  assert.equal(rankings[0].rank, 1);
  assert.equal(rankings[1].rank, 2);
});

test("Exact boundary tie extends budget via funded reserve", () => {
  const a = p("a", 10, 2, 2);
  const b = p("b", 10, 2, 2);
  const { rankings, boundaryTieAlert, totalAllocatedBudget } = computeCampaignRankings(baseCampaign, [a, b]);
  assert.equal(boundaryTieAlert, null);
  assert.equal(rankings[0].rank, 1);
  assert.equal(rankings[1].rank, 1);
  assert.equal(totalAllocatedBudget, 100);
});

test("Unfundable boundary tie pauses fulfillment with an alert (no random draw)", () => {
  const trio = [p("a", 5, 1, 1), p("b", 5, 1, 1), p("c", 5, 1, 1)];
  const { boundaryTieAlert } = computeCampaignRankings(baseCampaign, trio);
  assert.match(boundaryTieAlert, /paused pending owner review/);
});

test("Activation validation enforces budget, denomination, tie policy, and no worldwide", () => {
  assert.equal(validateCampaignForActivation(baseCampaign).valid, true);
  const overBudget = validateCampaignForActivation({ ...baseCampaign, prizeCount: 5 });
  assert.equal(overBudget.valid, false);
  const noTie = validateCampaignForActivation({ ...baseCampaign, tiePolicy: null });
  assert.equal(noTie.valid, false);
  const ww = validateCampaignForActivation({ ...baseCampaign, eligibleCountries: ["ALL"] });
  assert.equal(ww.valid, false);
  const badSplit = validateCampaignForActivation({
    ...baseCampaign,
    rewardValue: 15,
    fundedBudget: 15,
    tiePolicy: "split_equally_within_budget",
  });
  assert.ok(badSplit.errors.some((e) => /minimum gift-card denomination/.test(e)));
  const wrongCurrency = validateCampaignForActivation({ ...baseCampaign, currency: "USD" });
  assert.equal(wrongCurrency.valid, false);
});

test("Daily cap day key uses campaign timezone boundaries", () => {
  // 2026-11-16T20:30Z is already 2026-11-17 in Dubai (UTC+4) but still 11-16 in UTC
  const t = new Date("2026-11-16T20:30:00Z");
  assert.equal(getDayKeyInTimezone(t, "Asia/Dubai"), "2026-11-17");
  assert.equal(getDayKeyInTimezone(t, "UTC"), "2026-11-16");
});

test("Download classification handles HEAD, preview, scanners and range continuations", () => {
  const mk = (method, headers = {}, query = {}) => ({ method, headers, query });
  assert.equal(classifyDownloadRequest(mk("HEAD")).countsAsDownloadRequest, false);
  assert.equal(classifyDownloadRequest(mk("GET", {}, { mode: "inline" })).countsAsDownloadRequest, false);
  assert.equal(
    classifyDownloadRequest(mk("GET", { "user-agent": "WhatsApp/2.0" })).countsAsDownloadRequest,
    false
  );
  assert.equal(classifyDownloadRequest(mk("GET", { range: "bytes=500-" })).countsAsDownloadRequest, false);
  assert.equal(classifyDownloadRequest(mk("GET", { range: "bytes=0-99" })).countsAsDownloadRequest, true);
});

test("Gift card codes are encrypted at rest and round-trip", () => {
  const enc = encryptClaimCode("TEST-FIXTURE-ABC-1234");
  assert.ok(!enc.includes("TEST-FIXTURE"));
  assert.equal(decryptClaimCode(enc), "TEST-FIXTURE-ABC-1234");
});

test("Public copy is generated only from a complete active campaign", () => {
  assert.equal(buildPublicCampaignSummary({ ...baseCampaign, status: "draft" }).active, false);
  assert.equal(buildPublicCampaignSummary({ ...baseCampaign, rewardValue: null }).active, false);
  const live = buildPublicCampaignSummary(baseCampaign);
  assert.equal(live.active, true);
  assert.match(live.campaign.generatedCopy.summary, /AED 50/);
  assert.ok(live.campaign.generatedCopy.disclaimers.some((d) => /not a sponsor/.test(d)));
});
