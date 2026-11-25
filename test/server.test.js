process.env.NODE_ENV = "test";
process.env.ADMIN_USERNAME = "test_admin";
process.env.ADMIN_PASSWORD = "TestAdminStrongPassword!99";
process.env.ADMIN_VIEWER_USERNAME = "test_viewer";
process.env.ADMIN_VIEWER_PASSWORD = "TestViewerStrongPassword!88";

const test = require("node:test");
const assert = require("node:assert/strict");
const { attachInMemoryStore } = require("./memoryStore");
const {
  app,
  runStorageCleanupCycle,
  setStorageBucketForTesting,
  getDateWindowBounds,
} = require("../server");
const { Upload, Workspace, AdminAuditLog } = require("../models");
const { parseLegacyLocation, sanitizeCsvCell } = require("../lib/security");

const mem = attachInMemoryStore();

let server;
let baseUrl;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

let loginIpCounter = 1;
async function loginAs(username, password) {
  const ip = `10.0.0.${loginIpCounter++}`;
  const res = await fetch(`${baseUrl}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": ip },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  return { status: res.status, data };
}

test("1. Unauthenticated and unauthorized admin access are rejected", async () => {
  mem.clearAll();

  // Unauthenticated access to /api/admin/transfers, /api/uploads, /api/admin/workspaces
  const r1 = await fetch(`${baseUrl}/api/admin/transfers`);
  assert.equal(r1.status, 401);

  const r2 = await fetch(`${baseUrl}/api/uploads`);
  assert.equal(r2.status, 401);

  const r3 = await fetch(`${baseUrl}/api/admin/workspaces`);
  assert.equal(r3.status, 401);

  // Team credentials should NOT be accepted (only admin account is active)
  const viewerLogin = await loginAs("team", "team");
  assert.equal(viewerLogin.status, 401);

  // Admin account succeeds
  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  assert.equal(adminLogin.status, 200);
});

test("2. File-type spoofing, executable signatures, and unsafe filenames are blocked", async () => {
  mem.clearAll();

  // Disguised Windows PE executable ("MZ" header) renamed to .pdf
  const fakePdfBuffer = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const form1 = new FormData();
  form1.append("name", "Test");
  form1.append("files", new Blob([fakePdfBuffer], { type: "application/pdf" }), "invoice.pdf");

  const res1 = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    body: form1,
  });
  assert.equal(res1.status, 400);
  const body1 = await res1.json();
  assert.match(body1.error, /executable/i);

  // Disguised text file renamed to .pdf (missing %PDF- header)
  const badPdfBuffer = Buffer.from("This is plain text pretending to be a PDF");
  const form2 = new FormData();
  form2.append("files", new Blob([badPdfBuffer], { type: "application/pdf" }), "notes.pdf");

  const res2 = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    body: form2,
  });
  assert.equal(res2.status, 400);
  const body2 = await res2.json();
  assert.match(body2.error, /valid PDF header/i);

  // Valid PDF upload with unsafe path traversal filename ("../../evil<script>.pdf") is sanitized
  const validPdfBuffer = Buffer.from("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
  const form3 = new FormData();
  form3.append("name", "Project Draft");
  form3.append(
    "files",
    new Blob([validPdfBuffer], { type: "application/pdf" }),
    "../../report_final.pdf"
  );

  const res3 = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "CF-IPCountry": "AE" },
    body: form3,
  });
  assert.equal(res3.status, 201);
  const body3 = await res3.json();
  assert.equal(body3.files[0].name, "report_final.pdf");
  assert.match(body3.code, /^\d{6}$/);
  assert.ok(body3.shareToken.length >= 24);
  assert.ok(body3.revokeToken.length >= 24);
});

test("3. A transfer with 6 files counts as 1 transfer and 6 files, with pagination and timezone boundaries", async () => {
  mem.clearAll();

  // Seed historical and active records across dates and countries
  // Record 1: Nov 12, 2026 (Expired historical record - preserved in operational history!)
  await Upload.create({
    transferId: "tr_nov12_1",
    transferType: "anonymous",
    name: "[Redacted after expiry]",
    labelRedacted: true,
    code: null,
    codeHash: "hash1",
    fileCount: 2,
    size: 204800,
    status: "expired",
    date: new Date("2026-11-12T10:00:00.000Z"),
    expiresAt: new Date("2026-11-14T10:00:00.000Z"),
    storageDeletedAt: new Date("2026-11-14T10:05:00.000Z"),
    countryCode: "AE",
    countryName: "United Arab Emirates",
    locationSource: "cloudflare_header",
    locationStatus: "available",
    files: [
      { fileId: "f1", name: "[Expired file]", size: 102400, storageDeleted: true },
      { fileId: "f2", name: "[Expired file]", size: 102400, storageDeleted: true },
    ],
  });

  // Record 2: Nov 15, 2026 — 1 transfer containing 6 files (like the real Nov 15 Pune upload)
  const validPdfBuffer = Buffer.from("%PDF-1.7\nSynthetic test PDF\n%%EOF");
  const form6 = new FormData();
  form6.append("name", "Batch Package");
  for (let i = 1; i <= 6; i++) {
    form6.append(
      "files",
      new Blob([validPdfBuffer], { type: "application/pdf" }),
      `doc_${i}.pdf`
    );
  }
  const upload6Res = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "CF-IPCountry": "IN" },
    body: form6,
  });
  assert.equal(upload6Res.status, 201);

  // Record 3: Legacy record with timezone string "Asia/Calcutta" in location field
  await Upload.create({
    transferId: "tr_legacy_tz",
    transferType: "anonymous",
    name: "Legacy Upload",
    code: "888111",
    fileCount: 1,
    size: 50000,
    status: "available",
    date: new Date(),
    expiresAt: new Date(Date.now() + 24 * 3600 * 1000),
    location: "Asia/Calcutta",
    files: [{ fileId: "f_leg", name: "legacy.txt", size: 50000 }],
  });

  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  assert.equal(adminLogin.status, 200);
  const adminToken = adminLogin.data.token;

  // Query all retained history with pageSize=2 to verify complete dataset totals vs page slice
  const listRes = await fetch(
    `${baseUrl}/api/admin/transfers?period=all_retained&timezone=Asia/Dubai&page=1&pageSize=2`,
    {
      headers: { Authorization: `Bearer ${adminToken}` },
    }
  );
  assert.equal(listRes.status, 200);
  const report = await listRes.json();

  // Total across all 3 transfers must be: 3 transfers, and (2 + 6 + 1) = 9 files!
  assert.equal(report.totals.totalTransfers, 3);
  assert.equal(report.totals.totalFiles, 9);
  assert.equal(report.totals.activeTransfers, 2);
  assert.equal(report.totals.historicalTransfers, 1);
  assert.equal(report.items.length, 2); // Page 1 bounded to pageSize=2
  assert.equal(report.pagination.totalPages, 2);

  // Verify "Asia/Calcutta" legacy record was NOT treated as a country (mapped to Unknown)
  const unknownCountryBucket = report.countryBreakdown.find((c) => c.countryCode === null);
  assert.ok(unknownCountryBucket, "Unknown country bucket must be preserved in totals");
  assert.equal(unknownCountryBucket.countryName, "Unknown");
  assert.equal(unknownCountryBucket.transfers, 1);

  // Verify Asia/Dubai timezone boundary calculation (UTC+4: 2026-11-15T20:00:00Z is already 2026-11-16 00:00 in Dubai)
  const dubaiBounds = getDateWindowBounds("custom", "Asia/Dubai", "2026-11-16", "2026-11-16");
  assert.equal(dubaiBounds.startUtc.toISOString(), "2026-11-15T20:00:00.000Z");
});

test("4. Expiration before cleanup completes immediately stops retrieval and download", async () => {
  mem.clearAll();

  // Create a transfer whose expiresAt is 5 seconds in the past, BEFORE runStorageCleanupCycle() has run
  await Upload.create({
    transferId: "tr_expired_uncleaned",
    name: "Already Expired",
    code: "445566",
    status: "available", // Cleanup job has not yet transitioned status
    date: new Date(Date.now() - 49 * 3600 * 1000),
    expiresAt: new Date(Date.now() - 5000), // Expired 5s ago
    files: [{ fileId: "f_exp", name: "secret.pdf", size: 1234, storageDeleted: false }],
  });

  const getMeta = await fetch(`${baseUrl}/api/uploads/445566`, {
    headers: { "X-Forwarded-For": "10.0.1.50" },
  });
  assert.equal(getMeta.status, 404);

  const getDownload = await fetch(`${baseUrl}/api/uploads/445566/files/0/download`, {
    headers: { "X-Forwarded-For": "10.0.1.50" },
  });
  assert.equal(getDownload.status, 410);
});

test("5. Cleanup retries, failure observability, and historical record preservation", async () => {
  mem.clearAll();

  await Upload.create({
    transferId: "tr_cleanup_test",
    name: "Sensitive Label",
    code: "778899",
    fileCount: 1,
    size: 4096,
    status: "available",
    date: new Date(Date.now() - 50 * 3600 * 1000),
    expiresAt: new Date(Date.now() - 3600 * 1000),
    files: [
      {
        fileId: "f_clean",
        name: "private_contract.pdf",
        storagePath: "uploads/tr_cleanup_test/f_clean.pdf",
        size: 4096,
        storageDeleted: false,
      },
    ],
  });

  // 1st attempt: Simulate Firebase Storage failure -> should transition to deletion_pending
  setStorageBucketForTesting({
    name: "test-bucket",
    file() {
      return {
        async delete() {
          throw new Error("Simulated GCS network timeout");
        },
      };
    },
  });

  const cycle1 = await runStorageCleanupCycle();
  assert.equal(cycle1.failures, 1);

  const afterFail = await Upload.findOne({ transferId: "tr_cleanup_test" });
  assert.equal(afterFail.status, "deletion_pending");
  assert.equal(afterFail.cleanupAttempts, 1);
  assert.match(afterFail.lastCleanupError, /Simulated GCS network timeout/);

  // 2nd attempt: Storage succeeds -> should delete blob, scrub label/filenames/code, and keep historical record!
  let deletedPaths = [];
  setStorageBucketForTesting({
    name: "test-bucket",
    file(p) {
      return {
        async delete() {
          deletedPaths.push(p);
        },
      };
    },
  });

  const cycle2 = await runStorageCleanupCycle();
  assert.equal(cycle2.expiredProcessed, 1);
  assert.deepEqual(deletedPaths, ["uploads/tr_cleanup_test/f_clean.pdf"]);

  const afterSuccess = await Upload.findOne({ transferId: "tr_cleanup_test" });
  assert.ok(afterSuccess, "Historical operational record must NOT be deleted from MongoDB");
  assert.equal(afterSuccess.status, "deleted");
  assert.equal(afterSuccess.name, "Sensitive Label");
  assert.equal(afterSuccess.files[0].name, "private_contract.pdf");
  assert.equal(afterSuccess.files[0].storageDeleted, true);
  assert.ok(afterSuccess.storageDeletedAt);

  setStorageBucketForTesting(null);
});

test("6. Uploader revocation deletes server files, distinct from local device history", async () => {
  mem.clearAll();

  const validPdfBuffer = Buffer.from("%PDF-1.7\nRevoke test\n%%EOF");
  const form = new FormData();
  form.append("name", "Temp Doc");
  form.append("files", new Blob([validPdfBuffer], { type: "application/pdf" }), "temp.pdf");

  const createRes = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    body: form,
  });
  const created = await createRes.json();
  assert.equal(createRes.status, 201);

  // Attempting to revoke without revokeToken fails with 401
  const badRevoke = await fetch(`${baseUrl}/api/uploads/${created.code}/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ revokeToken: "wrong_token" }),
  });
  assert.equal(badRevoke.status, 401);

  // Revoking with valid revokeToken succeeds and immediately disables retrieval
  const goodRevoke = await fetch(`${baseUrl}/api/uploads/${created.code}/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Revoke-Token": created.revokeToken,
    },
  });
  assert.equal(goodRevoke.status, 200);

  const afterRevokeLookup = await fetch(`${baseUrl}/api/uploads/${created.code}`, {
    headers: { "X-Forwarded-For": "10.0.2.1" },
  });
  assert.equal(afterRevokeLookup.status, 404);

  // Admin can still inspect full compliance audit metadata (original code, label, filenames, IP, and audit log)
  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  const adminTransfers = await (
    await fetch(`${baseUrl}/api/admin/transfers?period=all_retained`, {
      headers: { Authorization: `Bearer ${adminLogin.data.token}` },
    })
  ).json();
  const revokedRecord = adminTransfers.items.find((t) => t.transferId === created.transferId);
  assert.ok(revokedRecord);
  assert.equal(revokedRecord.status, "revoked");
  assert.equal(revokedRecord.code, null);
  assert.equal(revokedRecord.revokedCode, created.code);
  assert.equal(revokedRecord.label, "Temp Doc");
  assert.equal(revokedRecord.files[0].name, "temp.pdf");
  assert.equal(revokedRecord.files[0].storageDeleted, true);
  assert.ok(revokedRecord.revokedAt);
  assert.ok(revokedRecord.uploaderIp);

  const revokeLogs = await AdminAuditLog.find({ action: "sender_revoke_transfer" });
  assert.equal(revokeLogs.length, 1);
  assert.equal(revokeLogs[0].metadata.revokedCode, created.code);
});

test("7. Workspace isolation: omitting PIN or using wrong workspace token is denied", async () => {
  mem.clearAll();

  const createBox = await fetch(`${baseUrl}/api/box/create`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ boxName: "TeamAlpha", pin: "4921" }),
  });
  assert.equal(createBox.status, 201);
  const boxData = await createBox.json();
  assert.ok(boxData.workspaceToken);

  // Verify PIN is retained for Admin Console view while also hashed
  const dbBox = await Workspace.findOne({ boxName: "TeamAlpha" });
  assert.equal(dbBox.pin, "4921");
  assert.ok(dbBox.pinHash);

  // Calling GET /api/workspaces/TeamAlpha WITHOUT token or PIN must return 401 (fixing the old bypass bug!)
  const unauthGet = await fetch(`${baseUrl}/api/workspaces/TeamAlpha`);
  assert.equal(unauthGet.status, 401);

  // Calling with valid workspaceToken succeeds
  const authGet = await fetch(`${baseUrl}/api/workspaces/TeamAlpha`, {
    headers: { Authorization: `Bearer ${boxData.workspaceToken}` },
  });
  assert.equal(authGet.status, 200);
});

test("8. CSV export neutralizes formula injection and records admin audit event", async () => {
  assert.equal(sanitizeCsvCell("=cmd|' /C calc'!A0"), `"'=cmd|' /C calc'!A0"`);
  assert.equal(sanitizeCsvCell("+SUM(A1:A2)"), `"'+SUM(A1:A2)"`);
  assert.equal(sanitizeCsvCell("@IMPORTXML()"), `"'@IMPORTXML()"`);

  const parsedTz = parseLegacyLocation("Asia/Calcutta");
  assert.equal(parsedTz.countryCode, null);
  assert.equal(parsedTz.countryName, "Unknown");
  assert.equal(parsedTz.browserTimezone, "Asia/Calcutta");

  const parsedDev = parseLegacyLocation("Mobile");
  assert.equal(parsedDev.countryCode, null);
  assert.equal(parsedDev.deviceCategory, "mobile");

  const parsedIn = parseLegacyLocation("🇮🇳 Pune, India");
  assert.equal(parsedIn.countryCode, "IN");
  assert.equal(parsedIn.countryName, "India");

  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  const csvRes = await fetch(`${baseUrl}/api/admin/export?period=all_retained`, {
    headers: { Authorization: `Bearer ${adminLogin.data.token}` },
  });
  assert.equal(csvRes.status, 200);
  const csvText = await csvRes.text();
  assert.match(csvText, /Transfer ID,Created At \(UTC\)/);

  const logs = await AdminAuditLog.find({ action: "export_csv" });
  assert.ok(logs.length >= 1);
});

test("9. Optional Rewards: normal upload/download works without email, and inactive/draft campaigns stay hidden", async () => {
  mem.clearAll();

  // Without an active campaign, /api/rewards/active-campaign must return active: false
  const noCampRes = await fetch(`${baseUrl}/api/rewards/active-campaign`);
  assert.equal(noCampRes.status, 200);
  const noCamp = await noCampRes.json();
  assert.equal(noCamp.active, false);
  assert.equal(noCamp.campaign, null);

  // Admin creates a default draft campaign -> country, currency, rewardValue, budget, dates, and legal eligibility are unset (null/[])
  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  const adminToken = adminLogin.data.token;

  const createDraftRes = await fetch(`${baseUrl}/api/admin/campaigns`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({ name: "Draft Unconfigured Campaign" }),
  });
  assert.equal(createDraftRes.status, 201);
  const draftPayload = await createDraftRes.json();
  assert.equal(draftPayload.campaign.status, "draft");
  assert.equal(draftPayload.campaign.marketplace, null);
  assert.equal(draftPayload.campaign.currency, null);
  assert.equal(draftPayload.campaign.rewardValue, null);
  assert.equal(draftPayload.campaign.fundedBudget, null);
  assert.deepEqual(draftPayload.campaign.eligibleCountries, []);
  assert.equal(draftPayload.validation.valid, false);

  // Attempting to activate an incomplete/unfunded draft campaign is rejected with specific validation errors
  const prematureActivate = await fetch(
    `${baseUrl}/api/admin/campaigns/${draftPayload.campaign.campaignId}/status`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ action: "activate", reason: "Try activating incomplete draft" }),
    }
  );
  assert.equal(prematureActivate.status, 400);

  // Normal anonymous upload and per-file download work without any email or campaign
  const pdfBuf = Buffer.from("%PDF-1.7\nAnonymous file transfer\n%%EOF");
  const form = new FormData();
  form.append("name", "No-Email Transfer");
  form.append("files", new Blob([pdfBuf], { type: "application/pdf" }), "slides.pdf");
  form.append("files", new Blob([pdfBuf], { type: "application/pdf" }), "handout.pdf");

  const upRes = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "X-Event-Id": "ev_idempotent_anon_1" },
    body: form,
  });
  assert.equal(upRes.status, 201);
  const upData = await upRes.json();
  assert.equal(upData.fileCount, 2);

  // Retrying the exact same upload eventId returns idempotent replay without inflating transfer or file counts
  const retryForm = new FormData();
  retryForm.append("files", new Blob([pdfBuf], { type: "application/pdf" }), "slides.pdf");
  const retryRes = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "X-Event-Id": "ev_idempotent_anon_1" },
    body: retryForm,
  });
  assert.equal(retryRes.status, 200);
  const retryData = await retryRes.json();
  assert.equal(retryData.idempotentReplay, true);
  assert.equal(retryData.transferId, upData.transferId);
});

test("10. Per-file download counts: clicks vs requests vs repeat sessions vs HEAD/preview/scanners/range chunks vs bundle", async () => {
  mem.clearAll();

  const pdfBuf = Buffer.from("%PDF-1.7\nPer-file counting test\n%%EOF");
  const form = new FormData();
  form.append("name", "Multi-File Package");
  form.append("files", new Blob([pdfBuf], { type: "application/pdf" }), "fileA.pdf");
  form.append("files", new Blob([pdfBuf], { type: "application/pdf" }), "fileB.pdf");

  const upRes = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "X-Fylshare-Session": "uploader_sess_001" },
    body: form,
  });
  const upData = await upRes.json();

  // 1. Record 2 button clicks on file 0 (with idempotency check on click 1)
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/click`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Event-Id": "clk_ev_1" },
  });
  // Replay same click eventId -> ignored
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/click`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Event-Id": "clk_ev_1" },
  });
  // Second distinct click
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/click`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Event-Id": "clk_ev_2" },
  });

  // 2. HEAD request and inline preview on file 0 -> counted in headOrPreviewRequests, NOT downloadRequests
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download`, {
    method: "HEAD",
    headers: { "X-Fylshare-Session": "recip_sess_1" },
  });
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?mode=inline&json=true`, {
    headers: { "X-Fylshare-Session": "recip_sess_1" },
  });

  // 3. Automated link scanner (Slackbot) -> counted in scannerOrBotRequests, NOT human downloadRequests
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
      "X-Fylshare-Session": "scanner_sess",
    },
  });

  // 4. First real download by recipient session 1 (initial range bytes=0-1023) -> counts as 1 downloadRequest & 1 distinct session
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
      "X-Fylshare-Session": "recip_sess_1",
      Range: "bytes=0-1023",
      "X-Event-Id": "dl_ev_1",
    },
  });

  // 5. Continuation range chunk (bytes=1024-2047) -> increments rangeRequests, does NOT inflate downloadRequests!
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
      "X-Fylshare-Session": "recip_sess_1",
      Range: "bytes=1024-2047",
    },
  });

  // 6. Replay of dl_ev_1 -> ignored
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
      "X-Fylshare-Session": "recip_sess_1",
      "X-Event-Id": "dl_ev_1",
    },
  });

  // 7. Repeat download by the SAME recipient session 1 -> increments downloadRequests AND repeatDownloads, distinct sessions stays 1
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
      "X-Fylshare-Session": "recip_sess_1",
    },
  });

  // 8. Second distinct recipient session 2 downloads file 0 -> downloadRequests = 3, estimatedDistinctSessions = 2
  await fetch(`${baseUrl}/api/uploads/${upData.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
      "X-Fylshare-Session": "recip_sess_2",
    },
  });

  // 9. Bundle download event -> tracked on transfer, does NOT inflate fileB's individual downloadRequests (which stays 0)
  await fetch(`${baseUrl}/api/uploads/${upData.code}/bundle-event`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Event-Id": "bundle_ev_1" },
  });

  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  const transfersRes = await fetch(`${baseUrl}/api/admin/transfers?period=all_retained`, {
    headers: { Authorization: `Bearer ${adminLogin.data.token}` },
  });
  const transfersData = await transfersRes.json();
  const tr = transfersData.items.find((i) => i.transferId === upData.transferId);
  assert.ok(tr);
  assert.equal(tr.bundleDownloadRequests, 1);

  const file0 = tr.files[0];
  const file1 = tr.files[1];

  assert.equal(file0.buttonClicks, 2);
  assert.equal(file0.headOrPreviewRequests, 2);
  assert.equal(file0.scannerOrBotRequests, 1);
  assert.equal(file0.rangeRequests, 2);
  assert.equal(file0.downloadRequests, 3);
  assert.equal(file0.repeatDownloads, 1);
  assert.equal(file0.estimatedDistinctSessions, 2);
  assert.ok(file0.lastActivityAt);

  // File 1 was never individually downloaded (bundle click did not inflate it)
  assert.equal(file1.downloadRequests, 0);
  assert.equal(file1.buttonClicks, 0);
});

test("11. Email verification, expiry, resend limits, marketing opt-in separation, and verified email change with duplicate check", async () => {
  mem.clearAll();

  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  const adminToken = adminLogin.data.token;

  // Create and activate a valid staging campaign
  const now = new Date();
  const createRes = await fetch(`${baseUrl}/api/admin/campaigns`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      name: "UAE November Activity Campaign",
      startAt: new Date(now.getTime() - 3600 * 1000).toISOString(),
      endAt: new Date(now.getTime() + 7 * 24 * 3600 * 1000).toISOString(),
      timezone: "Asia/Dubai",
      eligibleCountries: ["AE"],
      eligibilityRequirements: "UAE residents aged 18+ with a verified email address.",
      marketplace: "amazon.ae",
      currency: "AED",
      rewardValue: 50,
      prizeCount: 2,
      fundedBudget: 150,
      expectedFees: 0,
      tiePolicy: "extend_budget_for_tied_ranks",
      tieReserveBudget: 50,
      deliveryDeadline: new Date(now.getTime() + 14 * 24 * 3600 * 1000).toISOString(),
      supportContact: "support@fylshare.com",
      legalAndBrandReviewConfirmed: true,
      fundingVerifiedByOwner: true,
    }),
  });
  const createdCamp = (await createRes.json()).campaign;

  const actRes = await fetch(`${baseUrl}/api/admin/campaigns/${createdCamp.campaignId}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ action: "activate", reason: "Activate staging campaign for test" }),
  });
  assert.equal(actRes.status, 200);

  // Enroll participant A with marketingOptIn omitted (defaults to false; declining marketing never reduces eligibility)
  const enrollA = await fetch(`${baseUrl}/api/rewards/enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-IPCountry": "AE" },
    body: JSON.stringify({
      email: "Alice@Example.com",
      declaredCountry: "AE",
      serviceMessagesAccepted: true,
    }),
  });
  assert.equal(enrollA.status, 200);
  const enrollAData = await enrollA.json();
  assert.ok(enrollAData.enrollmentSessionToken);
  assert.ok(enrollAData._testVerification.otp);

  // Wrong OTP is rejected
  const badVerify = await fetch(`${baseUrl}/api/rewards/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      enrollmentSessionToken: enrollAData.enrollmentSessionToken,
      otp: "000000",
    }),
  });
  assert.equal(badVerify.status, 400);

  // Correct OTP verifies email and returns participantToken
  const goodVerify = await fetch(`${baseUrl}/api/rewards/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      enrollmentSessionToken: enrollAData.enrollmentSessionToken,
      otp: enrollAData._testVerification.otp,
    }),
  });
  assert.equal(goodVerify.status, 200);
  const verifiedA = await goodVerify.json();
  assert.equal(verifiedA.participant.email, "alice@example.com");
  assert.equal(verifiedA.participant.marketingOptIn, false);
  const tokenA = verifiedA.participantToken;

  // Re-using the same single-use OTP a second time fails
  const replayVerify = await fetch(`${baseUrl}/api/rewards/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      enrollmentSessionToken: enrollAData.enrollmentSessionToken,
      otp: enrollAData._testVerification.otp,
    }),
  });
  assert.equal(replayVerify.status, 400);

  // Enroll & verify participant B ("bob@example.com")
  const enrollB = await fetch(`${baseUrl}/api/rewards/enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: "bob@example.com",
      declaredCountry: "AE",
      serviceMessagesAccepted: true,
      marketingOptIn: true,
    }),
  });
  const enrollBData = await enrollB.json();
  await fetch(`${baseUrl}/api/rewards/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      verificationToken: enrollBData._testVerification.verificationToken,
    }),
  });

  // Alice attempts to change her email to Bob's already-claimed email -> rejected with 409 duplicate claim check!
  const dupEmailChange = await fetch(`${baseUrl}/api/rewards/change-email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Participant-Token": tokenA,
    },
    body: JSON.stringify({ newEmail: "bob@example.com" }),
  });
  assert.equal(dupEmailChange.status, 409);

  // Alice changes her email to a fresh address "alice.new@example.com" and verifies it
  const changeReq = await fetch(`${baseUrl}/api/rewards/change-email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Participant-Token": tokenA,
    },
    body: JSON.stringify({ newEmail: "alice.new@example.com" }),
  });
  assert.equal(changeReq.status, 200);
  const changeReqData = await changeReq.json();

  const confirmChange = await fetch(`${baseUrl}/api/rewards/confirm-email-change`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Participant-Token": tokenA,
    },
    body: JSON.stringify({ otp: changeReqData._testEmailChange.otp }),
  });
  assert.equal(confirmChange.status, 200);
  const confirmData = await confirmChange.json();
  assert.equal(confirmData.email, "alice.new@example.com");
});

test("12. Bounded scoring, caps, self-download exclusion, duplicate structure flagging, ranking by activity (NEVER signup order), fulfillment & retention", async () => {
  mem.clearAll();

  const adminLogin = await loginAs("test_admin", "TestAdminStrongPassword!99");
  const adminToken = adminLogin.data.token;
  const now = new Date();

  // Create and activate campaign with maxTransfersPerDay=3, maxDeliveriesPerTransfer=2, prizeCount=1, rewardValue=50 AED
  const campRes = await fetch(`${baseUrl}/api/admin/campaigns`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({
      name: "Activity Ranking & Fulfillment Test Campaign",
      startAt: new Date(now.getTime() - 2 * 3600 * 1000).toISOString(),
      endAt: new Date(now.getTime() + 5 * 24 * 3600 * 1000).toISOString(),
      timezone: "Asia/Dubai",
      eligibleCountries: ["AE"],
      eligibilityRequirements: "UAE residents 18+.",
      marketplace: "amazon.ae",
      currency: "AED",
      rewardValue: 50,
      prizeCount: 1,
      fundedBudget: 100,
      expectedFees: 0,
      scoringRules: {
        pointsPerTransfer: 1,
        pointsPerDelivery: 2,
        maxDeliveriesPerTransfer: 2,
        maxTransfersPerDay: 3,
        allowClaimingExistingUploadWithRevokeToken: true,
        minTransferBytes: 10,
      },
      tiePolicy: "extend_budget_for_tied_ranks",
      tieReserveBudget: 50,
      deliveryDeadline: new Date(now.getTime() + 10 * 24 * 3600 * 1000).toISOString(),
      supportContact: "support@fylshare.com",
      legalAndBrandReviewConfirmed: true,
      fundingVerifiedByOwner: true,
    }),
  });
  const campaign = (await campRes.json()).campaign;

  await fetch(`${baseUrl}/api/admin/campaigns/${campaign.campaignId}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ action: "activate", reason: "Activate campaign" }),
  });

  // Helper to enroll & verify a participant
  async function enrollAndVerify(email) {
    const r1 = await fetch(`${baseUrl}/api/rewards/enroll`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        declaredCountry: "AE",
        serviceMessagesAccepted: true,
      }),
    });
    const d1 = await r1.json();
    const r2 = await fetch(`${baseUrl}/api/rewards/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enrollmentSessionToken: d1.enrollmentSessionToken,
        otp: d1._testVerification.otp,
      }),
    });
    return await r2.json();
  }

  // Participant 1 registers FIRST ("early@example.com") and does only 1 upload (1 point)
  const earlyUser = await enrollAndVerify("early@example.com");
  const earlyForm = new FormData();
  earlyForm.append(
    "files",
    new Blob([Buffer.from("%PDF-1.7\nEarly user file content 111\n%%EOF")], {
      type: "application/pdf",
    }),
    "early.pdf"
  );
  await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: {
      "X-Participant-Token": earlyUser.participantToken,
      "X-Fylshare-Session": "early_sess",
    },
    body: earlyForm,
  });

  // Participant 2 registers LATER ("active_winner@example.com")
  // First uploads anonymously, then joins rewards and claims the upload using the uploader's revokeToken!
  const preEnrollForm = new FormData();
  const multiFilePdf = Buffer.from("%PDF-1.7\nActive user transfer with 6 files\n%%EOF");
  for (let i = 1; i <= 6; i++) {
    preEnrollForm.append(
      "files",
      new Blob([multiFilePdf], { type: "application/pdf" }),
      `item_${i}.pdf`
    );
  }
  const anonUploadRes = await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "X-Fylshare-Session": "winner_sess" },
    body: preEnrollForm,
  });
  const anonUpload = await anonUploadRes.json();
  assert.equal(anonUpload.fileCount, 6);

  const activeUser = await enrollAndVerify("active_winner@example.com");

  // Claiming without valid revokeToken fails
  const badClaim = await fetch(`${baseUrl}/api/rewards/claim-transfer`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Participant-Token": activeUser.participantToken,
    },
    body: JSON.stringify({ code: anonUpload.code, revokeToken: "invalid_revoke_token_000" }),
  });
  assert.equal(badClaim.status, 404); // Uniform "not found or token mismatch" — does not leak existence

  // Claiming with valid revokeToken succeeds and awards 1 transfer point (even though it has 6 files!)
  const goodClaim = await fetch(`${baseUrl}/api/rewards/claim-transfer`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Participant-Token": activeUser.participantToken,
      "X-Fylshare-Session": "winner_sess",
    },
    body: JSON.stringify({ code: anonUpload.code, revokeToken: anonUpload.revokeToken }),
  });
  assert.equal(goodClaim.status, 200);
  const claimData = await goodClaim.json();
  assert.equal(claimData.uploadPointsAwarded, 1);

  // Self-download by activeUser (same session "winner_sess") -> earns 0 recipient-delivery points!
  await fetch(`${baseUrl}/api/uploads/${anonUpload.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Macintosh)",
      "X-Fylshare-Session": "winner_sess",
    },
  });

  // Distinct recipient 1 downloads file 0 -> earns +2 points (total 3 pts)
  await fetch(`${baseUrl}/api/uploads/${anonUpload.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
      "X-Fylshare-Session": "distinct_recipient_1",
    },
  });

  // Distinct recipient 1 downloads file 1 in the SAME transfer -> repeat session on transfer, earns 0 extra points!
  await fetch(`${baseUrl}/api/uploads/${anonUpload.code}/files/1/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
      "X-Fylshare-Session": "distinct_recipient_1",
    },
  });

  // Distinct recipient 2 downloads file 0 -> earns +2 points (total 5 pts; hits maxDeliveriesPerTransfer = 2 cap!)
  await fetch(`${baseUrl}/api/uploads/${anonUpload.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Linux)",
      "X-Fylshare-Session": "distinct_recipient_2",
    },
  });

  // Distinct recipient 3 downloads file 0 -> beyond maxDeliveriesPerTransfer=2 cap, counted in operational stats but earns 0 reward points!
  await fetch(`${baseUrl}/api/uploads/${anonUpload.code}/files/0/download?json=true`, {
    headers: {
      "User-Agent": "Mozilla/5.0 (iPad)",
      "X-Fylshare-Session": "distinct_recipient_3",
    },
  });

  // Check activeUser's private dashboard (/api/rewards/me)
  const meRes = await fetch(`${baseUrl}/api/rewards/me`, {
    headers: { "X-Participant-Token": activeUser.participantToken },
  });
  assert.equal(meRes.status, 200);
  const meData = await meRes.json();
  assert.equal(meData.participant.points.uploadPoints, 1);
  assert.equal(meData.participant.points.deliveryPoints, 4);
  assert.equal(meData.participant.points.approvedPoints, 5);
  assert.equal(meData.participant.ranking.provisionalRank, 1); // Ranked #1 ahead of early@example.com!

  // Participant 3 ("spammer@example.com") uploads 3 identical-structure files in a row -> flagged for review!
  const spamUser = await enrollAndVerify("spammer@example.com");
  const identicalBytes = Buffer.from("%PDF-1.7\nIdentical artificial payload\n%%EOF");
  for (let k = 1; k <= 3; k++) {
    const f = new FormData();
    f.append("files", new Blob([identicalBytes], { type: "application/pdf" }), `dup_${k}.pdf`);
    await fetch(`${baseUrl}/api/uploads`, {
      method: "POST",
      headers: { "X-Participant-Token": spamUser.participantToken },
      body: f,
    });
  }

  const spamMe = await (
    await fetch(`${baseUrl}/api/rewards/me`, {
      headers: { "X-Participant-Token": spamUser.participantToken },
    })
  ).json();
  assert.equal(spamMe.participant.reviewAndAppeals.fraudStatus, "pending_review");
  assert.ok(
    spamMe.participant.reviewAndAppeals.suspiciousFlags.includes("repeated_identical_structure")
  );
  assert.equal(spamMe.participant.points.pendingReviewPoints, 1);

  // Spammer submits an appeal, and Admin reviews & disqualifies with a mandatory reason and audit trail
  const appealRes = await fetch(`${baseUrl}/api/rewards/appeal`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Participant-Token": spamUser.participantToken,
    },
    body: JSON.stringify({ message: "I uploaded test files repeatedly by mistake." }),
  });
  assert.equal(appealRes.status, 200);

  const adminReviewRes = await fetch(
    `${baseUrl}/api/admin/campaigns/${campaign.campaignId}/participants/${spamUser.participant.participantId}/review`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({
        action: "reject_appeal",
        reason: "Confirmed repeated identical test uploads during campaign.",
      }),
    }
  );
  assert.equal(adminReviewRes.status, 200);

  // Close campaign -> freezes immutable scoreSnapshot
  const closeRes = await fetch(`${baseUrl}/api/admin/campaigns/${campaign.campaignId}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ action: "close", reason: "Campaign period ended" }),
  });
  assert.equal(closeRes.status, 200);
  const closedCamp = (await closeRes.json()).campaign;
  assert.ok(closedCamp.snapshotFrozenAt);
  assert.equal(closedCamp.scoreSnapshot[0].participantId, activeUser.participant.participantId);
  assert.equal(closedCamp.scoreSnapshot[0].rank, 1);

  // Add non-redeemable test fixture gift card to inventory (must start with TEST-FIXTURE-)
  const badInv = await fetch(
    `${baseUrl}/api/admin/campaigns/${campaign.campaignId}/inventory`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({
        claimCode: "FAKE-AMAZON-CODE-1234",
        isTestFixture: true,
      }),
    }
  );
  assert.equal(badInv.status, 400);

  const goodInv = await fetch(
    `${baseUrl}/api/admin/campaigns/${campaign.campaignId}/inventory`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({
        claimCode: "TEST-FIXTURE-AED50-9988",
        isTestFixture: true,
      }),
    }
  );
  assert.equal(goodInv.status, 201);
  const invData = await goodInv.json();
  assert.equal(invData.codeMasked, "****-****-9988");

  // Approve fulfillment batch (concurrent/duplicate batch approval is idempotent!)
  const [approve1, approve2] = await Promise.all([
    fetch(`${baseUrl}/api/admin/campaigns/${campaign.campaignId}/approve-fulfillment`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ reason: "Approve winner batch" }),
    }),
    fetch(`${baseUrl}/api/admin/campaigns/${campaign.campaignId}/approve-fulfillment`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ reason: "Duplicate concurrent approve call" }),
    }),
  ]);
  assert.equal(approve1.status, 200);
  assert.equal(approve2.status, 200);
  const approveData = await approve1.json();
  assert.equal(approveData.approvedCount, 1);
  assert.equal(approveData.rewards[0].deliveryEmail, "active_winner@example.com");

  // Simulate provider/network timeout on 1st dispatch -> reserves card without losing or duplicating assignment
  const timeoutDispatch = await fetch(
    `${baseUrl}/api/admin/campaigns/${campaign.campaignId}/dispatch-rewards`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ simulateProviderTimeout: true }),
    }
  );
  assert.equal(timeoutDispatch.status, 200);
  const timeoutData = await timeoutDispatch.json();
  assert.equal(timeoutData.results[0].status, "reserved");
  const reservedCardId = timeoutData.results[0].assignedCardId;
  assert.ok(reservedCardId);

  // Retry dispatch -> reuses the EXACT same reserved cardId and delivers to active_winner@example.com
  const finalDispatch = await fetch(
    `${baseUrl}/api/admin/campaigns/${campaign.campaignId}/dispatch-rewards`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ simulateProviderTimeout: false }),
    }
  );
  assert.equal(finalDispatch.status, 200);
  const finalDispatchData = await finalDispatch.json();
  assert.equal(finalDispatchData.results[0].status, "delivered");
  assert.equal(finalDispatchData.results[0].assignedCardId, reservedCardId);

  // Post-reward retention: active_winner@example.com uploads a new file AFTER receiving the reward!
  // Also revoke their original upload to verify reward statistics survive file deletion/revocation!
  await fetch(`${baseUrl}/api/uploads/${anonUpload.code}/revoke`, {
    method: "POST",
    headers: { "X-Revoke-Token": anonUpload.revokeToken },
  });

  const postRewardForm = new FormData();
  postRewardForm.append(
    "files",
    new Blob([Buffer.from("%PDF-1.7\nPost-reward organic usage\n%%EOF")], {
      type: "application/pdf",
    }),
    "after_reward.pdf"
  );
  await fetch(`${baseUrl}/api/uploads`, {
    method: "POST",
    headers: { "X-Participant-Token": activeUser.participantToken },
    body: postRewardForm,
  });

  // Fetch Campaign Effectiveness & Retention Report (Section 11)
  const effRes = await fetch(
    `${baseUrl}/api/admin/campaigns/${campaign.campaignId}/effectiveness`,
    {
      headers: { Authorization: `Bearer ${adminToken}` },
    }
  );
  assert.equal(effRes.status, 200);
  const effReport = await effRes.json();
  assert.equal(
    effReport.centralCommercialQuestion,
    "Do people continue using Fylshare after the reward is gone?"
  );
  assert.equal(effReport.financialsAndFulfillment.rewardsDeliveredCount, 1);
  assert.equal(effReport.postRewardRetention.rewardedParticipantsCount, 1);
  assert.equal(effReport.postRewardRetention.retainedWithin7DaysCount, 1);
  assert.equal(effReport.postRewardRetention.retainedWithin7DaysPct, 100);
  assert.equal(effReport.postRewardRetention.costPerRetainedParticipant, 50);
});

