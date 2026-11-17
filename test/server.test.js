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

async function loginAs(username, password) {
  const res = await fetch(`${baseUrl}/api/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Forwarded-For": "10.0.0.1" },
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
