'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { createApp } = require('../src/server');
const { listPresets, PRESET_ORDER } = require('../src/presets');
const { mintDynamicQrPayload, verifyDynamicQrPayload, checkWifiIpPolicy, ipMatchesRule } = require('../src/login512/qr-guard');

function startTestServer(opts = {}) {
  const instance = createApp({
    dbPath: ':memory:',
    demoMockAuth: opts.demoMockAuth !== undefined ? opts.demoMockAuth : true,
    genesisSetupKey: opts.genesisSetupKey || 'L512-TEST-GENESIS-KEY-1234567890',
    trustProxy: opts.trustProxy !== undefined ? opts.trustProxy : true,
    disableRateLimit: true,
    ...opts,
  });
  return new Promise((resolve) => {
    const server = http.createServer(instance.app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        instance,
        close: () =>
          new Promise((res) => {
            server.close(() => {
              instance.close();
              res();
            });
          }),
      });
    });
  });
}

async function reqJson(baseUrl, path, { method = 'GET', body, headers = {}, cookie = '' } = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.get('set-cookie') || '';
  const data = await res.json().catch(() => null);
  return { status: res.status, data, setCookie, headers: res.headers };
}

test('1. All 5 industry presets load cleanly with bilingual TH/EN metadata and CSV headers', () => {
  const presets = listPresets();
  assert.deepEqual(presets.map((p) => p.id), PRESET_ORDER);
  assert.equal(presets.length, 5);
  for (const p of presets) {
    assert.ok(p.icon);
    assert.ok(p.th.name && p.en.name);
    assert.equal(p.th.csvHeaders.length, 10);
    assert.equal(p.en.csvHeaders.length, 10);
  }
});

test('2. Dynamic QR guard: accepts fresh 7s QR and rejects expired (>10s), tampered, and wrong-site QRs', () => {
  const site = { id: 'site_a', kiosk_secret: 'super_secret_kiosk_key', qr_rotate_sec: 7, qr_max_age_sec: 10 };
  const t0 = 1760000000000;
  const minted = mintDynamicQrPayload({ site, nowMs: t0 });

  const okRes = verifyDynamicQrPayload({ site, qrToken: minted.qr_token, nowMs: t0 + 4000 });
  assert.equal(okRes.ok, true);

  const expired = verifyDynamicQrPayload({ site, qrToken: minted.qr_token, nowMs: t0 + 15000 });
  assert.equal(expired.ok, false);
  assert.equal(expired.code, 'QR_EXPIRED');

  const tampered = verifyDynamicQrPayload({ site, qrToken: `${minted.qr_token.slice(0, -4)}AAAA`, nowMs: t0 + 1000 });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.code, 'QR_INVALID_SIGNATURE');

  const wrongSite = verifyDynamicQrPayload({ site: { ...site, id: 'site_b' }, qrToken: minted.qr_token, nowMs: t0 + 1000 });
  assert.equal(wrongSite.ok, false);
  assert.equal(wrongSite.code, 'QR_SITE_MISMATCH');
});

test('3. Wi-Fi IP Allowlist: supports exact IP, CIDR blocks, fail-closed empty list, and blocks remote video-call IPs', () => {
  assert.equal(ipMatchesRule('192.168.1.45', '192.168.1.0/24'), true);
  assert.equal(ipMatchesRule('192.168.2.45', '192.168.1.0/24'), false);
  assert.equal(ipMatchesRule('::ffff:203.0.113.10', '203.0.113.10'), true);

  const disabled = checkWifiIpPolicy({ site: { require_wifi_ip: false, allowed_ips: '' }, clientIp: '1.2.3.4' });
  assert.equal(disabled.allowed, true);
  assert.equal(disabled.status, 'DISABLED');

  const misconfigured = checkWifiIpPolicy({ site: { require_wifi_ip: true, allowed_ips: '' }, clientIp: '1.2.3.4' });
  assert.equal(misconfigured.allowed, false);
  assert.equal(misconfigured.status, 'MISCONFIGURED');

  const allowed = checkWifiIpPolicy({ site: { require_wifi_ip: true, allowed_ips: '203.0.113.10, 10.20.0.0/16' }, clientIp: '10.20.99.5' });
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.status, 'PASSED');

  const blocked = checkWifiIpPolicy({ site: { require_wifi_ip: true, allowed_ips: '203.0.113.10, 10.20.0.0/16' }, clientIp: '198.51.100.77' });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.status, 'BLOCKED');
});

test('4. End-to-End: Genesis Mode lock, Wi-Fi IP enforcement, Nonce/Passkey security contracts, Invite & CSV export', async () => {
  const srv = await startTestServer({ genesisSetupKey: 'L512-ONE-TIME-SETUP-KEY-999999' });
  try {
    // 4A. Genesis rejects wrong setup key
    const badKey = await reqJson(srv.baseUrl, '/api/setup/enroll-token', {
      method: 'POST',
      body: { setup_key: 'WRONG-KEY' },
    });
    assert.equal(badKey.status, 403);

    // 4B. Genesis enroll + claim succeeds & permanently locks
    const enr = await reqJson(srv.baseUrl, '/api/setup/enroll-token', {
      method: 'POST',
      body: { setup_key: 'L512-ONE-TIME-SETUP-KEY-999999', display_name: 'Dr. Somchai', admin_id: 'admin_main' },
    });
    assert.equal(enr.status, 201);
    assert.ok(enr.data.enrollment_token);

    const adminMockTok = srv.instance.login512.issueMockToken({ sub: 'admin_main', act: 'enroll', mod: 'FACE' });
    const claim = await reqJson(srv.baseUrl, '/api/setup/claim', {
      method: 'POST',
      body: {
        setup_key: 'L512-ONE-TIME-SETUP-KEY-999999',
        token: adminMockTok,
        auth_method: 'face',
        preset_id: 'workplace',
        org_name: 'Acme Thailand',
        site_name: 'HQ Gate 1',
        display_name: 'Dr. Somchai',
      },
    });
    assert.equal(claim.status, 200);
    assert.equal(claim.data.genesis_locked, true);
    const adminCookie = claim.setCookie.split(';')[0];
    const csrf = claim.data.csrf_token;
    assert.ok(adminCookie.startsWith('l512_checkin_sid='));
    assert.ok(csrf);

    // Second Genesis attempt must be rejected with 409 GENESIS_LOCKED
    const claimAgain = await reqJson(srv.baseUrl, '/api/setup/claim', {
      method: 'POST',
      body: { setup_key: 'L512-ONE-TIME-SETUP-KEY-999999', token: adminMockTok },
    });
    assert.equal(claimAgain.status, 409);
    assert.equal(claimAgain.data.error.code, 'GENESIS_LOCKED');

    // 4C. Admin CSRF protection enforced on site update
    const noCsrf = await reqJson(srv.baseUrl, '/api/admin/sites/site_main', {
      method: 'PATCH',
      cookie: adminCookie,
      body: { require_wifi_ip: true, allowed_ips: '203.0.113.50' },
    });
    assert.equal(noCsrf.status, 403);
    assert.equal(noCsrf.data.error.code, 'CSRF_INVALID');

    // Enable Layer 2 Wi-Fi IP Allowlist (only 203.0.113.50 allowed)
    const updSite = await reqJson(srv.baseUrl, '/api/admin/sites/site_main', {
      method: 'PATCH',
      cookie: adminCookie,
      headers: { 'x-csrf-token': csrf },
      body: { qr_rotate_sec: 6, require_wifi_ip: true, allowed_ips: '203.0.113.50' },
    });
    assert.equal(updSite.status, 200);
    assert.equal(updSite.data.site.require_wifi_ip, true);
    assert.equal(updSite.data.site.qr_rotate_sec, 6);

    // 4D. Admin creates one-time invite & member enrolls
    const invCreate = await reqJson(srv.baseUrl, '/api/admin/invites', {
      method: 'POST',
      cookie: adminCookie,
      headers: { 'x-csrf-token': csrf },
      body: { display_name: '=EvilFormulaName', member_code: 'EMP-007', group_name: 'Engineering', external_user_id: 'emp_007' },
    });
    assert.equal(invCreate.status, 201);
    const invCode = invCreate.data.invite.code;

    const invTok = srv.instance.login512.issueMockToken({ sub: 'emp_007', act: 'enroll', mod: 'FACE' });
    const invDone = await reqJson(srv.baseUrl, `/api/invites/${invCode}/complete`, {
      method: 'POST',
      body: { token: invTok, auth_method: 'face' },
    });
    assert.equal(invDone.status, 201);

    // Reusing the one-time invite fails with 410
    const invReuse = await reqJson(srv.baseUrl, `/api/invites/${invCode}`);
    assert.equal(invReuse.status, 410);

    // 4E. Kiosk mints live QR -> Remote IP (simulating video-call relay!) is HARD-BLOCKED
    const qrRes = await reqJson(srv.baseUrl, '/api/kiosk/site_main/qr');
    assert.equal(qrRes.status, 200);
    assert.ok(qrRes.data.qr_svg.includes('<svg'));

    const remoteBlocked = await reqJson(srv.baseUrl, '/api/checkin/start', {
      method: 'POST',
      headers: { 'x-forwarded-for': '198.51.100.99' },
      body: { site_id: 'site_main', qr_token: qrRes.data.qr_token },
    });
    assert.equal(remoteBlocked.status, 403);
    assert.equal(remoteBlocked.data.error.code, 'WIFI_IP_BLOCKED');

    // 4F. Authorized Office Wi-Fi IP passes -> Rejects method confusion (Face token claiming Passkey!)
    const start1 = await reqJson(srv.baseUrl, '/api/checkin/start', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { site_id: 'site_main', qr_token: qrRes.data.qr_token },
    });
    assert.equal(start1.status, 201);
    assert.equal(start1.data.ip_check_status, 'PASSED');

    const faceWithoutNonce = srv.instance.login512.issueMockToken({ sub: 'emp_007', act: 'login', mod: 'FACE', nonce: null });
    const methodBypassAttempt = await reqJson(srv.baseUrl, '/api/checkin/complete', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { ticket_id: start1.data.ticket_id, token: faceWithoutNonce, auth_method: 'passkey' },
    });
    assert.equal(methodBypassAttempt.status, 401);
    assert.equal(methodBypassAttempt.data.error.code, 'METHOD_MISMATCH');

    // Reusing consumed ticket_id must fail with 409 TICKET_ALREADY_USED
    const replayTicket = await reqJson(srv.baseUrl, '/api/checkin/complete', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { ticket_id: start1.data.ticket_id, token: faceWithoutNonce, auth_method: 'face' },
    });
    assert.equal(replayTicket.status, 409);
    assert.equal(replayTicket.data.error.code, 'TICKET_ALREADY_USED');

    // 4G. Step-up token MUST be rejected
    const start2 = await reqJson(srv.baseUrl, '/api/checkin/start', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { site_id: 'site_main', qr_token: qrRes.data.qr_token },
    });
    const stepUpTok = srv.instance.login512.issueMockToken({
      sub: 'emp_007',
      act: 'login',
      mod: 'FACE',
      nonce: start2.data.expected_nonce,
      stepUp: true,
    });
    const stepUpRes = await reqJson(srv.baseUrl, '/api/checkin/complete', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { ticket_id: start2.data.ticket_id, token: stepUpTok, auth_method: 'face' },
    });
    assert.equal(stepUpRes.status, 401);
    assert.equal(stepUpRes.data.error.code, 'STEP_UP_REQUIRED');

    // 4H. Valid Face check-in (with expected_nonce) succeeds!
    const start3 = await reqJson(srv.baseUrl, '/api/checkin/start', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { site_id: 'site_main', qr_token: qrRes.data.qr_token },
    });
    const validFaceTok = srv.instance.login512.issueMockToken({
      sub: 'emp_007',
      act: 'login',
      mod: 'FACE',
      nonce: start3.data.expected_nonce,
    });
    const okFace = await reqJson(srv.baseUrl, '/api/checkin/complete', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { ticket_id: start3.data.ticket_id, token: validFaceTok, auth_method: 'face', action: 'check_in', note: 'Morning shift' },
    });
    assert.equal(okFace.status, 201);
    assert.equal(okFace.data.checkin.nonce_checked, 1);
    assert.equal(okFace.data.checkin.ip_check_status, 'PASSED');

    // 4I. Valid Passkey fallback check-out succeeds!
    const start4 = await reqJson(srv.baseUrl, '/api/checkin/start', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { site_id: 'site_main', qr_token: qrRes.data.qr_token },
    });
    const validPasskeyTok = srv.instance.login512.issueMockToken({ sub: 'emp_007', act: 'login', mod: 'PASSKEY', nonce: null });
    const okPasskey = await reqJson(srv.baseUrl, '/api/checkin/complete', {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.50' },
      body: { ticket_id: start4.data.ticket_id, token: validPasskeyTok, auth_method: 'passkey', action: 'check_out' },
    });
    assert.equal(okPasskey.status, 201);
    assert.equal(okPasskey.data.checkin.auth_method, 'PASSKEY');
    assert.equal(okPasskey.data.checkin.action, 'check_out');

    // 4J. CSV Export has UTF-8 BOM, Thai workplace headers, and neutralizes Excel formula injection
    const csvRes = await fetch(`${srv.baseUrl}/api/admin/export.csv?lang=th`, { headers: { Cookie: adminCookie } });
    assert.equal(csvRes.status, 200);
    const csvBuf = Buffer.from(await csvRes.arrayBuffer());
    assert.deepEqual([...csvBuf.subarray(0, 3)], [0xef, 0xbb, 0xbf], 'Raw response must start with UTF-8 BOM bytes');
    const csvText = csvBuf.subarray(3).toString('utf8');
    assert.ok(csvText.includes('รหัสพนักงาน'));
    assert.ok(csvText.includes("'=EvilFormulaName"), 'Formula injection must be prefixed with apostrophe');
  } finally {
    await srv.close();
  }
});

test('5. Production safety: /api/demo/mock-token returns 404 when DEMO_MOCK_AUTH is false', async () => {
  const srv = await startTestServer({ demoMockAuth: false });
  try {
    const res = await reqJson(srv.baseUrl, '/api/demo/mock-token', {
      method: 'POST',
      body: { sub: 'attacker', act: 'login', mod: 'FACE' },
    });
    assert.equal(res.status, 404);
  } finally {
    await srv.close();
  }
});

test('6. Mock mode guard: refuses production/non-localhost, and mock tokens do not work across server instances', async () => {
  const base = { dbPath: ':memory:', demoMockAuth: true, genesisSetupKey: 'L512-TEST-GENESIS-KEY-1234567890', disableRateLimit: true };

  assert.throws(() => createApp({ ...base, nodeEnv: 'production' }), /NODE_ENV=production/);
  assert.throws(() => createApp({ ...base, nodeEnv: '', publicBaseUrl: 'https://checkin.example.com' }), /only allowed on localhost/);
  assert.throws(() => createApp({ ...base, nodeEnv: '', publicBaseUrl: 'http://192.168.1.20:3512' }), /only allowed on localhost/);

  const a = createApp({ ...base, nodeEnv: '', publicBaseUrl: 'http://localhost:3512' });
  const b = createApp({ ...base, nodeEnv: '', publicBaseUrl: 'http://127.0.0.1:3512' });
  try {
    const token = a.login512.issueMockToken({ sub: 'usr_demo_01', act: 'login', mod: 'PASSKEY' });
    const onOther = await b.login512.verifyAuthToken({ token, authMethod: 'passkey' });
    assert.equal(onOther.valid, false, 'A mock token from one server must not verify on another');
    assert.equal(onOther.errorCode, 'TOKEN_BAD_SIGNATURE');
    const onSame = await a.login512.verifyAuthToken({ token, authMethod: 'passkey' });
    assert.equal(onSame.valid, true);
  } finally {
    a.close();
    b.close();
  }

  // Real-key mode is unaffected by the guard
  const prod = createApp({ ...base, demoMockAuth: false, nodeEnv: 'production', publicBaseUrl: 'https://checkin.example.com' });
  prod.close();
});

test('7. Genesis on a second install: an already-enrolled Superadmin proves itself with a login (nonce-bound)', async () => {
  const KEY = 'L512-SECOND-INSTALL-KEY-0123456789';
  const srv = await startTestServer({ genesisSetupKey: KEY });
  try {
    // The same Login512 account already has this Superadmin (e.g. the first install on another computer).
    srv.instance.login512._mockEnrolledUsers.add('superadmin');

    const enr = await reqJson(srv.baseUrl, '/api/setup/enroll-token', {
      method: 'POST',
      body: { setup_key: KEY, display_name: 'Owner', admin_id: 'superadmin' },
    });
    assert.equal(enr.status, 200, JSON.stringify(enr.data));
    assert.equal(enr.data.mode, 'login');
    assert.ok(enr.data.nonce);
    assert.equal(enr.data.enrollment_token, undefined);

    const claimBody = (token, extra = {}) => ({
      setup_key: KEY, token, auth_method: 'face', mode: 'login', nonce: enr.data.nonce, admin_id: 'superadmin',
      preset_id: 'classroom', org_name: 'Second Install', display_name: 'Owner', ...extra,
    });

    // Someone else's login (right nonce) is refused...
    const other = srv.instance.login512.issueMockToken({ sub: 'someone_else', act: 'login', mod: 'FACE', nonce: enr.data.nonce });
    const bad = await reqJson(srv.baseUrl, '/api/setup/claim', { method: 'POST', body: claimBody(other) });
    assert.equal(bad.status, 403);
    assert.equal(bad.data.error.code, 'NOT_SUPERADMIN');

    // ...and the nonce was single-use, so a fresh one is needed.
    const enr2 = await reqJson(srv.baseUrl, '/api/setup/enroll-token', {
      method: 'POST',
      body: { setup_key: KEY, display_name: 'Owner', admin_id: 'superadmin' },
    });
    const reused = srv.instance.login512.issueMockToken({ sub: 'superadmin', act: 'login', mod: 'FACE', nonce: enr.data.nonce });
    const reuse = await reqJson(srv.baseUrl, '/api/setup/claim', { method: 'POST', body: claimBody(reused) });
    assert.equal(reuse.status, 400);
    assert.equal(reuse.data.error.code, 'INVALID_NONCE');

    // The real Superadmin with the fresh nonce sets the install up and locks it.
    const mine = srv.instance.login512.issueMockToken({ sub: 'superadmin', act: 'login', mod: 'FACE', nonce: enr2.data.nonce });
    const ok = await reqJson(srv.baseUrl, '/api/setup/claim', { method: 'POST', body: claimBody(mine, { nonce: enr2.data.nonce }) });
    assert.equal(ok.status, 200, JSON.stringify(ok.data));
    assert.equal(ok.data.genesis_locked, true);
    assert.equal(ok.data.admin.external_user_id, 'superadmin');
  } finally {
    await srv.close();
  }
});

test('8. A new industry is one JSON file: presets/<id>.json is picked up after the built-ins and checked', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { loadPresetsFrom, PRESETS_DIR, validatePreset } = require('../src/presets');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-presets-'));
  try {
    for (const id of PRESET_ORDER) fs.copyFileSync(path.join(PRESETS_DIR, `${id}.json`), path.join(dir, `${id}.json`));
    // What docs/ADD_A_PRESET.md tells a person or an AI agent to do: copy a preset, change id and texts.
    const gym = JSON.parse(fs.readFileSync(path.join(PRESETS_DIR, 'event.json'), 'utf8'));
    gym.id = 'gym-class';
    gym.icon = '🏋️';
    gym.th.name = 'คลาสฟิตเนส';
    gym.en.name = 'Fitness Class';
    fs.writeFileSync(path.join(dir, 'gym-class.json'), JSON.stringify(gym, null, 2));
    // A broken file is reported, not loaded, and does not take the others down.
    fs.writeFileSync(path.join(dir, 'broken.json'), JSON.stringify({ id: 'broken', icon: 'x', defaultQrRotateSec: 30 }));
    fs.writeFileSync(path.join(dir, 'not-json.json'), '{ nope');

    const { presets, report } = loadPresetsFrom(dir);
    assert.deepEqual([...presets.keys()], [...PRESET_ORDER, 'gym-class']);
    assert.equal(presets.get('gym-class').en.name, 'Fitness Class');
    const ids = report.map((r) => r.id).sort();
    assert.deepEqual(ids, ['broken', 'not-json']);
    const broken = report.find((r) => r.id === 'broken').problems.join(' | ');
    assert.match(broken, /defaultQrRotateSec must be a whole number from 5 to 8/);
    assert.match(broken, /"th" texts are missing/);

    // id must match the file name
    assert.ok(validatePreset({ ...gym, id: 'other' }, 'gym-class').some((m) => m.includes('must equal the file name')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
