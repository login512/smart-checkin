'use strict';

require('dotenv').config();

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const QRCode = require('qrcode');

const { initDatabase } = require('./db');
const { listPresets, getPreset, isValidPreset } = require('./presets');
const { Login512Client } = require('./login512/client');
const {
  mintDynamicQrPayload,
  verifyDynamicQrPayload,
  extractClientIp,
  checkWifiIpPolicy,
  maskIpForAudit,
} = require('./login512/qr-guard');
const { ensureGenesisState, isGenesisLocked, verifySetupKey, lockGenesis } = require('./login512/genesis');

const SESSION_COOKIE = 'l512_checkin_sid';

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    try {
      out[key] = decodeURIComponent(val);
    } catch {
      out[key] = val;
    }
  }
  return out;
}

function setSessionCookie(req, res, sessionId, maxAgeSec = 12 * 3600) {
  const isHttps = req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  const attrs = [
    `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
  ];
  if (isHttps) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function clearSessionCookie(req, res) {
  const isHttps = req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  const attrs = [`${SESSION_COOKIE}=`, 'HttpOnly', 'Path=/', 'SameSite=Lax', 'Max-Age=0'];
  if (isHttps) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function createRateLimiter({ windowMs = 60000, max = 60, trustProxy = false }) {
  const buckets = new Map();
  return function rateLimitMiddleware(req, res, next) {
    const ip = extractClientIp(req, trustProxy) || 'unknown';
    const now = Date.now();
    let entry = buckets.get(ip);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      buckets.set(ip, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      return res.status(429).json({
        error: { code: 'RATE_LIMITED', message: 'Too many requests. Please slow down and try again.' },
      });
    }
    // Lightweight periodic prune
    if (buckets.size > 2000) {
      for (const [k, v] of buckets.entries()) {
        if (now > v.resetAt) buckets.delete(k);
      }
    }
    return next();
  };
}

function csvEscapeCell(val) {
  let s = String(val == null ? '' : val);
  // Mitigate Excel CSV formula injection
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function safeSitePublic(site) {
  return {
    id: site.id,
    name: site.name,
    qr_rotate_sec: site.qr_rotate_sec,
    qr_max_age_sec: site.qr_max_age_sec,
    require_wifi_ip: Boolean(site.require_wifi_ip),
    allowed_ips: site.allowed_ips || '',
    created_at: site.created_at,
  };
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function isLoopbackHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  return LOOPBACK_HOSTS.has(h) || h.endsWith('.localhost');
}

function isLoopbackAddress(addr) {
  const a = String(addr || '');
  return a === '::1' || a.startsWith('127.') || a.startsWith('::ffff:127.');
}

/**
 * Refuses to start when DEMO_MOCK_AUTH=true could be reachable by other people:
 * NODE_ENV=production, or a PUBLIC_BASE_URL that is not localhost.
 */
function assertDemoMockAllowed({ publicBaseUrl, nodeEnv }) {
  if (String(nodeEnv || '').toLowerCase() === 'production') {
    throw new Error('DEMO_MOCK_AUTH=true is not allowed when NODE_ENV=production. Set DEMO_MOCK_AUTH=false and use real Login512 keys.');
  }
  if (publicBaseUrl) {
    let hostname = '';
    try {
      hostname = new URL(publicBaseUrl).hostname;
    } catch {
      throw new Error(`DEMO_MOCK_AUTH=true needs a localhost PUBLIC_BASE_URL, got an invalid URL: ${publicBaseUrl}`);
    }
    if (!isLoopbackHost(hostname)) {
      throw new Error(`DEMO_MOCK_AUTH=true is only allowed on localhost, but PUBLIC_BASE_URL is ${publicBaseUrl}. Set DEMO_MOCK_AUTH=false and use real Login512 keys.`);
    }
  }
}

function createApp(options = {}) {
  const dataDir = options.dataDir || process.env.DATA_DIR || path.join(__dirname, '..', 'data');
  const dbPath = options.dbPath || path.join(dataDir, 'smart-checkin.db');
  const defaultPreset = options.defaultPreset || process.env.DEFAULT_PRESET || 'classroom';
  const defaultLang = options.defaultLang || process.env.DEFAULT_LANG || 'th';
  const trustProxy = options.trustProxy !== undefined
    ? Boolean(options.trustProxy)
    : String(process.env.TRUST_PROXY || '0') === '1';

  const repo = initDatabase({
    dbPath,
    defaultPreset,
    defaultLang,
    defaultQrRotateSec: Number(options.qrRotateSec || process.env.QR_ROTATE_SECONDS || 7),
    defaultQrMaxAgeSec: Number(options.qrMaxAgeSec || process.env.QR_MAX_AGE_SECONDS || 10),
  });

  const genesisState = ensureGenesisState(repo, options.genesisSetupKey ?? process.env.GENESIS_SETUP_KEY ?? '');

  const login512 = options.login512Client || new Login512Client({
    endpoint: options.login512Endpoint,
    sdkUrl: options.login512SdkUrl,
    publishableKey: options.login512PublishableKey,
    secretKey: options.login512SecretKey,
    demoMockAuth: options.demoMockAuth,
  });

  const publicBaseUrlOverride = (options.publicBaseUrl || process.env.PUBLIC_BASE_URL || '').replace(/\/+$/, '');
  const disableRateLimit = Boolean(options.disableRateLimit);

  // Mock mode lets anyone mint tokens, so it may only ever run on a developer's own machine.
  if (login512.demoMockAuth) {
    assertDemoMockAllowed({
      publicBaseUrl: publicBaseUrlOverride,
      nodeEnv: options.nodeEnv !== undefined ? options.nodeEnv : process.env.NODE_ENV,
    });
  }

  // Per-site SSE subscribers for instant Kiosk live feed updates
  const sseClients = new Map(); // siteId -> Set<res>
  function broadcastCheckin(siteId, checkinRow) {
    const subs = sseClients.get(siteId);
    if (!subs || subs.size === 0) return;
    const payload = JSON.stringify({
      id: checkinRow.id,
      site_id: checkinRow.site_id,
      site_name: checkinRow.site_name,
      external_user_id: checkinRow.external_user_id,
      display_name: checkinRow.display_name,
      member_code: checkinRow.member_code,
      group_name: checkinRow.group_name,
      action: checkinRow.action,
      auth_method: checkinRow.auth_method,
      ip_check_status: checkinRow.ip_check_status,
      qr_age_ms: checkinRow.qr_age_ms,
      note: checkinRow.note,
      token_alg: checkinRow.token_alg,
      token_jti: checkinRow.token_jti,
      created_at: checkinRow.created_at,
      today_count: repo.countTodayCheckins(siteId),
    });
    for (const res of subs) {
      try {
        res.write(`event: checkin\ndata: ${payload}\n\n`);
      } catch {
        subs.delete(res);
      }
    }
  }

  function resolveBaseUrl(req) {
    if (publicBaseUrlOverride && !publicBaseUrlOverride.includes('localhost:3512')) {
      return publicBaseUrlOverride;
    }
    const proto = trustProxy && req.headers['x-forwarded-proto']
      ? String(req.headers['x-forwarded-proto']).split(',')[0].trim()
      : req.protocol || 'http';
    const host = req.headers.host || 'localhost:3512';
    return `${proto}://${host}`;
  }

  const app = express();
  app.disable('x-powered-by');
  if (trustProxy) app.set('trust proxy', 1);

  app.use(express.json({ limit: '256kb' }));

  // Baseline security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  const authRateLimit = disableRateLimit
    ? (_req, _res, next) => next()
    : createRateLimiter({ windowMs: 60000, max: 30, trustProxy });
  const checkinRateLimit = disableRateLimit
    ? (_req, _res, next) => next()
    : createRateLimiter({ windowMs: 60000, max: 120, trustProxy });

  function getAdminSession(req) {
    const cookies = parseCookies(req);
    const sess = repo.getSessionWithMember(cookies[SESSION_COOKIE]);
    if (!sess || sess.role !== 'ADMIN') return null;
    return sess;
  }

  function requireAdmin(req, res, next) {
    const sess = getAdminSession(req);
    if (!sess) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Admin authentication required' } });
    }
    req.adminSession = sess;
    return next();
  }

  function requireCsrf(req, res, next) {
    const provided = String(req.headers['x-csrf-token'] || '');
    const expected = String(req.adminSession?.csrf_token || '');
    if (!provided || !expected) {
      return res.status(403).json({ error: { code: 'CSRF_INVALID', message: 'Missing CSRF token' } });
    }
    const a = Buffer.from(provided);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).json({ error: { code: 'CSRF_INVALID', message: 'Invalid CSRF token' } });
    }
    return next();
  }

  // Static UI assets
  const publicDir = path.join(__dirname, '..', 'public');
  app.use('/assets', express.static(path.join(publicDir, 'assets')));

  // Page routes (4 clean screens)
  app.get('/', (_req, res) => {
    if (!isGenesisLocked(repo)) {
      return res.redirect('/setup');
    }
    return res.redirect('/kiosk');
  });
  app.get('/setup', (_req, res) => res.sendFile(path.join(publicDir, 'setup.html')));
  app.get('/kiosk', (_req, res) => res.sendFile(path.join(publicDir, 'kiosk.html')));
  app.get('/scan', (_req, res) => res.sendFile(path.join(publicDir, 'scan.html')));
  app.get('/admin', (_req, res) => res.sendFile(path.join(publicDir, 'admin.html')));

  // Health check
  app.get('/healthz', (_req, res) => {
    const cfg = repo.getAppConfig();
    res.json({
      status: 'ok',
      preset: cfg.preset_id,
      genesis_locked: cfg.genesis_locked,
      login512_configured: login512.isConfigured(),
    });
  });

  // Public runtime config (NEVER exposes secret key or kiosk secrets)
  app.get('/api/config', (_req, res) => {
    const cfg = repo.getAppConfig();
    const preset = getPreset(cfg.preset_id);
    const sites = repo.listSites().map((s) => ({
      id: s.id,
      name: s.name,
      qr_rotate_sec: s.qr_rotate_sec,
      qr_max_age_sec: s.qr_max_age_sec,
      require_wifi_ip: s.require_wifi_ip,
    }));
    res.json({
      ...cfg,
      preset,
      presets: listPresets(),
      sites,
      login512: login512.publicConfig(),
    });
  });

  // ============================================================================
  // 1. First-Time Genesis Mode (/api/setup/*) — Zero default admin/1234
  // ============================================================================
  app.get('/api/setup/status', (_req, res) => {
    const cfg = repo.getAppConfig();
    res.json({
      locked: isGenesisLocked(repo),
      preset_id: cfg.preset_id,
      default_lang: cfg.default_lang,
      org_name: cfg.org_name,
      presets: listPresets(),
      login512: login512.publicConfig(),
    });
  });

  app.post('/api/setup/enroll-token', authRateLimit, async (req, res) => {
    if (isGenesisLocked(repo)) {
      return res.status(409).json({ error: { code: 'GENESIS_LOCKED', message: 'Initial setup is already completed and permanently locked.' } });
    }
    const { setup_key, display_name, admin_id } = req.body || {};
    if (!verifySetupKey(repo, setup_key)) {
      return res.status(403).json({ error: { code: 'INVALID_SETUP_KEY', message: 'Invalid One-Time Genesis Setup Key.' } });
    }
    const cleanName = String(display_name || 'Superadmin').trim().slice(0, 80) || 'Superadmin';
    const externalUserId = String(admin_id || 'superadmin')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:@-]/g, '')
      .slice(0, 64) || 'superadmin';

    try {
      const enr = await login512.createEnrollmentToken({
        externalUserId,
        displayName: cleanName,
        ttlSeconds: 300,
      });
      return res.status(201).json({
        enrollment_token: enr.enrollment_token,
        expires_at: enr.expires_at,
        external_user_id: externalUserId,
      });
    } catch (err) {
      return res.status(502).json({ error: { code: 'ENROLL_TOKEN_FAILED', message: err.message } });
    }
  });

  app.post('/api/setup/claim', authRateLimit, async (req, res) => {
    if (isGenesisLocked(repo)) {
      return res.status(409).json({ error: { code: 'GENESIS_LOCKED', message: 'Genesis mode is already permanently locked.' } });
    }

    const { setup_key, token, auth_method, preset_id, org_name, default_lang, display_name, site_name } = req.body || {};
    if (!verifySetupKey(repo, setup_key)) {
      return res.status(403).json({ error: { code: 'INVALID_SETUP_KEY', message: 'Invalid One-Time Genesis Setup Key.' } });
    }

    const verified = await login512.verifyAuthToken({
      token,
      authMethod: auth_method === 'passkey' ? 'passkey' : 'face',
      expectedActs: ['enroll', 'enroll_passkey'],
    });

    repo.recordVerifyAudit({
      context: 'genesis_claim',
      authMethod: auth_method || 'face',
      valid: verified.valid,
      errorCode: verified.errorCode,
      externalUserId: verified.subject,
      tokenJti: verified.tokenMeta?.jti,
      tokenKid: verified.tokenMeta?.kid,
      tokenAlg: verified.tokenMeta?.alg,
      tokenAct: verified.tokenMeta?.act,
      nonceChecked: verified.nonceChecked,
      ipCheckStatus: 'GENESIS',
    });

    if (!verified.valid) {
      return res.status(401).json({ error: { code: verified.errorCode, message: verified.errorMessage } });
    }

    const chosenPresetId = isValidPreset(preset_id) ? preset_id : repo.getSetting('preset_id', 'classroom');
    const chosenPreset = getPreset(chosenPresetId);
    const chosenLang = default_lang === 'en' ? 'en' : 'th';
    const finalOrgName = String(org_name || '').trim().slice(0, 120) || chosenPreset[chosenLang].defaultOrgName;

    repo.setSetting('preset_id', chosenPreset.id);
    repo.setSetting('default_lang', chosenLang);
    repo.setSetting('org_name', finalOrgName);

    const defaultSite = repo.getDefaultSite();
    if (defaultSite) {
      repo.updateSite(defaultSite.id, {
        name: String(site_name || '').trim().slice(0, 120) || chosenPreset[chosenLang].defaultSiteName,
        qrRotateSec: chosenPreset.defaultQrRotateSec || 7,
      });
    }

    const adminMember = repo.upsertMember({
      externalUserId: verified.subject,
      displayName: String(display_name || 'Superadmin').trim().slice(0, 80) || 'Superadmin',
      memberCode: 'ADMIN-01',
      groupName: 'Superadmin',
      role: 'ADMIN',
      method: verified.authMethod,
    });

    lockGenesis(repo);

    // Issue fresh admin session (prevents session fixation)
    const session = repo.createSession(adminMember.id);
    setSessionCookie(req, res, session.id);

    return res.json({
      ok: true,
      genesis_locked: true,
      admin: adminMember,
      csrf_token: session.csrf_token,
      token_meta: verified.tokenMeta,
    });
  });

  // ============================================================================
  // 2. Admin Authentication (/api/auth/*)
  // ============================================================================
  app.post('/api/auth/nonce', authRateLimit, (_req, res) => {
    const nonce = login512.generateNonce();
    repo.createAuthNonce(nonce, 'admin_login', 120000);
    res.json({ nonce, expires_in_sec: 120 });
  });

  app.post('/api/auth/login', authRateLimit, async (req, res) => {
    const { token, auth_method, nonce } = req.body || {};
    const method = auth_method === 'passkey' ? 'passkey' : 'face';

    if (method === 'face') {
      if (!nonce || !repo.consumeAuthNonce(String(nonce), 'admin_login')) {
        return res.status(400).json({ error: { code: 'INVALID_NONCE', message: 'Login challenge nonce is missing, expired, or already used.' } });
      }
    }

    const verified = await login512.verifyAuthToken({
      token,
      authMethod: method,
      expectedNonce: method === 'face' ? String(nonce) : null,
      expectedActs: ['login'],
    });

    repo.recordVerifyAudit({
      context: 'admin_login',
      authMethod: method,
      valid: verified.valid,
      errorCode: verified.errorCode,
      externalUserId: verified.subject,
      tokenJti: verified.tokenMeta?.jti,
      tokenKid: verified.tokenMeta?.kid,
      tokenAlg: verified.tokenMeta?.alg,
      tokenAct: verified.tokenMeta?.act,
      nonceChecked: verified.nonceChecked,
      ipCheckStatus: 'ADMIN',
    });

    if (!verified.valid) {
      return res.status(401).json({ error: { code: verified.errorCode, message: verified.errorMessage } });
    }

    const member = repo.getMemberByExternalId(verified.subject);
    if (!member || member.role !== 'ADMIN' || member.status !== 'ACTIVE') {
      return res.status(403).json({ error: { code: 'NOT_ADMIN', message: 'Verified identity does not have Admin privileges.' } });
    }

    // Rotate session ID cleanly on login
    const oldCookies = parseCookies(req);
    if (oldCookies[SESSION_COOKIE]) repo.deleteSession(oldCookies[SESSION_COOKIE]);

    const session = repo.createSession(member.id);
    setSessionCookie(req, res, session.id);

    return res.json({
      ok: true,
      user: member,
      csrf_token: session.csrf_token,
      token_meta: verified.tokenMeta,
    });
  });

  app.get('/api/auth/me', (req, res) => {
    const sess = getAdminSession(req);
    if (!sess) {
      return res.status(401).json({ authenticated: false, genesis_locked: isGenesisLocked(repo) });
    }
    return res.json({
      authenticated: true,
      csrf_token: sess.csrf_token,
      detected_ip: extractClientIp(req, trustProxy),
      user: {
        id: sess.member_id,
        external_user_id: sess.external_user_id,
        display_name: sess.display_name,
        member_code: sess.member_code,
        group_name: sess.group_name,
        role: sess.role,
      },
    });
  });

  app.post('/api/auth/logout', (req, res) => {
    const cookies = parseCookies(req);
    if (cookies[SESSION_COOKIE]) {
      repo.deleteSession(cookies[SESSION_COOKIE]);
    }
    clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // ============================================================================
  // 3. Kiosk Dynamic QR (5-8s) + Real-Time SSE Stream (/api/kiosk/*)
  // ============================================================================
  app.get('/api/kiosk/:siteId/qr', async (req, res) => {
    const site = req.params.siteId === 'default' ? repo.getDefaultSite() : repo.getSite(req.params.siteId);
    if (!site) {
      return res.status(404).json({ error: { code: 'SITE_NOT_FOUND', message: 'Check-in station not found' } });
    }
    const qrPayload = mintDynamicQrPayload({ site });
    const baseUrl = resolveBaseUrl(req);
    const scanUrl = `${baseUrl}/scan?site=${encodeURIComponent(site.id)}&qr=${encodeURIComponent(qrPayload.qr_token)}`;
    const qrSvg = await QRCode.toString(scanUrl, {
      type: 'svg',
      margin: 1,
      errorCorrectionLevel: 'M',
      color: { dark: '#0B1120', light: '#FFFFFF' },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      site: {
        id: site.id,
        name: site.name,
        qr_rotate_sec: site.qr_rotate_sec,
        qr_max_age_sec: site.qr_max_age_sec,
        require_wifi_ip: site.require_wifi_ip,
      },
      ...qrPayload,
      scan_url: scanUrl,
      qr_svg: qrSvg,
      today_count: repo.countTodayCheckins(site.id),
      recent_checkins: repo.listCheckins({ siteId: site.id, limit: 15 }),
    });
  });

  app.get('/api/kiosk/:siteId/stream', (req, res) => {
    const site = req.params.siteId === 'default' ? repo.getDefaultSite() : repo.getSite(req.params.siteId);
    if (!site) {
      return res.status(404).end();
    }
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    res.write(`event: ready\ndata: ${JSON.stringify({ site_id: site.id, today_count: repo.countTodayCheckins(site.id) })}\n\n`);

    if (!sseClients.has(site.id)) sseClients.set(site.id, new Set());
    const set = sseClients.get(site.id);
    set.add(res);

    const heartbeat = setInterval(() => {
      try {
        res.write(': ping\n\n');
      } catch {
        clearInterval(heartbeat);
        set.delete(res);
      }
    }, 20000);

    req.on('close', () => {
      clearInterval(heartbeat);
      set.delete(res);
    });
  });

  // ============================================================================
  // 4. Mobile Proof-of-Presence Check-In (/api/checkin/*)
  // ============================================================================
  app.post('/api/checkin/start', checkinRateLimit, (req, res) => {
    const { site_id, qr_token } = req.body || {};
    const site = site_id ? repo.getSite(site_id) : repo.getDefaultSite();
    if (!site) {
      return res.status(404).json({ error: { code: 'SITE_NOT_FOUND', message: 'Check-in station not found.' } });
    }

    // Layer 1: Fast-rotating Dynamic QR HMAC & freshness check (5-10s window)
    const qrCheck = verifyDynamicQrPayload({ site, qrToken: qr_token });
    if (!qrCheck.ok) {
      repo.recordVerifyAudit({
        context: 'checkin_qr_gate',
        authMethod: 'qr',
        valid: false,
        errorCode: qrCheck.code,
        ipCheckStatus: 'SKIPPED',
        qrAgeMs: qrCheck.ageMs ?? null,
      });
      return res.status(400).json({ error: { code: qrCheck.code, message: qrCheck.message } });
    }

    // Layer 2: Optional Office/School Wi-Fi IP Allowlist (blocks video-call relay from remote IPs!)
    const clientIp = extractClientIp(req, trustProxy);
    const ipCheck = checkWifiIpPolicy({ site, clientIp });
    if (!ipCheck.allowed) {
      repo.recordVerifyAudit({
        context: 'checkin_ip_gate',
        authMethod: 'wifi_ip',
        valid: false,
        errorCode: `WIFI_IP_${ipCheck.status}`,
        ipCheckStatus: ipCheck.status,
        qrAgeMs: qrCheck.ageMs,
      });
      return res.status(403).json({
        error: {
          code: `WIFI_IP_${ipCheck.status}`,
          message: ipCheck.message,
          detected_ip_masked: maskIpForAudit(clientIp),
        },
      });
    }

    // Issue single-use check-in ticket bound to a fresh expected_nonce
    const expectedNonce = login512.generateNonce();
    const ticket = repo.createCheckinTicket({
      siteId: site.id,
      expectedNonce,
      qrSlot: qrCheck.slot,
      qrAgeMs: qrCheck.ageMs,
      clientIp,
      ipCheckStatus: ipCheck.status,
      ttlMs: 90000,
    });

    const cfg = repo.getAppConfig();
    const preset = getPreset(cfg.preset_id);

    return res.status(201).json({
      ok: true,
      ticket_id: ticket.id,
      expected_nonce: ticket.expected_nonce,
      site_id: site.id,
      site_name: site.name,
      qr_age_ms: qrCheck.ageMs,
      ip_check_status: ipCheck.status,
      supports_clock_out: Boolean(preset.supportsClockOut),
      expires_in_sec: 90,
    });
  });

  app.post('/api/checkin/complete', checkinRateLimit, async (req, res) => {
    const { ticket_id, token, auth_method, action, note } = req.body || {};
    const ticket = repo.getCheckinTicket(String(ticket_id || ''));
    if (!ticket) {
      return res.status(400).json({ error: { code: 'TICKET_NOT_FOUND', message: 'Invalid or expired check-in ticket. Please rescan QR.' } });
    }
    if (ticket.consumed_at !== null) {
      return res.status(409).json({ error: { code: 'TICKET_ALREADY_USED', message: 'This check-in ticket was already used. Please rescan live QR.' } });
    }
    if (Date.now() > ticket.expires_at) {
      return res.status(400).json({ error: { code: 'TICKET_EXPIRED', message: 'Check-in ticket expired. Please rescan live QR.' } });
    }

    const site = repo.getSite(ticket.site_id);
    if (!site) {
      return res.status(404).json({ error: { code: 'SITE_NOT_FOUND', message: 'Station not found.' } });
    }

    // Re-enforce Layer 2 Wi-Fi IP Allowlist on completion (prevents starting on Wi-Fi then switching networks)
    const clientIp = extractClientIp(req, trustProxy);
    const ipCheck = checkWifiIpPolicy({ site, clientIp });
    if (!ipCheck.allowed) {
      repo.recordVerifyAudit({
        context: 'checkin_complete_ip',
        authMethod: auth_method || 'face',
        valid: false,
        errorCode: `WIFI_IP_${ipCheck.status}`,
        ipCheckStatus: ipCheck.status,
        qrAgeMs: ticket.qr_age_ms,
      });
      return res.status(403).json({ error: { code: `WIFI_IP_${ipCheck.status}`, message: ipCheck.message } });
    }

    // Atomically consume single-use ticket BEFORE verification (prevents race/replay)
    if (!repo.consumeCheckinTicket(ticket.id)) {
      return res.status(409).json({ error: { code: 'TICKET_ALREADY_USED', message: 'Check-in ticket already used or expired.' } });
    }

    const method = auth_method === 'passkey' ? 'passkey' : 'face';
    const verified = await login512.verifyAuthToken({
      token,
      authMethod: method,
      expectedNonce: method === 'face' ? ticket.expected_nonce : null,
      expectedActs: ['login'],
    });

    repo.recordVerifyAudit({
      context: 'checkin_complete',
      authMethod: method,
      valid: verified.valid,
      errorCode: verified.errorCode,
      externalUserId: verified.subject,
      tokenJti: verified.tokenMeta?.jti,
      tokenKid: verified.tokenMeta?.kid,
      tokenAlg: verified.tokenMeta?.alg,
      tokenAct: verified.tokenMeta?.act,
      nonceChecked: verified.nonceChecked,
      ipCheckStatus: ipCheck.status,
      qrAgeMs: ticket.qr_age_ms,
    });

    if (!verified.valid) {
      return res.status(401).json({ error: { code: verified.errorCode, message: verified.errorMessage } });
    }

    const member = repo.getMemberByExternalId(verified.subject);
    const cleanAction = action === 'check_out' ? 'check_out' : 'check_in';

    const checkin = repo.recordCheckin({
      siteId: site.id,
      siteName: site.name,
      memberId: member ? member.id : null,
      externalUserId: verified.subject,
      displayName: member ? member.display_name : verified.subject,
      memberCode: member ? member.member_code : '',
      groupName: member ? member.group_name : '',
      action: cleanAction,
      authMethod: verified.authMethod,
      ipCheckStatus: ipCheck.status,
      clientIpMasked: maskIpForAudit(clientIp),
      qrAgeMs: ticket.qr_age_ms,
      note: String(note || '').trim(),
      tokenJti: verified.tokenMeta.jti,
      tokenKid: verified.tokenMeta.kid,
      tokenAlg: verified.tokenMeta.alg,
      tokenAct: verified.tokenMeta.act,
      nonceChecked: verified.nonceChecked,
    });

    broadcastCheckin(site.id, checkin);

    return res.status(201).json({
      ok: true,
      checkin,
      token_meta: verified.tokenMeta,
    });
  });

  // ============================================================================
  // 5. Invite-Based First-Time Member Enrollment (/api/invites/*)
  // ============================================================================
  app.get('/api/invites/:code', (req, res) => {
    const invite = repo.getInvite(String(req.params.code || '').trim());
    if (!invite) {
      return res.status(404).json({ error: { code: 'INVITE_NOT_FOUND', message: 'Invite link not found.' } });
    }
    if (invite.uses_count >= invite.max_uses) {
      return res.status(410).json({ error: { code: 'INVITE_USED', message: 'This invite link has already been used.' } });
    }
    if (Date.now() > invite.expires_at) {
      return res.status(410).json({ error: { code: 'INVITE_EXPIRED', message: 'This invite link has expired.' } });
    }
    return res.json({
      code: invite.code,
      external_user_id: invite.external_user_id,
      display_name: invite.display_name,
      member_code: invite.member_code,
      group_name: invite.group_name,
      role: invite.role,
      expires_at: invite.expires_at,
    });
  });

  app.post('/api/invites/:code/enroll-token', authRateLimit, async (req, res) => {
    const invite = repo.getInvite(String(req.params.code || '').trim());
    if (!invite || invite.uses_count >= invite.max_uses || Date.now() > invite.expires_at) {
      return res.status(410).json({ error: { code: 'INVITE_INVALID', message: 'Invite is invalid, used, or expired.' } });
    }
    const displayName = String(req.body?.display_name || invite.display_name || invite.external_user_id).trim().slice(0, 80);
    try {
      const enr = await login512.createEnrollmentToken({
        externalUserId: invite.external_user_id,
        displayName,
        ttlSeconds: 300,
      });
      return res.status(201).json({
        enrollment_token: enr.enrollment_token,
        expires_at: enr.expires_at,
        external_user_id: invite.external_user_id,
      });
    } catch (err) {
      return res.status(502).json({ error: { code: 'ENROLL_TOKEN_FAILED', message: err.message } });
    }
  });

  app.post('/api/invites/:code/complete', authRateLimit, async (req, res) => {
    const invite = repo.getInvite(String(req.params.code || '').trim());
    if (!invite || invite.uses_count >= invite.max_uses || Date.now() > invite.expires_at) {
      return res.status(410).json({ error: { code: 'INVITE_INVALID', message: 'Invite is invalid, used, or expired.' } });
    }

    const { token, auth_method, display_name, member_code, group_name } = req.body || {};
    const method = auth_method === 'passkey' ? 'passkey' : 'face';

    const verified = await login512.verifyAuthToken({
      token,
      authMethod: method,
      expectedActs: ['enroll', 'enroll_passkey'],
    });

    repo.recordVerifyAudit({
      context: 'invite_enroll',
      authMethod: method,
      valid: verified.valid,
      errorCode: verified.errorCode,
      externalUserId: verified.subject,
      tokenJti: verified.tokenMeta?.jti,
      tokenKid: verified.tokenMeta?.kid,
      tokenAlg: verified.tokenMeta?.alg,
      tokenAct: verified.tokenMeta?.act,
      nonceChecked: false,
      ipCheckStatus: 'ENROLL',
    });

    if (!verified.valid) {
      return res.status(401).json({ error: { code: verified.errorCode, message: verified.errorMessage } });
    }
    if (verified.subject !== invite.external_user_id) {
      return res.status(403).json({ error: { code: 'SUBJECT_MISMATCH', message: 'Enrollment token subject does not match invite.' } });
    }

    if (!repo.consumeInvite(invite.code)) {
      return res.status(409).json({ error: { code: 'INVITE_USED', message: 'Invite was already consumed.' } });
    }

    const member = repo.upsertMember({
      externalUserId: invite.external_user_id,
      displayName: String(display_name || invite.display_name || invite.external_user_id).trim().slice(0, 80),
      memberCode: String(member_code || invite.member_code || '').trim().slice(0, 40),
      groupName: String(group_name || invite.group_name || '').trim().slice(0, 60),
      role: invite.role,
      method: verified.authMethod,
    });

    return res.status(201).json({
      ok: true,
      member,
      token_meta: verified.tokenMeta,
    });
  });

  // ============================================================================
  // 6. Admin Console Endpoints (/api/admin/*)
  // ============================================================================
  app.get('/api/admin/overview', requireAdmin, (req, res) => {
    const cfg = repo.getAppConfig();
    const sites = repo.listSites().map(safeSitePublic);
    const members = repo.listMembers();
    const invites = repo.listInvites(25);
    const checkins = repo.listCheckins({ limit: 150 });
    const audits = repo.listVerifyAudit(50);

    res.json({
      config: cfg,
      preset: getPreset(cfg.preset_id),
      presets: listPresets(),
      detected_ip: extractClientIp(req, trustProxy),
      base_url: resolveBaseUrl(req),
      stats: {
        today_checkins: repo.countTodayCheckins(),
        total_members: members.length,
        total_sites: sites.length,
        wifi_locked_sites: sites.filter((s) => s.require_wifi_ip).length,
      },
      sites,
      members,
      invites,
      checkins,
      audits,
    });
  });

  app.patch('/api/admin/settings', requireAdmin, requireCsrf, (req, res) => {
    const { org_name, preset_id, default_lang } = req.body || {};
    if (preset_id !== undefined && isValidPreset(preset_id)) {
      repo.setSetting('preset_id', preset_id);
    }
    if (default_lang === 'th' || default_lang === 'en') {
      repo.setSetting('default_lang', default_lang);
    }
    if (org_name !== undefined && String(org_name).trim()) {
      repo.setSetting('org_name', String(org_name).trim().slice(0, 120));
    }
    const cfg = repo.getAppConfig();
    res.json({ ok: true, config: cfg, preset: getPreset(cfg.preset_id) });
  });

  app.post('/api/admin/sites', requireAdmin, requireCsrf, (req, res) => {
    const { name, qr_rotate_sec, qr_max_age_sec, require_wifi_ip, allowed_ips } = req.body || {};
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Station name is required.' } });
    }
    const site = repo.createSite({
      name: String(name).trim().slice(0, 120),
      qrRotateSec: qr_rotate_sec ?? 7,
      qrMaxAgeSec: qr_max_age_sec ?? 10,
      requireWifiIp: Boolean(require_wifi_ip),
      allowedIps: allowed_ips || '',
    });
    return res.status(201).json({ ok: true, site: safeSitePublic(site) });
  });

  app.patch('/api/admin/sites/:id', requireAdmin, requireCsrf, (req, res) => {
    const { name, qr_rotate_sec, qr_max_age_sec, require_wifi_ip, allowed_ips } = req.body || {};
    const updated = repo.updateSite(req.params.id, {
      name,
      qrRotateSec: qr_rotate_sec,
      qrMaxAgeSec: qr_max_age_sec,
      requireWifiIp: require_wifi_ip,
      allowedIps: allowed_ips,
    });
    if (!updated) {
      return res.status(404).json({ error: { code: 'SITE_NOT_FOUND', message: 'Station not found.' } });
    }
    return res.json({ ok: true, site: safeSitePublic(updated) });
  });

  app.post('/api/admin/invites', requireAdmin, requireCsrf, (req, res) => {
    const { display_name, member_code, group_name, external_user_id, role, ttl_hours } = req.body || {};
    const invite = repo.createInvite({
      displayName: display_name || '',
      memberCode: member_code || '',
      groupName: group_name || '',
      externalUserId: external_user_id || '',
      role: role === 'ADMIN' ? 'ADMIN' : 'MEMBER',
      ttlHours: ttl_hours || 24,
    });
    const baseUrl = resolveBaseUrl(req);
    res.status(201).json({
      ok: true,
      invite,
      invite_url: `${baseUrl}/scan?invite=${encodeURIComponent(invite.code)}`,
    });
  });

  app.get('/api/admin/export.csv', requireAdmin, (req, res) => {
    const cfg = repo.getAppConfig();
    const preset = getPreset(cfg.preset_id);
    const lang = req.query.lang === 'en' ? 'en' : (req.query.lang === 'th' ? 'th' : cfg.default_lang);
    const siteId = req.query.site_id ? String(req.query.site_id) : null;
    const rows = repo.listCheckins({ siteId, limit: 1000 });
    const headers = preset[lang === 'en' ? 'en' : 'th'].csvHeaders;

    const lines = [headers.map(csvEscapeCell).join(',')];
    for (const r of rows) {
      lines.push(
        [
          r.created_at,
          r.site_name,
          r.member_code || r.external_user_id,
          r.display_name,
          r.group_name,
          r.action,
          r.auth_method,
          r.ip_check_status,
          r.note,
          r.token_jti,
        ]
          .map(csvEscapeCell)
          .join(',')
      );
    }

    const filename = `login512-${preset.id}-checkins-${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    // Prefix UTF-8 BOM (\uFEFF) so Thai characters render cleanly in Microsoft Excel
    res.send(`\uFEFF${lines.join('\r\n')}\r\n`);
  });

  // ============================================================================
  // 7. Local Offline Demo/Test Helper (STRICTLY disabled unless DEMO_MOCK_AUTH=true)
  // ============================================================================
  app.post('/api/demo/mock-token', (req, res) => {
    if (!login512.demoMockAuth) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    }
    // Only this machine may mint mock tokens (socket address, not X-Forwarded-For, so it cannot be spoofed).
    if (!isLoopbackAddress(req.socket.remoteAddress)) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    }
    const { sub, act, mod, nonce, step_up } = req.body || {};
    const token = login512.issueMockToken({
      sub: String(sub || 'usr_demo_01'),
      act: String(act || 'login'),
      mod: String(mod || 'FACE').toUpperCase(),
      nonce: nonce || null,
      stepUp: Boolean(step_up),
    });
    return res.json({ token, mock: true });
  });

  return {
    app,
    repo,
    login512,
    genesisState,
    close() {
      for (const set of sseClients.values()) {
        for (const res of set) {
          try { res.end(); } catch {}
        }
      }
      sseClients.clear();
      repo.close();
    },
  };
}

if (require.main === module) {
  const port = Number.parseInt(process.env.PORT || '3512', 10);
  const instance = createApp();
  const cfg = instance.repo.getAppConfig();

  const server = instance.app.listen(port, () => {
    console.log('');
    console.log('==================================================================');
    console.log('  Login512 Smart Check-in (Open-Source Reference App)');
    console.log(`  URL:          http://localhost:${port}`);
    console.log(`  Preset:       ${cfg.preset_id} (${getPreset(cfg.preset_id).en.shortName})`);
    console.log(`  Login512 API: ${instance.login512.endpoint} ${instance.login512.demoMockAuth ? '[DEMO_MOCK_AUTH]' : (instance.login512.isConfigured() ? '[CONFIGURED]' : '[NEEDS KEYS in .env]')}`);
    if (!instance.genesisState.locked) {
      console.log('------------------------------------------------------------------');
      console.log(`  FIRST-TIME GENESIS MODE ACTIVE: http://localhost:${port}/setup`);
      if (instance.genesisState.generatedSetupKey) {
        console.log(`  ONE-TIME SETUP KEY: ${instance.genesisState.generatedSetupKey}`);
      } else {
        console.log('  SETUP KEY: (using GENESIS_SETUP_KEY from environment / previous boot)');
      }
    } else {
      console.log(`  Kiosk Screen: http://localhost:${port}/kiosk`);
      console.log(`  Admin Panel:  http://localhost:${port}/admin`);
    }
    console.log('==================================================================');
    console.log('');
  });

  const shutdown = () => {
    server.close(() => {
      instance.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = { createApp };
