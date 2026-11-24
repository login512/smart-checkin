'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const { getPreset } = require('./presets');

function initDatabase({ dbPath, defaultPreset = 'classroom', defaultLang = 'th', defaultQrRotateSec = 7, defaultQrMaxAgeSec = 10 }) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  if (dbPath !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sites (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      kiosk_secret TEXT NOT NULL,
      qr_rotate_sec INTEGER NOT NULL DEFAULT 7,
      qr_max_age_sec INTEGER NOT NULL DEFAULT 10,
      require_wifi_ip INTEGER NOT NULL DEFAULT 0,
      allowed_ips TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS members (
      id TEXT PRIMARY KEY,
      external_user_id TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      member_code TEXT NOT NULL DEFAULT '',
      group_name TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'MEMBER',
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      enrolled_methods TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS invites (
      code TEXT PRIMARY KEY,
      external_user_id TEXT NOT NULL,
      display_name TEXT NOT NULL DEFAULT '',
      member_code TEXT NOT NULL DEFAULT '',
      group_name TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'MEMBER',
      max_uses INTEGER NOT NULL DEFAULT 1,
      uses_count INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS checkin_tickets (
      id TEXT PRIMARY KEY,
      site_id TEXT NOT NULL,
      expected_nonce TEXT NOT NULL,
      qr_slot INTEGER NOT NULL,
      qr_age_ms INTEGER NOT NULL,
      client_ip TEXT NOT NULL,
      ip_check_status TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS auth_nonces (
      nonce TEXT PRIMARY KEY,
      purpose TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      member_id TEXT NOT NULL,
      csrf_token TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS checkins (
      id TEXT PRIMARY KEY,
      site_id TEXT NOT NULL,
      site_name TEXT NOT NULL,
      member_id TEXT,
      external_user_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      member_code TEXT NOT NULL DEFAULT '',
      group_name TEXT NOT NULL DEFAULT '',
      action TEXT NOT NULL DEFAULT 'check_in',
      auth_method TEXT NOT NULL,
      ip_check_status TEXT NOT NULL,
      client_ip_masked TEXT NOT NULL DEFAULT '',
      qr_age_ms INTEGER NOT NULL DEFAULT 0,
      note TEXT NOT NULL DEFAULT '',
      token_jti TEXT NOT NULL DEFAULT '',
      token_kid TEXT NOT NULL DEFAULT '',
      token_alg TEXT NOT NULL DEFAULT 'ML-DSA-65',
      token_act TEXT NOT NULL DEFAULT 'login',
      nonce_checked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_checkins_created ON checkins(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_checkins_site ON checkins(site_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS verify_audit (
      id TEXT PRIMARY KEY,
      context TEXT NOT NULL,
      auth_method TEXT NOT NULL,
      valid INTEGER NOT NULL,
      error_code TEXT,
      external_user_id TEXT,
      token_jti TEXT,
      token_kid TEXT,
      token_alg TEXT,
      token_act TEXT,
      nonce_checked INTEGER NOT NULL DEFAULT 0,
      ip_check_status TEXT,
      qr_age_ms INTEGER,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_verify_audit_created ON verify_audit(created_at DESC);
  `);

  const preset = getPreset(defaultPreset);
  const langKey = defaultLang === 'en' ? 'en' : 'th';
  const seedSetting = db.prepare('INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)');
  seedSetting.run('preset_id', preset.id);
  seedSetting.run('default_lang', langKey);
  seedSetting.run('org_name', preset[langKey].defaultOrgName);
  seedSetting.run('genesis_locked', '0');

  const siteCount = db.prepare('SELECT COUNT(*) AS cnt FROM sites').get().cnt;
  if (siteCount === 0) {
    const rot = clampInt(defaultQrRotateSec || preset.defaultQrRotateSec || 7, 5, 15);
    const maxAge = Math.max(rot + 3, clampInt(defaultQrMaxAgeSec || 10, 6, 30));
    db.prepare(`
      INSERT INTO sites (id, name, kiosk_secret, qr_rotate_sec, qr_max_age_sec, require_wifi_ip, allowed_ips, created_at)
      VALUES (?, ?, ?, ?, ?, 0, '', ?)
    `).run(
      'site_main',
      preset[langKey].defaultSiteName,
      crypto.randomBytes(32).toString('hex'),
      rot,
      maxAge,
      new Date().toISOString()
    );
  }

  return createRepo(db);
}

function clampInt(val, min, max) {
  const n = Number.parseInt(val, 10);
  if (Number.isNaN(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function createRepo(db) {
  return {
    raw: db,

    close() {
      db.close();
    },

    getSetting(key, fallback = null) {
      const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
      return row ? row.value : fallback;
    },

    setSetting(key, value) {
      db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(
        key,
        String(value)
      );
    },

    deleteSetting(key) {
      db.prepare('DELETE FROM app_settings WHERE key = ?').run(key);
    },

    getAppConfig() {
      const presetId = this.getSetting('preset_id', 'classroom');
      const lang = this.getSetting('default_lang', 'th');
      const preset = getPreset(presetId);
      return {
        preset_id: preset.id,
        default_lang: lang,
        org_name: this.getSetting('org_name', preset[lang === 'en' ? 'en' : 'th'].defaultOrgName),
        genesis_locked: this.getSetting('genesis_locked', '0') === '1',
      };
    },

    // --- Sites / Kiosk Stations ---
    listSites() {
      return db.prepare('SELECT * FROM sites ORDER BY created_at ASC').all().map(formatSite);
    },

    getSite(id) {
      const row = db.prepare('SELECT * FROM sites WHERE id = ?').get(id);
      return row ? formatSite(row) : null;
    },

    getDefaultSite() {
      const row = db.prepare('SELECT * FROM sites ORDER BY created_at ASC LIMIT 1').get();
      return row ? formatSite(row) : null;
    },

    createSite({ name, qrRotateSec = 7, qrMaxAgeSec = 10, requireWifiIp = false, allowedIps = '' }) {
      const id = `site_${crypto.randomBytes(4).toString('hex')}`;
      const rot = clampInt(qrRotateSec, 5, 15);
      const maxAge = Math.max(rot + 2, clampInt(qrMaxAgeSec, 6, 30));
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO sites (id, name, kiosk_secret, qr_rotate_sec, qr_max_age_sec, require_wifi_ip, allowed_ips, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, name.trim(), crypto.randomBytes(32).toString('hex'), rot, maxAge, requireWifiIp ? 1 : 0, String(allowedIps || '').trim(), now);
      return this.getSite(id);
    },

    updateSite(id, { name, qrRotateSec, qrMaxAgeSec, requireWifiIp, allowedIps }) {
      const existing = this.getSite(id);
      if (!existing) return null;
      const nextName = name !== undefined ? String(name).trim() || existing.name : existing.name;
      const rot = qrRotateSec !== undefined ? clampInt(qrRotateSec, 5, 15) : existing.qr_rotate_sec;
      const maxAge = qrMaxAgeSec !== undefined ? Math.max(rot + 2, clampInt(qrMaxAgeSec, 6, 30)) : Math.max(rot + 2, existing.qr_max_age_sec);
      const reqIp = requireWifiIp !== undefined ? (requireWifiIp ? 1 : 0) : (existing.require_wifi_ip ? 1 : 0);
      const ips = allowedIps !== undefined ? String(allowedIps).trim() : existing.allowed_ips;
      db.prepare(`
        UPDATE sites
        SET name = ?, qr_rotate_sec = ?, qr_max_age_sec = ?, require_wifi_ip = ?, allowed_ips = ?
        WHERE id = ?
      `).run(nextName, rot, maxAge, reqIp, ips, id);
      return this.getSite(id);
    },

    // --- Members ---
    countAdmins() {
      return db.prepare("SELECT COUNT(*) AS cnt FROM members WHERE role = 'ADMIN' AND status = 'ACTIVE'").get().cnt;
    },

    listMembers() {
      return db.prepare('SELECT * FROM members ORDER BY role ASC, created_at DESC').all();
    },

    getMemberById(id) {
      return db.prepare('SELECT * FROM members WHERE id = ?').get(id) || null;
    },

    getMemberByExternalId(externalUserId) {
      return db.prepare('SELECT * FROM members WHERE external_user_id = ?').get(externalUserId) || null;
    },

    upsertMember({ externalUserId, displayName, memberCode = '', groupName = '', role = 'MEMBER', method = '' }) {
      const existing = this.getMemberByExternalId(externalUserId);
      if (existing) {
        const methods = new Set((existing.enrolled_methods || '').split(',').filter(Boolean));
        if (method) methods.add(method.toUpperCase());
        const nextRole = existing.role === 'ADMIN' ? 'ADMIN' : role;
        db.prepare(`
          UPDATE members
          SET display_name = ?, member_code = ?, group_name = ?, role = ?, status = 'ACTIVE', enrolled_methods = ?
          WHERE id = ?
        `).run(
          displayName || existing.display_name,
          memberCode || existing.member_code,
          groupName || existing.group_name,
          nextRole,
          Array.from(methods).join(','),
          existing.id
        );
        return this.getMemberById(existing.id);
      }

      const id = `mem_${crypto.randomBytes(6).toString('hex')}`;
      const methods = method ? method.toUpperCase() : '';
      db.prepare(`
        INSERT INTO members (id, external_user_id, display_name, member_code, group_name, role, status, enrolled_methods, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
      `).run(
        id,
        externalUserId,
        displayName || externalUserId,
        memberCode || '',
        groupName || '',
        role,
        methods,
        new Date().toISOString()
      );
      return this.getMemberById(id);
    },

    // --- Invites ---
    createInvite({ displayName = '', memberCode = '', groupName = '', externalUserId = '', role = 'MEMBER', ttlHours = 24 }) {
      const code = `INV-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      const extId = (externalUserId || '').trim() || `usr_${crypto.randomBytes(6).toString('hex')}`;
      const expiresAt = Date.now() + clampInt(ttlHours, 1, 720) * 3600 * 1000;
      db.prepare(`
        INSERT INTO invites (code, external_user_id, display_name, member_code, group_name, role, max_uses, uses_count, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
      `).run(code, extId, displayName.trim(), memberCode.trim(), groupName.trim(), role === 'ADMIN' ? 'ADMIN' : 'MEMBER', expiresAt, new Date().toISOString());
      return this.getInvite(code);
    },

    getInvite(code) {
      return db.prepare('SELECT * FROM invites WHERE code = ?').get(code) || null;
    },

    listInvites(limit = 30) {
      return db.prepare('SELECT * FROM invites ORDER BY created_at DESC LIMIT ?').all(limit);
    },

    consumeInvite(code) {
      const res = db.prepare(
        'UPDATE invites SET uses_count = uses_count + 1 WHERE code = ? AND uses_count < max_uses AND expires_at > ?'
      ).run(code, Date.now());
      return res.changes > 0;
    },

    // --- Check-in Tickets (Single-Use, Nonce-Bound) ---
    createCheckinTicket({ siteId, expectedNonce, qrSlot, qrAgeMs, clientIp, ipCheckStatus, ttlMs = 90000 }) {
      const id = `tkt_${crypto.randomBytes(10).toString('hex')}`;
      db.prepare(`
        INSERT INTO checkin_tickets (id, site_id, expected_nonce, qr_slot, qr_age_ms, client_ip, ip_check_status, expires_at, consumed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
      `).run(id, siteId, expectedNonce, qrSlot, qrAgeMs, clientIp, ipCheckStatus, Date.now() + ttlMs);
      return this.getCheckinTicket(id);
    },

    getCheckinTicket(id) {
      return db.prepare('SELECT * FROM checkin_tickets WHERE id = ?').get(id) || null;
    },

    consumeCheckinTicket(id) {
      const now = Date.now();
      const res = db.prepare(
        'UPDATE checkin_tickets SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at >= ?'
      ).run(now, id, now);
      return res.changes > 0;
    },

    // --- Auth Nonces (Admin Login / Setup) ---
    createAuthNonce(nonce, purpose, ttlMs = 120000) {
      db.prepare('INSERT INTO auth_nonces (nonce, purpose, expires_at, consumed_at) VALUES (?, ?, ?, NULL)').run(
        nonce,
        purpose,
        Date.now() + ttlMs
      );
      return nonce;
    },

    consumeAuthNonce(nonce, purpose) {
      const now = Date.now();
      const res = db.prepare(
        'UPDATE auth_nonces SET consumed_at = ? WHERE nonce = ? AND purpose = ? AND consumed_at IS NULL AND expires_at >= ?'
      ).run(now, nonce, purpose, now);
      return res.changes > 0;
    },

    // --- Sessions ---
    createSession(memberId, ttlMs = 12 * 3600 * 1000) {
      const id = crypto.randomBytes(32).toString('base64url');
      const csrfToken = crypto.randomBytes(24).toString('base64url');
      const expiresAt = Date.now() + ttlMs;
      db.prepare('INSERT INTO sessions (id, member_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)').run(
        id,
        memberId,
        csrfToken,
        expiresAt,
        new Date().toISOString()
      );
      return { id, member_id: memberId, csrf_token: csrfToken, expires_at: expiresAt };
    },

    getSessionWithMember(sessionId) {
      if (!sessionId) return null;
      const row = db.prepare(`
        SELECT s.id AS session_id, s.csrf_token, s.expires_at,
               m.id AS member_id, m.external_user_id, m.display_name, m.member_code, m.group_name, m.role, m.status
        FROM sessions s
        JOIN members m ON m.id = s.member_id
        WHERE s.id = ? AND s.expires_at > ? AND m.status = 'ACTIVE'
      `).get(sessionId, Date.now());
      return row || null;
    },

    deleteSession(sessionId) {
      if (!sessionId) return;
      db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    },

    // --- Check-ins & Verify Audit ---
    recordCheckin(entry) {
      const id = `chk_${crypto.randomBytes(6).toString('hex')}`;
      const now = new Date().toISOString();
      db.prepare(`
        INSERT INTO checkins (
          id, site_id, site_name, member_id, external_user_id, display_name, member_code, group_name,
          action, auth_method, ip_check_status, client_ip_masked, qr_age_ms, note,
          token_jti, token_kid, token_alg, token_act, nonce_checked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        entry.siteId,
        entry.siteName,
        entry.memberId || null,
        entry.externalUserId,
        entry.displayName,
        entry.memberCode || '',
        entry.groupName || '',
        entry.action || 'check_in',
        entry.authMethod,
        entry.ipCheckStatus,
        entry.clientIpMasked || '',
        entry.qrAgeMs || 0,
        (entry.note || '').slice(0, 200),
        entry.tokenJti || '',
        entry.tokenKid || '',
        entry.tokenAlg || 'ML-DSA-65',
        entry.tokenAct || 'login',
        entry.nonceChecked ? 1 : 0,
        now
      );
      return db.prepare('SELECT * FROM checkins WHERE id = ?').get(id);
    },

    listCheckins({ siteId = null, limit = 100 } = {}) {
      if (siteId) {
        return db.prepare('SELECT * FROM checkins WHERE site_id = ? ORDER BY created_at DESC LIMIT ?').all(siteId, clampInt(limit, 1, 1000));
      }
      return db.prepare('SELECT * FROM checkins ORDER BY created_at DESC LIMIT ?').all(clampInt(limit, 1, 1000));
    },

    countTodayCheckins(siteId = null) {
      const dayPrefix = new Date().toISOString().slice(0, 10);
      if (siteId) {
        return db.prepare("SELECT COUNT(*) AS cnt FROM checkins WHERE site_id = ? AND created_at LIKE ?").get(siteId, `${dayPrefix}%`).cnt;
      }
      return db.prepare("SELECT COUNT(*) AS cnt FROM checkins WHERE created_at LIKE ?").get(`${dayPrefix}%`).cnt;
    },

    recordVerifyAudit(entry) {
      const id = `aud_${crypto.randomBytes(6).toString('hex')}`;
      db.prepare(`
        INSERT INTO verify_audit (
          id, context, auth_method, valid, error_code, external_user_id,
          token_jti, token_kid, token_alg, token_act, nonce_checked, ip_check_status, qr_age_ms, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        entry.context,
        entry.authMethod || 'unknown',
        entry.valid ? 1 : 0,
        entry.errorCode || null,
        entry.externalUserId || null,
        entry.tokenJti || null,
        entry.tokenKid || null,
        entry.tokenAlg || 'ML-DSA-65',
        entry.tokenAct || null,
        entry.nonceChecked ? 1 : 0,
        entry.ipCheckStatus || null,
        entry.qrAgeMs != null ? entry.qrAgeMs : null,
        new Date().toISOString()
      );
    },

    listVerifyAudit(limit = 50) {
      return db.prepare('SELECT * FROM verify_audit ORDER BY created_at DESC LIMIT ?').all(clampInt(limit, 1, 200));
    },
  };
}

function formatSite(row) {
  return {
    ...row,
    require_wifi_ip: Boolean(row.require_wifi_ip),
  };
}

module.exports = {
  initDatabase,
  clampInt,
};
