'use strict';

/**
 * src/login512/qr-guard.js — Pure-Web Proof-of-Presence Location Guard
 *
 * Defeats Fake GPS, group-chat QR photo sharing, AND live video-call QR relay without needing a native app:
 *   Layer 1: Fast-Rotating Dynamic QR (5-8s rotation, default 7s; <= 10s expiry) signed with per-site HMAC-SHA256.
 *   Layer 2: Optional Office/School Wi-Fi IP Allowlist (exact IPv4/IPv6 or IPv4 CIDR) enforced server-side.
 *            Even if a friend streams the Kiosk screen over a video call, any phone outside the allowed
 *            office/school Wi-Fi IP range is hard-blocked before scanning and again upon check-in submission.
 */

const crypto = require('crypto');
const net = require('net');

/**
 * Mints a signed rotating Dynamic QR token for a Kiosk screen.
 */
function mintDynamicQrPayload({ site, nowMs = Date.now() }) {
  const rotateSec = Math.max(5, Math.min(15, Number(site.qr_rotate_sec) || 7));
  const maxAgeSec = Math.max(rotateSec + 2, Math.min(30, Number(site.qr_max_age_sec) || 10));
  const rotateMs = rotateSec * 1000;
  const slot = Math.floor(nowMs / rotateMs);
  const issuedTs = slot * rotateSec; // epoch seconds at slot start
  const nextRotateInMs = Math.max(250, (slot + 1) * rotateMs - nowMs);

  const sig = signQrSlot(site.kiosk_secret, site.id, issuedTs, slot);
  const qrToken = `${site.id}.${issuedTs}.${slot}.${sig}`;

  return {
    site_id: site.id,
    ts: issuedTs,
    slot,
    sig,
    qr_token: qrToken,
    rotate_sec: rotateSec,
    max_age_sec: maxAgeSec,
    next_rotate_in_ms: nextRotateInMs,
  };
}

/**
 * Validates a scanned Dynamic QR token against per-site HMAC secret and strict freshness window.
 */
function verifyDynamicQrPayload({ site, qrToken, nowMs = Date.now() }) {
  if (!site || !qrToken || typeof qrToken !== 'string') {
    return { ok: false, code: 'QR_MISSING', message: 'Missing or invalid QR token' };
  }

  const parts = qrToken.trim().split('.');
  if (parts.length !== 4) {
    return { ok: false, code: 'QR_MALFORMED', message: 'Malformed QR payload' };
  }

  const [siteId, tsStr, slotStr, providedSig] = parts;
  if (siteId !== site.id) {
    return { ok: false, code: 'QR_SITE_MISMATCH', message: 'QR does not belong to this check-in station' };
  }

  const issuedTs = Number.parseInt(tsStr, 10);
  const slot = Number.parseInt(slotStr, 10);
  if (!Number.isFinite(issuedTs) || !Number.isFinite(slot)) {
    return { ok: false, code: 'QR_MALFORMED', message: 'Invalid QR timestamp or slot' };
  }

  const expectedSig = signQrSlot(site.kiosk_secret, site.id, issuedTs, slot);
  const a = Buffer.from(providedSig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, code: 'QR_INVALID_SIGNATURE', message: 'QR signature verification failed' };
  }

  const rotateSec = Math.max(5, Math.min(15, Number(site.qr_rotate_sec) || 7));
  const maxAgeSec = Math.max(rotateSec + 2, Math.min(30, Number(site.qr_max_age_sec) || 10));
  const ageMs = nowMs - issuedTs * 1000;

  if (ageMs < -3000) {
    return { ok: false, code: 'QR_FUTURE_TIMESTAMP', message: 'QR timestamp is in the future' };
  }
  if (ageMs > maxAgeSec * 1000) {
    return {
      ok: false,
      code: 'QR_EXPIRED',
      message: `QR expired (${Math.round(ageMs / 1000)}s old, max ${maxAgeSec}s). Please rescan live Kiosk screen.`,
      ageMs,
    };
  }

  return {
    ok: true,
    siteId,
    slot,
    ageMs: Math.max(0, Math.round(ageMs)),
  };
}

function signQrSlot(secret, siteId, issuedTs, slot) {
  return crypto
    .createHmac('sha256', String(secret))
    .update(`${siteId}:${issuedTs}:${slot}`)
    .digest('base64url')
    .slice(0, 32);
}

/**
 * Normalizes IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1).
 */
function normalizeIp(raw) {
  if (!raw || typeof raw !== 'string') return '';
  let ip = raw.trim();
  if (ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }
  if (ip.startsWith('::ffff:')) {
    const mapped = ip.slice(7);
    if (net.isIPv4(mapped)) return mapped;
  }
  return ip;
}

/**
 * Extracts real client IP safely (only honors proxy headers when TRUST_PROXY is enabled).
 */
function extractClientIp(req, trustProxy = false) {
  if (trustProxy) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) return normalizeIp(String(cfIp));
    const xff = req.headers['x-forwarded-for'];
    if (xff) return normalizeIp(String(xff));
  }
  return normalizeIp(req.socket?.remoteAddress || req.ip || '');
}

function ipv4ToInt(ip) {
  const octets = ip.split('.').map((n) => Number.parseInt(n, 10));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return (((octets[0] << 24) >>> 0) + ((octets[1] << 16) >>> 0) + ((octets[2] << 8) >>> 0) + (octets[3] >>> 0)) >>> 0;
}

function ipMatchesRule(clientIp, rawRule) {
  const ip = normalizeIp(clientIp);
  const rule = normalizeIp(rawRule);
  if (!ip || !rule) return false;

  // Treat IPv4 and IPv6 loopback as equivalent for local development convenience
  const isLocal = (v) => v === '127.0.0.1' || v === '::1';
  if (isLocal(ip) && isLocal(rule)) return true;

  if (rule.includes('/')) {
    const [baseIp, bitsStr] = rule.split('/');
    const bits = Number.parseInt(bitsStr, 10);
    if (!net.isIPv4(baseIp) || !net.isIPv4(ip) || Number.isNaN(bits) || bits < 0 || bits > 32) {
      return false;
    }
    const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0;
    const ipInt = ipv4ToInt(ip);
    const baseInt = ipv4ToInt(baseIp);
    return (ipInt & mask) === (baseInt & mask);
  }

  return ip.toLowerCase() === rule.toLowerCase();
}

function parseAllowlist(allowedIpsStr) {
  return String(allowedIpsStr || '')
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Evaluates Layer 2 Office/School Wi-Fi IP Allowlist policy (fail-closed when enabled).
 */
function checkWifiIpPolicy({ site, clientIp }) {
  if (!site || !site.require_wifi_ip) {
    return { allowed: true, status: 'DISABLED', clientIp: normalizeIp(clientIp) };
  }

  const rules = parseAllowlist(site.allowed_ips);
  const ip = normalizeIp(clientIp);
  if (rules.length === 0) {
    return {
      allowed: false,
      status: 'MISCONFIGURED',
      clientIp: ip,
      message: 'Wi-Fi IP Lock is enabled for this station, but no allowed IP/CIDR is configured.',
    };
  }

  const matched = rules.some((rule) => ipMatchesRule(ip, rule));
  if (!matched) {
    return {
      allowed: false,
      status: 'BLOCKED',
      clientIp: ip,
      message: 'Check-in blocked: you must connect to the authorized on-site Wi-Fi network.',
    };
  }

  return { allowed: true, status: 'PASSED', clientIp: ip };
}

function maskIpForAudit(rawIp) {
  const ip = normalizeIp(rawIp);
  if (!ip) return '';
  if (net.isIPv4(ip)) {
    const parts = ip.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
  }
  const segs = ip.split(':');
  return segs.length > 2 ? `${segs.slice(0, 2).join(':')}:xxxx` : ip;
}

module.exports = {
  mintDynamicQrPayload,
  verifyDynamicQrPayload,
  normalizeIp,
  extractClientIp,
  ipMatchesRule,
  parseAllowlist,
  checkWifiIpPolicy,
  maskIpForAudit,
};
