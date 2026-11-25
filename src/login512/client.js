'use strict';

/**
 * src/login512/client.js — Reference Server-Side Integration for Login512
 *
 * Developers integrating Login512 into any Node.js app (ERP, POS, HR, LMS, SaaS) can copy this file directly.
 *
 * Security rules enforced here (never skip any of these in production):
 *   1. Secret Key (l512_sk_...) stays ONLY on the backend — never sent to browser JS.
 *   2. Every biometric/passkey token MUST be verified via POST /v1/token/verify before trusting the user.
 *   3. HTTP 200 alone is NOT success: check `valid === true && session_allowed === true && !step_up_required`.
 *   4. Face login tokens MUST be bound to a server-issued single-use `expected_nonce`.
 *   5. Passkey login tokens are verified for single-use JTI + ML-DSA-65 signature AND strictly checked for
 *      `claims.mod === 'PASSKEY'` so a face token can never masquerade as passkey to skip nonce checking.
 *   6. Enrollment tokens MUST be minted server-side via POST /v1/enrollment-tokens for an authorized user.
 */

const crypto = require('crypto');
const sdk = require('@login512/server-sdk');

class Login512Client {
  constructor(config = {}) {
    this.endpoint = (config.endpoint || process.env.LOGIN512_ENDPOINT || 'https://api.login512.com').replace(/\/+$/, '');
    this.sdkUrl = config.sdkUrl || process.env.LOGIN512_SDK_URL || 'https://login512.com/sdk/login512-sdk.js?v=2026.11.25';
    this.publishableKey = (config.publishableKey || process.env.LOGIN512_PUBLISHABLE_KEY || '').trim();
    this.secretKey = (config.secretKey || process.env.LOGIN512_SECRET_KEY || '').trim();

    // Local automated test / offline demo mode ONLY. NEVER enable in production!
    this.demoMockAuth = Boolean(
      config.demoMockAuth !== undefined
        ? config.demoMockAuth
        : String(process.env.DEMO_MOCK_AUTH || '').toLowerCase() === 'true'
    );
    // Random per process: mock tokens are only valid inside this one running server, so a mock token
    // (or a copy of this public source code) can never be used against another deployment.
    this._mockKey = crypto.randomBytes(32);
    this._mockUsedJtis = new Set();
    this._mockEnrollTokens = new Map();
  }

  isConfigured() {
    if (this.demoMockAuth) return true;
    return (
      this.publishableKey.startsWith('l512_pk_') &&
      !this.publishableKey.includes('replace_with') &&
      this.secretKey.startsWith('l512_sk_') &&
      !this.secretKey.includes('replace_with')
    );
  }

  publicConfig() {
    return {
      endpoint: this.endpoint,
      sdkUrl: this.sdkUrl,
      publishableKey: this.publishableKey,
      configured: this.isConfigured(),
      demoMockAuth: this.demoMockAuth,
    };
  }

  generateNonce() {
    return sdk.generateNonce();
  }

  /**
   * Mints a short-lived single-use enrollment token using the backend SECRET key.
   */
  async createEnrollmentToken({ externalUserId, displayName = null, ttlSeconds = 180 }) {
    if (!externalUserId) {
      throw new Error('externalUserId is required');
    }

    if (this.demoMockAuth) {
      const token = `l512_enr_mock_${crypto.randomBytes(12).toString('hex')}`;
      this._mockEnrollTokens.set(token, {
        externalUserId,
        displayName,
        expiresAt: Date.now() + ttlSeconds * 1000,
      });
      return {
        enrollment_token: token,
        expires_at: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
        mock: true,
      };
    }

    return sdk.createEnrollmentToken({
      secretKey: this.secretKey,
      externalUserId,
      displayName,
      ttlSeconds,
      endpoint: this.endpoint,
    });
  }

  /**
   * Verifies a Login512 ML-DSA-65 token on the server with strict anti-replay, nonce, act, and mod checks.
   *
   * @param {Object} params
   * @param {string} params.token - Raw L512 token from browser SDK
   * @param {'face'|'passkey'} params.authMethod - Expected authentication method
   * @param {string|null} [params.expectedNonce] - Required when authMethod === 'face' and action is login
   * @param {string[]} [params.expectedActs] - Allowed `claims.act` values (e.g. ['login'] or ['enroll', 'enroll_passkey'])
   */
  async verifyAuthToken({ token, authMethod = 'face', expectedNonce = null, expectedActs = ['login'] }) {
    const method = String(authMethod || 'face').toLowerCase() === 'passkey' ? 'passkey' : 'face';
    const isLoginFlow = expectedActs.includes('login');

    if (!token || typeof token !== 'string') {
      return failResult('MISSING_TOKEN', 'Missing biometric verification token');
    }

    // Rule 4: Face login MUST always bind to a server-issued expected_nonce
    if (method === 'face' && isLoginFlow && !expectedNonce) {
      return failResult('NONCE_REQUIRED', 'Server expected_nonce is required for face verification');
    }

    const rawRes = this.demoMockAuth
      ? this._verifyMockToken({ token, expectedNonce: method === 'face' && isLoginFlow ? expectedNonce : null })
      : await sdk.verifyToken({
          secretKey: this.secretKey,
          token,
          expectedNonce: method === 'face' && isLoginFlow ? expectedNonce : undefined,
          endpoint: this.endpoint,
        });

    if (!rawRes || rawRes.valid !== true) {
      return failResult(rawRes?.error || 'TOKEN_INVALID', rawRes?.error || 'Login512 token verification failed');
    }
    if (rawRes.step_up_required === true || rawRes.session_allowed === false) {
      return failResult('STEP_UP_REQUIRED', 'Additional verification (step-up) is required before granting access', rawRes.claims);
    }

    const claims = rawRes.claims || {};
    if (!claims.sub) {
      return failResult('TOKEN_HAS_NO_SUBJECT', 'Verified token is missing claims.sub', claims);
    }

    const actualMod = String(claims.mod || '').toUpperCase();
    const actualAct = String(claims.act || '').toLowerCase();

    // Rule 5: Prevent method confusion (a face token must NEVER pass under authMethod='passkey' to skip nonce!)
    if (method === 'passkey' && actualMod !== 'PASSKEY') {
      return failResult('METHOD_MISMATCH', 'Expected PASSKEY token, but received non-passkey token', claims);
    }
    if (method === 'face' && actualMod === 'PASSKEY') {
      return failResult('METHOD_MISMATCH', 'Expected FACE token, but received PASSKEY token', claims);
    }

    if (Array.isArray(expectedActs) && expectedActs.length > 0 && !expectedActs.includes(actualAct)) {
      return failResult('UNEXPECTED_TOKEN_ACTION', `Unexpected token action "${actualAct}"`, claims);
    }

    const header = decodeTokenHeaderSafe(token);
    return {
      valid: true,
      sessionAllowed: true,
      errorCode: null,
      errorMessage: null,
      subject: String(claims.sub),
      authMethod: actualMod === 'PASSKEY' ? 'PASSKEY' : 'FACE',
      nonceChecked: Boolean(method === 'face' && isLoginFlow && expectedNonce),
      tokenMeta: {
        jti: String(claims.jti || ''),
        kid: String(header?.kid || claims.kid || 'ml-dsa-65'),
        alg: String(header?.alg || 'ML-DSA-65'),
        act: actualAct || 'login',
        mod: actualMod || 'FACE',
        risk: String(claims.risk || 'LOW'),
      },
      claims,
    };
  }

  /**
   * Local test/demo helper ONLY (when DEMO_MOCK_AUTH=true).
   * Issues a synthetic L512-shaped token that enforces identical nonce, JTI replay, act, mod, and step-up checks.
   */
  issueMockToken({ sub, act = 'login', mod = 'FACE', nonce = null, stepUp = false, expOffsetSec = 120 }) {
    if (!this.demoMockAuth) {
      throw new Error('issueMockToken is disabled unless DEMO_MOCK_AUTH=true');
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const header = { typ: 'L512', alg: 'ML-DSA-65', kid: 'demo-local-mock' };
    const payload = {
      sub,
      act,
      mod,
      iss: 'login512-local-mock',
      aud: 'demo-tenant',
      iat: nowSec,
      exp: nowSec + expOffsetSec,
      jti: crypto.randomUUID(),
      nonce,
      stp: Boolean(stepUp),
      risk: stepUp ? 'HIGH' : 'LOW',
    };
    const h = Buffer.from(JSON.stringify(header)).toString('base64url');
    const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', this._mockKey).update(`${h}.${p}`).digest('base64url');
    return `${h}.${p}.${sig}`;
  }

  _verifyMockToken({ token, expectedNonce }) {
    const parts = String(token).split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'TOKEN_MALFORMED', session_allowed: false, step_up_required: false };
    }
    try {
      const expectedSig = crypto.createHmac('sha256', this._mockKey).update(`${parts[0]}.${parts[1]}`).digest('base64url');
      const a = Buffer.from(parts[2]);
      const b = Buffer.from(expectedSig);
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return { valid: false, error: 'TOKEN_BAD_SIGNATURE', session_allowed: false, step_up_required: false };
      }
      const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      const nowSec = Math.floor(Date.now() / 1000);
      if (claims.exp && nowSec > claims.exp) {
        return { valid: false, error: 'TOKEN_EXPIRED', claims, session_allowed: false, step_up_required: false };
      }
      if (expectedNonce && claims.nonce !== expectedNonce) {
        return { valid: false, error: 'NONCE_MISMATCH', claims, session_allowed: false, step_up_required: false };
      }
      if (!claims.jti || this._mockUsedJtis.has(claims.jti)) {
        return { valid: false, error: 'TOKEN_ALREADY_USED', claims, session_allowed: false, step_up_required: false };
      }
      this._mockUsedJtis.add(claims.jti);
      const stepUp = Boolean(claims.stp);
      return {
        valid: true,
        claims,
        error: null,
        session_allowed: !stepUp,
        step_up_required: stepUp,
      };
    } catch (err) {
      return { valid: false, error: 'TOKEN_MALFORMED', session_allowed: false, step_up_required: false };
    }
  }
}

function decodeTokenHeaderSafe(token) {
  try {
    const seg = String(token).split('.')[0];
    if (!seg) return null;
    return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function failResult(errorCode, errorMessage, claims = null) {
  return {
    valid: false,
    sessionAllowed: false,
    errorCode,
    errorMessage,
    subject: null,
    authMethod: null,
    nonceChecked: false,
    tokenMeta: null,
    claims,
  };
}

module.exports = {
  Login512Client,
};
