'use strict';

/**
 * src/login512/genesis.js — App-Level First-Time Genesis Mode (Zero default admin/1234)
 *
 * Replaces insecure default passwords (admin/1234) on fresh self-hosted deployments:
 *   1. On first boot with 0 admins, generates a high-entropy one-time Setup Key (or uses GENESIS_SETUP_KEY env)
 *      and stores ONLY its SHA-256 hash in SQLite.
 *   2. The installer enters the Setup Key on /setup, selects an Industry Preset, and enrolls their own
 *      Face or Passkey via Login512 (server-minted enrollment_token + server-verified ML-DSA-65 token).
 *   3. Once the first Superadmin is verified, Genesis Mode is permanently locked and the Setup Key hash is wiped.
 */

const crypto = require('crypto');

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function ensureGenesisState(repo, envSetupKey = '') {
  if (repo.getSetting('genesis_locked', '0') === '1' || repo.countAdmins() > 0) {
    repo.setSetting('genesis_locked', '1');
    repo.deleteSetting('genesis_setup_key_hash');
    return { locked: true, generatedSetupKey: null };
  }

  const trimmedEnv = String(envSetupKey || '').trim();
  if (trimmedEnv.length >= 16) {
    repo.setSetting('genesis_setup_key_hash', sha256Hex(trimmedEnv));
    return { locked: false, generatedSetupKey: null, fromEnv: true };
  }

  // Generate once per fresh DB so restarts before setup completes keep working if desired,
  // or regenerate if no hash exists yet.
  const existingHash = repo.getSetting('genesis_setup_key_hash', '');
  if (existingHash) {
    return { locked: false, generatedSetupKey: null, fromEnv: false };
  }

  const oneTimeKey = `L512-SETUP-${crypto.randomBytes(12).toString('hex').toUpperCase()}`;
  repo.setSetting('genesis_setup_key_hash', sha256Hex(oneTimeKey));
  return { locked: false, generatedSetupKey: oneTimeKey, fromEnv: false };
}

function isGenesisLocked(repo) {
  return repo.getSetting('genesis_locked', '0') === '1' || repo.countAdmins() > 0;
}

function verifySetupKey(repo, providedKey) {
  if (isGenesisLocked(repo)) return false;
  const storedHash = repo.getSetting('genesis_setup_key_hash', '');
  if (!storedHash || !providedKey || typeof providedKey !== 'string') return false;

  const actualHash = sha256Hex(providedKey.trim());
  const a = Buffer.from(actualHash, 'hex');
  const b = Buffer.from(storedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function lockGenesis(repo) {
  repo.setSetting('genesis_locked', '1');
  repo.deleteSetting('genesis_setup_key_hash');
}

module.exports = {
  ensureGenesisState,
  isGenesisLocked,
  verifySetupKey,
  lockGenesis,
};
