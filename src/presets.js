'use strict';

const fs = require('fs');
const path = require('path');

const PRESETS_DIR = path.join(__dirname, '..', 'presets');

// The 5 built-in presets, in display order. Any other presets/<id>.json is added after them (sorted by id), so a new
// industry is one JSON file: copy a built-in preset, change "id" (= file name) and the texts. See docs/ADD_A_PRESET.md.
const PRESET_ORDER = ['classroom', 'workplace', 'event', 'checkpoint', 'dev-reference'];

const LANGS = ['th', 'en'];
const TEXT_KEYS = [
  'name', 'shortName', 'tagline', 'defaultOrgName', 'defaultSiteName', 'memberLabel', 'memberCodeLabel',
  'memberCodePlaceholder', 'groupLabel', 'groupPlaceholder', 'siteLabel', 'actionInLabel', 'actionOutLabel',
  'notePlaceholder', 'kioskHeadline', 'kioskSub',
];
const ID_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;

/** Problems with a preset object (empty list = valid). fileId is the file name without ".json". */
function validatePreset(p, fileId) {
  const problems = [];
  if (!p || typeof p !== 'object') return ['not a JSON object'];
  if (!ID_RE.test(String(p.id || ''))) problems.push('id must be 2-32 chars of a-z, 0-9 and "-"');
  if (fileId && p.id !== fileId) problems.push(`id "${p.id}" must equal the file name "${fileId}"`);
  if (typeof p.icon !== 'string' || !p.icon) problems.push('icon (an emoji) is required');
  if (!/^#[0-9a-fA-F]{6}$/.test(String(p.accent || ''))) problems.push('accent must be a color like "#38BDF8"');
  for (const k of ['showDevInspectorDefault', 'supportsClockOut', 'allowNote']) {
    if (typeof p[k] !== 'boolean') problems.push(`${k} must be true or false`);
  }
  // Rotating QR every 5-8 s is what stops photos/video calls of the kiosk QR from working (README, CLAUDE.md).
  if (!Number.isInteger(p.defaultQrRotateSec) || p.defaultQrRotateSec < 5 || p.defaultQrRotateSec > 8) {
    problems.push('defaultQrRotateSec must be a whole number from 5 to 8');
  }
  for (const lang of LANGS) {
    const t = p[lang];
    if (!t || typeof t !== 'object') { problems.push(`"${lang}" texts are missing`); continue; }
    for (const k of TEXT_KEYS) {
      if (typeof t[k] !== 'string' || !t[k].trim()) problems.push(`${lang}.${k} is missing`);
    }
    if (!Array.isArray(t.csvHeaders) || t.csvHeaders.length < 1 || !t.csvHeaders.every((h) => typeof h === 'string')) {
      problems.push(`${lang}.csvHeaders must be a list of column names`);
    }
  }
  return problems;
}

/** Loads presets from a directory: built-ins in PRESET_ORDER, then the other *.json files sorted by id. */
function loadPresetsFrom(dir) {
  const loaded = new Map();
  const report = [];
  const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')) : [];
  const extra = files.map((f) => f.slice(0, -5)).filter((id) => !PRESET_ORDER.includes(id)).sort();
  for (const id of [...PRESET_ORDER, ...extra]) {
    const filePath = path.join(dir, `${id}.json`);
    if (!fs.existsSync(filePath)) continue;
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (e) {
      report.push({ id, problems: [`invalid JSON: ${e.message}`] });
      continue;
    }
    const problems = validatePreset(parsed, id);
    if (problems.length) {
      report.push({ id, problems });
      continue;
    }
    loaded.set(id, parsed);
  }
  return { presets: loaded, report };
}

let _cache = null;
function loadAllPresets() {
  if (_cache) return _cache;
  const { presets, report } = loadPresetsFrom(PRESETS_DIR);
  for (const r of report) {
    console.warn(`[presets] skipped presets/${r.id}.json: ${r.problems.join('; ')} (run: npm run check:presets)`);
  }
  _cache = presets;
  return _cache;
}

function listPresets() {
  return [...loadAllPresets().values()];
}

function presetIds() {
  return [...loadAllPresets().keys()];
}

function getPreset(id) {
  const map = loadAllPresets();
  if (id && map.has(id)) return map.get(id);
  return map.get('classroom') || listPresets()[0];
}

function isValidPreset(id) {
  return loadAllPresets().has(id);
}

module.exports = {
  PRESET_ORDER,
  PRESETS_DIR,
  TEXT_KEYS,
  listPresets,
  presetIds,
  getPreset,
  isValidPreset,
  validatePreset,
  loadPresetsFrom,
};
