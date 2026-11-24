'use strict';

const fs = require('fs');
const path = require('path');

const PRESETS_DIR = path.join(__dirname, '..', 'presets');
const PRESET_ORDER = ['classroom', 'workplace', 'event', 'checkpoint', 'dev-reference'];

const _cache = new Map();

function loadAllPresets() {
  if (_cache.size > 0) return _cache;
  for (const id of PRESET_ORDER) {
    const filePath = path.join(PRESETS_DIR, `${id}.json`);
    if (fs.existsSync(filePath)) {
      const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      _cache.set(parsed.id || id, parsed);
    }
  }
  return _cache;
}

function listPresets() {
  const map = loadAllPresets();
  return PRESET_ORDER.map((id) => map.get(id)).filter(Boolean);
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
  listPresets,
  getPreset,
  isValidPreset,
};
