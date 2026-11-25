#!/usr/bin/env node
'use strict';
// Checks every presets/*.json. Run after adding or editing a preset: npm run check:presets
const { loadPresetsFrom, PRESETS_DIR, PRESET_ORDER } = require('../src/presets');

const { presets, report } = loadPresetsFrom(PRESETS_DIR);
for (const [id, p] of presets) {
  const builtIn = PRESET_ORDER.includes(id) ? 'built-in' : 'custom';
  console.log(`OK   ${id.padEnd(16)} ${p.icon} ${p.en.name} (${builtIn}, QR ${p.defaultQrRotateSec}s)`);
}
for (const r of report) {
  console.log(`FAIL ${r.id}`);
  for (const msg of r.problems) console.log(`     - ${msg}`);
}
console.log(`\n${presets.size} preset(s) OK, ${report.length} with problems.`);
process.exit(report.length ? 1 : 0);
