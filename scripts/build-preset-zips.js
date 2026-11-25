'use strict';

/**
 * scripts/build-preset-zips.js — Zero-Dependency Preset ZIP Packager
 *
 * Packages the single codebase into 5 ready-to-download ZIP files (one per industry preset)
 * for GitHub Releases, pre-configuring `.env.example` with `DEFAULT_PRESET=<presetId>`.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { presetIds } = require('../src/presets');

const ROOT = path.join(__dirname, '..');
const OUT_DIR = path.join(ROOT, 'dist-zips');
const EXCLUDE_DIRS = new Set(['node_modules', 'data', 'dist-zips', '.git']);
const EXCLUDE_FILES = new Set(['.env', '.env.local']);

function collectFiles(dir, baseRel = '') {
  const entries = [];
  for (const dirent of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = baseRel ? `${baseRel}/${dirent.name}` : dirent.name;
    const full = path.join(dir, dirent.name);
    if (dirent.isDirectory()) {
      if (EXCLUDE_DIRS.has(dirent.name)) continue;
      entries.push(...collectFiles(full, rel));
    } else {
      if (EXCLUDE_FILES.has(dirent.name) || dirent.name.endsWith('.db') || dirent.name.endsWith('.db-wal') || dirent.name.endsWith('.db-shm')) {
        continue;
      }
      entries.push({ rel, full });
    }
  }
  return entries;
}

/**
 * Minimal standards-compliant ZIP writer using Node's built-in zlib.deflateRawSync & zlib.crc32.
 */
function buildZipBuffer(fileEntries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const item of fileEntries) {
    const nameBuf = Buffer.from(item.zipPath, 'utf8');
    const rawBuf = item.content;
    const compressed = zlib.deflateRawSync(rawBuf, { level: 6 });
    const crc = zlib.crc32(rawBuf) >>> 0;

    // Local file header (30 bytes + name)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
    localHeader.writeUInt16LE(8, 8); // deflate
    localHeader.writeUInt16LE(0, 10); // time
    localHeader.writeUInt16LE(0x5421, 12); // date
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(rawBuf.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuf, compressed);

    // Central directory header (46 bytes + name)
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x5421, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(rawBuf.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);

    centralParts.push(central, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }

  const centralBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(fileEntries.length, 8);
  eocd.writeUInt16LE(fileEntries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralBuf, eocd]);
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const sourceFiles = collectFiles(ROOT);

  for (const presetId of presetIds()) {
    const folderPrefix = `login512-smart-checkin-${presetId}`;
    const entries = sourceFiles.map(({ rel, full }) => {
      let content = fs.readFileSync(full);
      if (rel === '.env.example') {
        const text = content.toString('utf8').replace(/^DEFAULT_PRESET=.*$/m, `DEFAULT_PRESET=${presetId}`);
        content = Buffer.from(text, 'utf8');
      }
      return { zipPath: `${folderPrefix}/${rel}`, content };
    });

    const outPath = path.join(OUT_DIR, `${folderPrefix}.zip`);
    const zipBuf = buildZipBuffer(entries);
    fs.writeFileSync(outPath, zipBuf);
    console.log(`Built ${path.basename(outPath)} (${entries.length} files, ${(zipBuf.length / 1024).toFixed(1)} KB)`);
  }
}

main();
