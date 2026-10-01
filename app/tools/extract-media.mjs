// Extracts inlined base64 application/octet-stream media blobs from the
// exported PaintScope single-file HTML into www/media/ files and rewrites
// the references to relative paths. Verifies every blob by SHA-256.
//
// Usage: node tools/extract-media.mjs
// Idempotent: re-running reproduces identical output.

import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = '/home/hatch/workspace/your_files/paintscope/paintscope.html';
const WWW = join(ROOT, 'www');
const MEDIA = join(WWW, 'media');

const slug = (s) =>
  s.toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

const sniffExt = (buf) => {
  const head = buf.subarray(0, 16);
  if (head[0] === 0x49 && head[1] === 0x44 && head[2] === 0x33) return '.mp3'; // ID3
  if (head[0] === 0xff && (head[1] & 0xe0) === 0xe0) return '.mp3'; // MP3 frame sync
  if (head.subarray(4, 8).toString('latin1') === 'ftyp') return '.mp4';
  throw new Error('unknown media magic: ' + head.subarray(0, 8).toString('hex'));
};

const html = readFileSync(SRC, 'utf8');
const re = /data:application\/octet-stream;base64,([A-Za-z0-9+/=]+)/g;

// Pass 1: collect matches with context-derived names.
const matches = [];
let m;
while ((m = re.exec(html))) {
  const before = html.slice(Math.max(0, m.index - 120), m.index);
  const trackName = before.match(/\['([^']+)','$/);
  const station = before.match(/(\w+):\[\[$/) || before.match(/(\w+):\[\['/);
  let kind, name, stationName = 'misc';
  if (before.includes('speakerPrimer')) {
    kind = 'primer'; name = 'speaker-primer';
  } else if (before.includes('radioAudio')) {
    kind = 'radio-src'; name = 'radio-initial';
  } else if (before.includes('origin story')) {
    kind = 'video'; name = 'origin-story';
  } else if (before.includes('videoFallback')) {
    kind = 'video-fallback'; name = 'origin-story';
  } else if (trackName) {
    kind = 'track'; name = slug(trackName[1]);
  } else {
    kind = 'unknown'; name = 'asset-' + matches.length;
  }
  matches.push({ index: m.index, full: m[0], b64: m[1], kind, name, stationName, before });
}

// Derive station for tracks by scanning the radioLibrary literal ranges.
const libStart = html.indexOf('var radioLibrary={');
const stationRanges = [];
{
  const stations = ['jazz', 'calm', 'uplifting', 'lofi', 'classical', 'diy'];
  for (const s of stations) {
    const i = html.indexOf(s + ':[', libStart);
    stationRanges.push({ s, i });
  }
  stationRanges.sort((a, b) => a.i - b.i);
}
for (const mt of matches) {
  if (mt.kind === 'track') {
    let st = 'misc';
    for (const r of stationRanges) if (mt.index > r.i) st = r.s;
    mt.stationName = st;
  }
}

// Pass 2: decode, dedupe by content hash, write files.
// Track entries are written FIRST so byte-duplicate non-track references
// (e.g. the radio <audio> element's initial src) reuse the meaningful
// track filename instead of claiming it.
mkdirSync(MEDIA, { recursive: true });
rmSync(MEDIA, { recursive: true, force: true }); // re-run safety: drop stale files
mkdirSync(MEDIA, { recursive: true });
const hashToPath = new Map();
const manifest = [];
const orderedPaths = new Array(matches.length);

const writeMatch = (i) => {
  const mt = matches[i];
  const buf = Buffer.from(mt.b64, 'base64');
  const hash = sha256(buf);
  // sanity: decoded length must match base64 length expectation
  const expected = Math.floor((mt.b64.replace(/=+$/, '').length * 3) / 4);
  if (Math.abs(buf.length - expected) > 2) {
    throw new Error(`length mismatch at match ${i}: got ${buf.length}, expected ~${expected}`);
  }
  const ext = sniffExt(buf);
  let rel;
  if (hashToPath.has(hash)) {
    rel = hashToPath.get(hash); // byte-identical duplicate: reuse one file
  } else {
    rel = mt.kind === 'track'
      ? `media/radio/${mt.stationName}/${mt.name}${ext}`
      : `media/${mt.name}${ext}`;
    const dest = join(WWW, rel);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, buf);
    hashToPath.set(hash, rel);
    manifest.push({ file: rel, bytes: buf.length, sha256: hash, matchIndex: i, kind: mt.kind });
  }
  orderedPaths[i] = rel;
};

for (let i = 0; i < matches.length; i++) if (matches[i].kind === 'track') writeMatch(i);
for (let i = 0; i < matches.length; i++) if (matches[i].kind !== 'track') writeMatch(i);

// Pass 3: rewrite references (regex matches in the same order).
let n = 0;
const out = html.replace(/data:application\/octet-stream;base64,[A-Za-z0-9+/=]+/g, () => orderedPaths[n++]);
if (n !== matches.length) throw new Error(`replaced ${n}, expected ${matches.length}`);
if (out.includes('data:application/octet-stream')) throw new Error('unreplaced data URI remains');

// Pass 4: verify — re-read every written file, compare hashes; confirm all refs resolve.
for (const e of manifest) {
  const buf = readFileSync(join(WWW, e.file));
  if (sha256(buf) !== e.sha256) throw new Error(`hash mismatch on re-read: ${e.file}`);
  if (buf.length !== e.bytes) throw new Error(`size mismatch on re-read: ${e.file}`);
}
const refRe = /(src|href)="media\/[^"]+"/g;
const refs = new Set();
let rm;
while ((rm = refRe.exec(out))) refs.add(rm[0].split('"')[1]);
for (const r of refs) {
  if (!existsSync(join(WWW, r))) throw new Error(`referenced file missing: ${r}`);
}

mkdirSync(WWW, { recursive: true });
writeFileSync(join(WWW, 'index.html'), out);
writeFileSync(join(MEDIA, 'MANIFEST.json'), JSON.stringify({
  source: 'paintscope.html (exported 2026-09-29)',
  extractedAt: new Date().toISOString(),
  matches: matches.length,
  uniqueFiles: manifest.length,
  duplicatesDeduped: matches.length - manifest.length,
  files: manifest,
}, null, 2));

const totalMedia = manifest.reduce((a, e) => a + e.bytes, 0);
console.log(JSON.stringify({
  matches: matches.length,
  uniqueFiles: manifest.length,
  duplicatesDeduped: matches.length - manifest.length,
  totalMediaBytes: totalMedia,
  indexHtmlBytes: Buffer.byteLength(out, 'utf8'),
  distinctMediaRefsInHtml: refs.size,
  kinds: [...new Set(manifest.map((e) => e.kind))],
}, null, 2));
console.log('OK: all hashes verified, all references resolve.');
