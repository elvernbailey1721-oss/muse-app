// Mobile-shell web build:
//   1. tsc -> www/js/          (src/*.ts compiled, type-only imports erased)
//   2. Replace the __PAINTSCOPE_API_URL_BUILD__ build token in www/js/*.js
//      with $PAINTSCOPE_API_URL (default http://localhost:3000).
//   3. Inject <script type="module" src="js/main.js"> before </body> in
//      www/index.html (idempotent).
//   4. Extend the CSP meta tag minimally so the shell additions work:
//        script-src += 'self'          (allow the js/main.js module script;
//                                       the existing inline-script hash stays)
//        connect-src += <api origin>   (allow API calls to the backend)
//      Everything else in the CSP is left byte-identical.
// Usage: node tools/build-web.mjs
// Run AFTER tools/extract-media.mjs (which regenerates www/index.html).

import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WWW = join(ROOT, 'www');
const JS = join(WWW, 'js');

const API_URL = process.env.PAINTSCOPE_API_URL || 'http://localhost:3000';
let API_ORIGIN = API_URL;
try {
  API_ORIGIN = new URL(API_URL).origin;
} catch { /* keep raw value */ }

// 1. Compile.
execSync('npx tsc', { cwd: ROOT, stdio: 'inherit' });

// 2. Build-time API URL replacement (exact build token only — never the
// runtime window property name).
const TOKEN = '__PAINTSCOPE_API_URL_BUILD__';
let replaced = 0;
for (const f of readdirSync(JS)) {
  if (!f.endsWith('.js')) continue;
  const p = join(JS, f);
  const src = readFileSync(p, 'utf8');
  if (src.includes(TOKEN)) {
    writeFileSync(p, src.split(TOKEN).join(JSON.stringify(API_URL)));
    replaced++;
  }
}

// 2b. Syntax-gate every emitted file (catches bad token replacements).
for (const f of readdirSync(JS)) {
  if (!f.endsWith('.js')) continue;
  execSync(`node --check ${JSON.stringify(join(JS, f))}`, { stdio: 'pipe' });
}
const INDEX = join(WWW, 'index.html');
if (!existsSync(INDEX)) throw new Error('www/index.html missing — run tools/extract-media.mjs first');
let html = readFileSync(INDEX, 'utf8');

const BRIDGE_TAG = '<script type="module" src="js/main.js"></script>';
let injected = false;
if (!html.includes(BRIDGE_TAG)) {
  if (!html.includes('</body>')) throw new Error('no </body> in index.html');
  html = html.replace('</body>', `  ${BRIDGE_TAG}\n</body>`);
  injected = true;
}

let cspChanged = false;
html = html.replace(
  /<meta([^>]*?)http-equiv="Content-Security-Policy"([^>]*?)content="([^"]*)"([^>]*?)>/i,
  (full, pre1, pre2, content, post) => {
    let c = content;
    if (!c.includes(`script-src 'self'`)) {
      c = c.replace('script-src ', `script-src 'self' `);
      cspChanged = true;
    }
    // connect-src: normalize to exactly `'self'` + current API origin, so
    // rebuilding with a different $PAINTSCOPE_API_URL replaces the old
    // origin instead of accumulating stale ones.
    c = c.replace(/connect-src 'self'[^;]*/, (m) => {
      const want = `connect-src 'self' ${API_ORIGIN}`;
      if (m === want) return m;
      cspChanged = true;
      return want;
    });
    return `<meta${pre1}http-equiv="Content-Security-Policy"${pre2}content="${c}"${post}>`;
  }
);

writeFileSync(INDEX, html);
console.log(JSON.stringify({
  apiUrl: API_URL,
  apiOrigin: API_ORIGIN,
  tokenReplacedInFiles: replaced,
  bridgeInjected: injected,
  cspExtended: cspChanged,
}, null, 2));
console.log('OK: web build complete.');
