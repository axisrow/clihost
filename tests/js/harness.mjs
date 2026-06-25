// Shared jsdom harness for the terminal paste/clipboard assets (issue #66).
//
// These tests execute the REAL JavaScript shipped in app/assets/*.html — they
// extract the <script> body from each asset and run it inside a jsdom window so
// that synthesized paste/drop events flow through the actual production code.
// The previous Python tests only grep the asset strings; they never proved that
// pasted text reaches the terminal, which is exactly how the #53/#54 regression
// slipped through.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { JSDOM, VirtualConsole } from 'jsdom';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, '..', '..', 'app', 'assets');

export function readAsset(name) {
  return readFileSync(join(ASSETS_DIR, name), 'utf8');
}

// Pull the executable body out of a `<script>...</script>` asset.
export function extractScript(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) throw new Error('no <script> block found in asset');
  return m[1];
}

// A minimal fake xterm.js terminal. Records text typed via term.paste so a test
// can assert that pasted text actually reached the terminal.
export function makeFakeTerm() {
  const pasted = [];
  return {
    pasted,
    paste(text) { pasted.push(text); },
    buffer: { active: { type: 'normal' } },
    rows: 24,
    scrollLines() {},
    input() {},
    _core: { coreService: { triggerDataEvent() {} } },
  };
}

// A fake ttyd WebSocket that records every raw frame the page sends. ttyd's
// protocol prefixes input frames with '0', so sent.text() strips that.
export function makeFakeSocket(readyState = 1) {
  const frames = [];
  return {
    frames,
    readyState,
    send(frame) { frames.push(frame); },
    // text typed via the raw socket path (strip the ttyd '0' INPUT prefix)
    inputs() {
      return frames
        .filter((f) => typeof f === 'string' && f[0] === '0')
        .map((f) => f.slice(1));
    },
  };
}

// Build a clipboard/data-transfer stub. `text` is what getData('text/plain')
// returns; `files`/`items` model image (or other) file payloads. Pass
// text:null to model the iOS-Safari "empty clipboardData" quirk.
export function makeDataTransfer({ text = '', files = [], items = null } = {}) {
  const dt = {
    getData(type) {
      if (type === 'text/plain') return text == null ? '' : text;
      return '';
    },
    files,
  };
  if (text == null) {
    // iOS Safari paste gesture: clipboardData present but getData throws/empty.
    dt.getData = () => '';
  }
  if (items !== null) dt.items = items;
  return dt;
}

// Model a single image file the way the DOM exposes it to extractImageFiles:
// either via DataTransferItemList (.items) or the flat .files list.
export function makeImageFile(type = 'image/png') {
  const file = { type, name: 'pasted.png' };
  return file;
}

export function makeImageItems(files) {
  return files.map((f) => ({
    kind: 'file',
    type: f.type,
    getAsFile: () => f,
  }));
}

// Run an asset's script inside a fresh jsdom window. Returns { window, dom }.
// `setup(window)` runs BEFORE the script so a test can pre-install fakes
// (window.term, navigator.clipboard, fetch, iframe, …).
export function runAssetScript(assetName, { setup, html } = {}) {
  const virtualConsole = new VirtualConsole();
  const logs = [];
  virtualConsole.on('warn', (...a) => logs.push(['warn', ...a]));
  virtualConsole.on('log', (...a) => logs.push(['log', ...a]));

  const dom = new JSDOM(html || '<!DOCTYPE html><html><body></body></html>', {
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    virtualConsole,
  });
  const { window } = dom;
  window.logs = logs;
  installMissingDomShims(window);

  if (setup) setup(window);

  const code = extractScript(readAsset(assetName));
  // Execute the asset's IIFE in the window's realm.
  window.eval(code);

  return { window, dom, logs };
}

// jsdom omits a few browser APIs the assets touch (matchMedia). Shim only what
// is missing so the asset's own code runs unchanged — never to mask a bug.
export function installMissingDomShims(window) {
  if (!window.matchMedia) {
    window.matchMedia = (query) => ({
      matches: false,
      media: query,
      addListener() {},
      removeListener() {},
      addEventListener() {},
      removeEventListener() {},
    });
  }
  if (!window.requestAnimationFrame) {
    window.requestAnimationFrame = (cb) => setTimeout(() => cb(0), 0);
  }
}

// Execute the REAL tab_fix_script.html inside an iframe's contentWindow so that
// parent-page tests forward into the genuine triage logic instead of a fake.
// Returns the iframe window plus the term/socket fakes wired into it.
export function bootIframeScript(window, { term = makeFakeTerm(),
                                          socket = makeFakeSocket(),
                                          onUpload } = {}) {
  const iframe = window.document.getElementById('terminal');
  const iframeWin = iframe.contentWindow;
  installMissingDomShims(iframeWin);
  iframeWin.term = term;
  iframeWin._ttydSocket = socket;
  iframeWin.document.cookie = 'csrf_token=tok123';
  iframeWin.fetch = (url, opts) => {
    if (onUpload) onUpload({ url, opts });
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ path: '/home/hapi/.uploads/x.png' }),
    });
  };
  iframeWin.eval(extractScript(readAsset('tab_fix_script.html')));
  return { iframeWin, term, socket };
}
