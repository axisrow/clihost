// Executable tests for app/assets/tab_fix_script.html — the script injected
// into ttyd's iframe. Covers the paste/drop triage: text must reach the
// terminal (the #66 regression), images must still upload, non-image files
// must be skipped without typing a file:// URL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runAssetScript,
  makeFakeTerm,
  makeFakeSocket,
  makeDataTransfer,
  makeImageFile,
  makeImageItems,
} from './harness.mjs';

const ASSET = 'tab_fix_script.html';

// Install a terminal + socket + fetch before running the asset, then return the
// fakes plus a helper to dispatch a real DOM event through the capture-phase
// listeners the asset registers on `document`.
function bootIframe({ term = makeFakeTerm(), socket = makeFakeSocket() } = {}) {
  const uploads = [];
  const ctx = runAssetScript(ASSET, {
    setup(window) {
      window.term = term;
      window._ttydSocket = socket;
      // jsdom has no real fetch; record upload calls instead.
      window.fetch = (url, opts) => {
        uploads.push({ url, opts });
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ path: '/home/hapi/.uploads/x.png' }),
        });
      };
      // CSRF cookie the uploader reads.
      window.document.cookie = 'csrf_token=tok123';
    },
  });
  return { ...ctx, term, socket, uploads };
}

function dispatchPaste(window, dataTransfer) {
  const ev = new window.Event('paste', { bubbles: true, cancelable: true });
  ev.clipboardData = dataTransfer;
  window.document.dispatchEvent(ev);
  return ev;
}

function dispatchDrop(window, dataTransfer) {
  const ev = new window.Event('drop', { bubbles: true, cancelable: true });
  ev.dataTransfer = dataTransfer;
  window.document.dispatchEvent(ev);
  return ev;
}

test('iframe paste of plain text reaches the terminal (desktop Ctrl/Cmd+V)', () => {
  const { window, term } = bootIframe();
  // __handleDataTransfer is the entry the parent forwards to AND models a
  // text paste that the iframe must not drop.
  const consumed = window.__handleDataTransfer(makeDataTransfer({ text: 'hello world' }));
  assert.equal(consumed, true, 'text transfer must be consumed');
  assert.deepEqual(term.pasted, ['hello world'], 'text must be typed into term');
});

test('iframe drop of plain text falls through to native xterm (not preventDefault)', () => {
  // Text drops must reach xterm's own drop handling — the script must neither
  // type the text itself nor suppress the native path (regression #66).
  const { window, term } = bootIframe();
  const ev = dispatchDrop(window, makeDataTransfer({ text: 'dropped text' }));
  assert.equal(ev.defaultPrevented, false, 'text drop must not be preventDefault()ed');
  assert.deepEqual(term.pasted, [], 'the script must not type the dropped text itself');
});

test('pasted image still uploads to /upload (regression guard for #53)', () => {
  const { window, uploads } = bootIframe();
  const img = makeImageFile('image/png');
  const dt = makeDataTransfer({ files: [img], items: makeImageItems([img]) });
  const ev = dispatchPaste(window, dt);
  assert.equal(uploads.length, 1, 'one upload POST expected');
  assert.equal(uploads[0].url, '/upload');
  assert.ok(ev.defaultPrevented, 'image paste must preventDefault to stop xterm');
});

test('non-image file paste is skipped, never typed as a file URL', () => {
  const { window, term } = bootIframe();
  const pdf = { type: 'application/pdf', name: 'doc.pdf' };
  // Browser exposes both a file and a text/plain (file:// URL) representation.
  const dt = makeDataTransfer({
    text: 'file:///private/var/doc.pdf',
    files: [pdf],
    items: makeImageItems([pdf]),
  });
  const consumed = window.__handleDataTransfer(dt);
  assert.equal(consumed, false, 'non-image file transfer must not be consumed');
  assert.deepEqual(term.pasted, [], 'the file:// URL must NOT be typed');
});

test('empty clipboard text is a no-op (iOS Safari getData quirk)', () => {
  const { window, term } = bootIframe();
  const consumed = window.__handleDataTransfer(makeDataTransfer({ text: '' }));
  assert.equal(consumed, false);
  assert.deepEqual(term.pasted, []);
});

// --- Drop preventDefault must be conditional (adjacent bug from the diagnosis) ---
// A bare text drop that the triage does not consume should NOT be swallowed by
// an unconditional preventDefault — otherwise the browser's native handling is
// killed while nothing replaces it.
test('drop only prevents default when the transfer was actually handled', () => {
  const { window, term } = bootIframe({ term: { ...makeFakeTerm(), paste: undefined } });
  // No term.paste and no socket → text cannot be handled.
  window._ttydSocket = makeFakeSocket(0); // socket not open
  const empty = makeDataTransfer({ text: '' });
  const ev = dispatchDrop(window, empty);
  assert.equal(ev.defaultPrevented, false,
    'unhandled drop must leave default behavior intact');
});
