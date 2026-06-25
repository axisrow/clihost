// Executable tests for app/assets/terminal_parent_tab_handler.html — the script
// that runs on the PARENT terminal page (the one hosting the ttyd iframe).
//
// This is the primary culprit of the #66 text-paste regression: on mobile the
// iframe is not focused, so the paste event lands on the parent. The parent
// forwarded the transfer into the iframe's __handleDataTransfer and then
// preventDefault()'d the native path — but getData('text/plain') is empty on
// the iOS paste gesture, so the text was lost AND the native xterm path was
// suppressed.
//
// These tests run the REAL tab_fix_script.html inside the iframe's
// contentWindow, so the parent forwards into the genuine triage logic — no
// stubbed iframe API that could hide the regression.
//
// Desired behavior (matching pre-#53): the parent must only intercept IMAGES.
// Plain text must fall through to xterm's native handling untouched.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  readAsset,
  extractScript,
  installMissingDomShims,
  bootIframeScript,
  makeFakeTerm,
  makeFakeSocket,
  makeDataTransfer,
  makeImageFile,
  makeImageItems,
} from './harness.mjs';
import { JSDOM, VirtualConsole } from 'jsdom';

const ASSET = 'terminal_parent_tab_handler.html';

// Boot a parent page with a real iframe whose contentWindow runs the genuine
// injected tab_fix_script. Returns the parent window plus the iframe fakes.
function bootParent({ term = makeFakeTerm(), socket = makeFakeSocket() } = {}) {
  const vc = new VirtualConsole();
  const dom = new JSDOM(
    '<!DOCTYPE html><html><body><iframe id="terminal"></iframe></body></html>',
    { runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc },
  );
  const { window } = dom;
  installMissingDomShims(window);

  const uploads = [];
  bootIframeScript(window, { term, socket, onUpload: (u) => uploads.push(u) });

  window.eval(extractScript(readAsset(ASSET)));
  return { window, term, socket, uploads };
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

test('parent paste of plain text does NOT preventDefault (native xterm path)', () => {
  const { window, term } = bootParent();
  const ev = dispatchPaste(window, makeDataTransfer({ text: 'typed on parent' }));
  assert.equal(ev.defaultPrevented, false,
    'parent must let plain-text paste reach the native handler');
  assert.deepEqual(term.pasted, [],
    'parent must NOT route text through the fragile pasteTextToTerminal path');
});

test('mobile paste gesture (empty getData) is not swallowed by the parent', () => {
  // iOS Safari: clipboardData present, getData('text/plain') returns ''.
  const { window } = bootParent();
  const ev = dispatchPaste(window, makeDataTransfer({ text: '' }));
  assert.equal(ev.defaultPrevented, false,
    'an empty/text-only paste must not be preventDefault()ed on the parent');
});

test('parent paste of an image still forwards to the iframe and uploads', () => {
  const img = makeImageFile('image/png');
  const dt = makeDataTransfer({ files: [img], items: makeImageItems([img]) });
  const { window, uploads } = bootParent();
  const ev = dispatchPaste(window, dt);
  assert.equal(uploads.length, 1, 'image transfer must reach /upload via the iframe');
  assert.equal(ev.defaultPrevented, true, 'a handled image paste preventDefaults');
});

test('parent drop of plain text does not prevent default', () => {
  const { window } = bootParent();
  const ev = dispatchDrop(window, makeDataTransfer({ text: 'plain drop' }));
  assert.equal(ev.defaultPrevented, false,
    'unhandled parent drop must not be preventDefault()ed');
});

test('parent drop of a handled image preventDefaults', () => {
  const img = makeImageFile('image/png');
  const dt = makeDataTransfer({ files: [img], items: makeImageItems([img]) });
  const { window, uploads } = bootParent();
  const ev = dispatchDrop(window, dt);
  assert.equal(uploads.length, 1);
  assert.equal(ev.defaultPrevented, true);
});
