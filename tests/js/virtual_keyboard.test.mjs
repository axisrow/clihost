// Executable tests for the ^V button in app/assets/virtual_keyboard.html.
//
// The ^V button is the dedicated mobile paste path. The pre-fix version read
// navigator.clipboard.readText() and sent a raw socket.send('0'+text) — which
// (a) silently swallowed a readText() rejection in .catch, (b) bypassed
// bracketed paste, and (c) lost text entirely when window._ttydSocket was not
// ready. These tests pin the hardened behavior: term.paste() preferred, and the
// text not lost when readText resolves.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  readAsset,
  extractScript,
  installMissingDomShims,
  makeFakeTerm,
  makeFakeSocket,
} from './harness.mjs';
import { JSDOM, VirtualConsole } from 'jsdom';

const VKBD_ASSET = 'virtual_keyboard.html';

// The vkbd asset is a fragment, not a full <script> page document — it has the
// markup, then a <script>. Build a terminal page around it with a real iframe
// whose contentWindow carries term + socket (like the injected tab_fix_script).
function bootVkbd({ clipboardText = 'CLIP', readTextRejects = false,
                    term = makeFakeTerm(), socket = makeFakeSocket() } = {}) {
  const vc = new VirtualConsole();
  const dom = new JSDOM(
    `<!DOCTYPE html><html><body>
       <div id="terminal-shell"><iframe id="terminal"></iframe></div>
     </body></html>`,
    { runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc },
  );
  const { window } = dom;
  window.logs = [];
  vc.on('warn', (...a) => window.logs.push(['warn', ...a]));
  vc.on('log', (...a) => window.logs.push(['log', ...a]));
  installMissingDomShims(window);

  // Inject the vkbd markup (buttons) so getElementById('vkbd') etc. resolve.
  const asset = readAsset(VKBD_ASSET);
  const markup = asset.slice(0, asset.indexOf('<script>'));
  // The toggle button + #vkbd container live in the markup; drop it into body.
  const holder = window.document.createElement('div');
  holder.innerHTML = markup;
  while (holder.firstChild) window.document.body.appendChild(holder.firstChild);

  // Wire the iframe's contentWindow to look like a live terminal.
  const iframe = window.document.getElementById('terminal');
  const iframeWin = iframe.contentWindow;
  iframeWin.term = term;
  iframeWin._ttydSocket = socket;
  // In production, tab_fix_script.html (injected INTO the iframe) exports
  // __sendToTTYD; the vkbd delegates to it instead of an inline socket copy
  // (#101/#14). The fake iframe doesn't run that script, so provide the same
  // exported helper here — it owns socket discovery + the '0' INPUT prefix.
  iframeWin.__sendToTTYD = (data) => {
    const s = iframeWin._ttydSocket || iframeWin.socket || iframeWin.ws;
    if (s && s.readyState === 1) {
      s.send('0' + data);
      return true;
    }
    return false;
  };
  // jsdom's textarea focus path needs the helper textarea to exist.
  const ta = iframeWin.document.createElement('textarea');
  ta.className = 'xterm-helper-textarea';
  iframeWin.document.body.appendChild(ta);

  // Clipboard mock.
  window.navigator.clipboard = {
    readText: () =>
      readTextRejects
        ? Promise.reject(new Error('NotAllowedError'))
        : Promise.resolve(clipboardText),
  };

  window.eval(extractScript(asset));
  return { window, iframe, iframeWin, term, socket };
}

function clickKey(window, key) {
  const btn = window.document.querySelector(`[data-key="${key}"]`);
  assert.ok(btn, `button [data-key="${key}"] must exist`);
  btn.dispatchEvent(new window.Event('click', { bubbles: true }));
}

const tick = () => new Promise((r) => setTimeout(r, 0));

test('^V types clipboard text into the terminal via term.paste (bracketed paste)', async () => {
  const { window, term } = bootVkbd({ clipboardText: 'pasted via vkbd' });
  clickKey(window, 'ctrl-v');
  await tick();
  await tick();
  assert.deepEqual(term.pasted, ['pasted via vkbd'],
    '^V must deliver clipboard text through term.paste');
});

test('^V falls back to the raw socket when term.paste is unavailable', async () => {
  const term = makeFakeTerm();
  term.paste = undefined; // older xterm / not ready
  const socket = makeFakeSocket();
  const { window } = bootVkbd({ clipboardText: 'fallback text', term, socket });
  clickKey(window, 'ctrl-v');
  await tick();
  await tick();
  assert.deepEqual(socket.inputs(), ['fallback text'],
    '^V must fall back to socket.send when term.paste is missing');
});

test('^V readText rejection does not crash and types nothing', async () => {
  const { window, term, socket } = bootVkbd({ readTextRejects: true });
  clickKey(window, 'ctrl-v');
  await tick();
  await tick();
  assert.deepEqual(term.pasted, []);
  assert.deepEqual(socket.inputs(), []);
  // It must surface the failure somewhere (warn), not be fully silent.
  assert.ok(
    window.logs.some(([lvl]) => lvl === 'warn' || lvl === 'log'),
    'a readText rejection should be logged',
  );
});

test('^C still sends the interrupt byte (non-paste keys unaffected)', () => {
  const { window, socket } = bootVkbd();
  clickKey(window, 'ctrl-c');
  assert.deepEqual(socket.inputs(), [String.fromCharCode(3)]);
});
