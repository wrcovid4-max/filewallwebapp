// app.js — bootstrap. Feature-detect, register the service worker, then hand off
// to the UI. If the platform can't run FileWall, say exactly what is missing
// rather than presenting a half-working vault.

import { init as initUI } from './ui.js';

function detectMissing() {
  const missing = [];
  if (!('storage' in navigator) || !navigator.storage.getDirectory) {
    missing.push('Origin Private File System (OPFS) — needed to store your encrypted files');
  }
  if (!('indexedDB' in window)) missing.push('IndexedDB — needed for file metadata');
  if (!('crypto' in window) || !crypto.subtle) missing.push('Web Crypto (SubtleCrypto) — needed to encrypt files');
  if (typeof Worker === 'undefined') missing.push('Web Workers — needed for fast, non-blocking crypto');
  return missing;
}

async function main() {
  const missing = detectMissing();
  if (missing.length) {
    const gate = document.getElementById('unsupported');
    const list = document.getElementById('missing-features');
    list.innerHTML = missing.map((m) => `<li>${m}</li>`).join('');
    gate.classList.remove('hidden');
    return;
  }

  document.getElementById('app').classList.remove('hidden');

  // Service worker: powers offline + /vault-stream video. Registered as a module
  // so it can import the shared crypto/idb/config code. Non-fatal if it fails
  // (streaming video degrades, but everything else still works).
  if ('serviceWorker' in navigator) {
    try {
      await navigator.serviceWorker.register('./sw.js', { type: 'module' });
      await navigator.serviceWorker.ready;
    } catch (err) {
      console.warn('Service worker registration failed:', err);
    }
  }

  try {
    await initUI();
  } catch (err) {
    console.error(err);
    const gate = document.getElementById('unsupported');
    document.getElementById('missing-features').innerHTML = `<li>${String(err.message || err)}</li>`;
    document.querySelector('#unsupported h1').textContent = 'FileWall failed to start';
    document.getElementById('app').classList.add('hidden');
    gate.classList.remove('hidden');
  }
}

main();
