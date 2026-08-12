// sw.js — service worker (registered as a module).
//
// Two jobs:
//   1. Precache the app shell so FileWall opens offline after the first visit.
//   2. Intercept GET /vault-stream/<fileId>, honour the HTTP Range header, and
//      stream back 206 Partial Content with only the requested bytes decrypted.
//      This is how <video src="/vault-stream/id"> gets native seeking/buffering
//      without ever materialising the whole plaintext — the web counterpart to
//      the Android custom DataSource / iOS AVAssetResourceLoaderDelegate.
//
// We NEVER put vault content in the Cache Storage API — that would be a plaintext
// copy sitting in a place nothing else wipes. Only the static shell is cached.

import {
  VAULT_MAIN, VAULT_HIDDEN, STORE_KEYS, STORE_FILES, CHUNK_SIZE, ENC_CHUNK_SIZE,
} from './js/config.js';
import { parseHeader, openChunk, chunkCiphertextOffset, HEADER_SIZE } from './js/crypto.js';
import { kvGet, getRecord } from './js/idb.js';

const CACHE = 'filewall-shell-v2';
const SHELL = [
  './', './index.html', './manifest.json',
  './css/styles.css',
  './js/config.js', './js/crypto.js', './js/idb.js', './js/storage.js',
  './js/worker.js', './js/app.js', './js/ui.js', './js/archive.js', './js/webauthn.js',
  './icons/shield.svg', './icons/icon-192.png', './icons/icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

// In-memory key registry. The main vault key is read from IndexedDB on demand
// (it's a persisted non-extractable handle). The hidden key is pushed here by
// the page after a successful unlock and dropped on lock — never persisted here.
const sessionKeys = new Map();

self.addEventListener('message', (e) => {
  const msg = e.data || {};
  if (msg.type === 'set-key' && msg.vault && msg.key) sessionKeys.set(msg.vault, msg.key);
  if (msg.type === 'drop-key' && msg.vault) sessionKeys.delete(msg.vault);
});

async function keyFor(vault) {
  if (vault === VAULT_HIDDEN) return sessionKeys.get(VAULT_HIDDEN) || null;
  const cached = sessionKeys.get(VAULT_MAIN);
  if (cached) return cached;
  const k = await kvGet(STORE_KEYS, VAULT_MAIN);
  if (k) sessionKeys.set(VAULT_MAIN, k);
  return k || null;
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin === self.location.origin && url.pathname.includes('/vault-stream/')) {
    e.respondWith(handleStream(e.request, url));
    return;
  }
  // Shell: NETWORK-FIRST so a freshly-served update always wins, with the cache
  // as the offline fallback. (Cache-first caused stale files to persist after an
  // update until the SW was manually unregistered.) We refresh the cache on every
  // successful fetch so the latest shell is available offline next time.
  if (e.request.method === 'GET' && url.origin === self.location.origin) {
    e.respondWith((async () => {
      try {
        const res = await fetch(e.request);
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        }
        return res;
      } catch {
        // Offline — serve from cache; for navigations fall back to the shell index.
        const cached = await caches.match(e.request, { ignoreSearch: true });
        if (cached) return cached;
        if (e.request.mode === 'navigate') return caches.match('./index.html');
        throw new Error('offline');
      }
    })());
  }
});

async function handleStream(request, url) {
  const fileId = url.pathname.split('/vault-stream/')[1];
  const rec = await getRecord(STORE_FILES, fileId);
  if (!rec) return new Response('Not found', { status: 404 });
  const vault = rec.hidden ? VAULT_HIDDEN : VAULT_MAIN;
  const key = await keyFor(vault);
  if (!key) return new Response('Vault locked', { status: 403 });

  let dir, fileHandle, opfsFile;
  try {
    const root = await navigator.storage.getDirectory();
    dir = await root.getDirectoryHandle('blobs');
    fileHandle = await dir.getFileHandle(rec.blobId);
    opfsFile = await fileHandle.getFile();
  } catch {
    return new Response('Blob missing', { status: 404 });
  }

  // Read the header to learn base nonce, chunk size and true plaintext size.
  const headerBytes = new Uint8Array(await opfsFile.slice(0, HEADER_SIZE).arrayBuffer());
  const { baseNonce, plaintextSize } = parseHeader(headerBytes);
  const mime = rec.mime || 'application/octet-stream';

  const rangeHeader = request.headers.get('Range');
  let start = 0;
  let end = plaintextSize - 1;
  let partial = false;
  if (rangeHeader) {
    const m = /bytes=(\d*)-(\d*)/.exec(rangeHeader);
    if (m) {
      partial = true;
      if (m[1]) start = parseInt(m[1], 10);
      if (m[2]) end = Math.min(parseInt(m[2], 10), plaintextSize - 1);
      if (!m[1] && m[2]) { // suffix range: last N bytes
        start = Math.max(0, plaintextSize - parseInt(m[2], 10));
        end = plaintextSize - 1;
      }
    }
  }
  if (start > end || start >= plaintextSize) {
    return new Response('Range Not Satisfiable', {
      status: 416,
      headers: { 'Content-Range': `bytes */${plaintextSize}` },
    });
  }

  const firstChunk = Math.floor(start / CHUNK_SIZE);
  const lastChunk = Math.floor(end / CHUNK_SIZE);
  const bodyLen = end - start + 1;

  // Stream chunk by chunk so we never hold more than ~1 decrypted chunk.
  const stream = new ReadableStream({
    async pull(controller) {
      try {
        for (let i = firstChunk; i <= lastChunk; i++) {
          const cipherStart = chunkCiphertextOffset(i);
          const cipherEnd = Math.min(cipherStart + ENC_CHUNK_SIZE, opfsFile.size);
          const cipher = new Uint8Array(await opfsFile.slice(cipherStart, cipherEnd).arrayBuffer());
          const plain = await openChunk(key, baseNonce, i, cipher);
          const chunkPlainStart = i * CHUNK_SIZE;
          const sliceStart = Math.max(0, start - chunkPlainStart);
          const sliceEnd = Math.min(plain.length, end - chunkPlainStart + 1);
          controller.enqueue(plain.subarray(sliceStart, sliceEnd));
        }
        controller.close();
      } catch (err) {
        controller.error(err);
      }
    },
  });

  const headers = {
    'Content-Type': mime,
    'Accept-Ranges': 'bytes',
    'Content-Length': String(bodyLen),
    'Cache-Control': 'no-store',
  };
  if (partial) {
    headers['Content-Range'] = `bytes ${start}-${end}/${plaintextSize}`;
    return new Response(stream, { status: 206, headers });
  }
  return new Response(stream, { status: 200, headers });
}
