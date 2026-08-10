// worker.js — the dedicated Web Worker that owns all file IO and bulk crypto.
//
// Why a worker: createSyncAccessHandle() (the fast OPFS path) is only available
// off the main thread, and decrypting a large file must never block the UI.
// The main thread posts requests; this worker does the encrypt/decrypt against
// OPFS and posts back results + progress. Plaintext lives here, transiently, and
// is handed back to the main thread only as a Blob when a viewer needs it.

import {
  OPFS_DIR, VAULT_MAIN, VAULT_HIDDEN, STORE_KEYS, STORE_META,
  CHUNK_SIZE, ENC_CHUNK_SIZE,
} from './config.js';
import {
  generateDataKey, buildHeader, parseHeader, sealChunk, openChunk,
  chunkCiphertextOffset, randomBytes, generateWrappableKeyBytes, wrapKeyBytes,
  unwrapKeyToDataKey, unwrapToRawBytes, importDataKey,
  deriveKeyFromPassphrase, deriveKeyFromPrf, uuid, HEADER_SIZE,
} from './crypto.js';
import { openDB, kvGet, kvPut } from './idb.js';
import { buildArchive, extractArchive, parseArchiveFrames } from './archive.js';

// Session key registry. Main vault key is persisted (non-extractable) and loaded
// lazily; the hidden key only exists here in memory after a successful unlock.
const keys = new Map(); // vault -> CryptoKey

let opfsRoot = null;
async function blobsDir() {
  if (!opfsRoot) {
    const root = await navigator.storage.getDirectory();
    opfsRoot = await root.getDirectoryHandle(OPFS_DIR, { create: true });
  }
  return opfsRoot;
}

// ---- key management -------------------------------------------------------

async function ensureMainKey() {
  if (keys.has(VAULT_MAIN)) return keys.get(VAULT_MAIN);
  await openDB();
  let key = await kvGet(STORE_KEYS, VAULT_MAIN);
  if (!key) {
    key = await generateDataKey();       // extractable:false, persisted as a handle
    await kvPut(STORE_KEYS, VAULT_MAIN, key);
  }
  keys.set(VAULT_MAIN, key);
  return key;
}

async function keyFor(vault) {
  if (vault === VAULT_HIDDEN) {
    const k = keys.get(VAULT_HIDDEN);
    if (!k) throw new Error('Hidden vault is locked');
    return k;
  }
  return ensureMainKey();
}

async function deriveWrappingKey(method, secret, salt, usages) {
  if (method === 'prf') return deriveKeyFromPrf(secret, salt, usages);
  return deriveKeyFromPassphrase(secret, salt, usages);
}

// Hidden-vault wraps are stored as a map keyed by unlock method, so the SAME
// hidden data key can be unlocked by either a passcode ('pass') or a passkey's
// PRF secret ('prf'). Each entry is one AES-GCM wrapping of the raw hidden key.
async function loadWraps() {
  return (await kvGet(STORE_META, 'hiddenWraps')) || {};
}
async function saveWraps(wraps) {
  await kvPut(STORE_META, 'hiddenWraps', wraps);
}

async function wrapUnder(method, secret, rawBytes) {
  const salt = randomBytes(16);
  const wrapKey = await deriveWrappingKey(method, secret, salt, ['encrypt']);
  const { iv, wrapped } = await wrapKeyBytes(wrapKey, rawBytes);
  return { method, salt, iv, wrapped, createdAt: Date.now() };
}

// Configure the hidden vault for the first time: mint a hidden data key, wrap it
// under the chosen method, persist only the wrapped bytes, keep the live
// (non-extractable) session key in memory.
async function setupHidden({ method, secret }) {
  const rawHidden = await generateWrappableKeyBytes();
  const entry = await wrapUnder(method, secret, rawHidden);
  await saveWraps({ [method]: entry });
  const sessionKey = await importDataKey(rawHidden);
  rawHidden.fill(0); // scrub the raw bytes from memory promptly
  keys.set(VAULT_HIDDEN, sessionKey);
  // Hand the session key back so the main thread can register it with the
  // service worker for hidden-video streaming right after first setup.
  return { method, key: sessionKey };
}

// Add another unlock method to an already-configured hidden vault. Requires an
// existing method+secret to recover the raw key, which is scrubbed after use.
async function addHiddenMethod({ unlockMethod, unlockSecret, newMethod, newSecret }) {
  const wraps = await loadWraps();
  const rec = wraps[unlockMethod];
  if (!rec) throw new Error('Cannot unlock to add method');
  const wrapKey = await deriveWrappingKey(rec.method, unlockSecret, rec.salt, ['decrypt']);
  let raw;
  try { raw = await unwrapToRawBytes(wrapKey, rec.iv, rec.wrapped); }
  catch { throw new Error('Wrong passcode'); }
  wraps[newMethod] = await wrapUnder(newMethod, newSecret, raw);
  await saveWraps(wraps);
  raw.fill(0);
  return { methods: Object.keys(wraps) };
}

async function removeHiddenMethod({ method }) {
  const wraps = await loadWraps();
  delete wraps[method];
  if (Object.keys(wraps).length === 0) {
    // No methods left => disable hidden vault entirely.
    await kvPut(STORE_META, 'hiddenWraps', {});
  } else {
    await saveWraps(wraps);
  }
  return { methods: Object.keys(wraps) };
}

async function unlockHidden({ method, secret }) {
  const wraps = await loadWraps();
  const rec = wraps[method];
  if (!rec) throw new Error('Hidden vault not configured for this method');
  const wrapKey = await deriveWrappingKey(rec.method, secret, rec.salt, ['decrypt']);
  let sessionKey;
  try {
    sessionKey = await unwrapKeyToDataKey(wrapKey, rec.iv, rec.wrapped);
  } catch {
    throw new Error('Wrong passcode'); // GCM auth failure == bad key
  }
  keys.set(VAULT_HIDDEN, sessionKey);
  return { key: sessionKey };
}

function lockHidden() {
  keys.delete(VAULT_HIDDEN);
}

// ---- file IO --------------------------------------------------------------

// Encrypt a source Blob into a fresh OPFS blob. Streams chunk-by-chunk so peak
// memory is ~1 chunk regardless of file size. Returns the blob's UUID name.
async function writeEncrypted(vault, srcBlob, onProgress) {
  const key = await keyFor(vault);
  const dir = await blobsDir();
  const blobId = uuid();
  const handle = await dir.getFileHandle(blobId, { create: true });
  const access = await handle.createSyncAccessHandle();
  try {
    const baseNonce = randomBytes(8);
    const total = srcBlob.size;
    const header = buildHeader(baseNonce, total);
    access.write(header, { at: 0 });
    let offset = HEADER_SIZE;
    const nChunks = Math.max(1, Math.ceil(total / CHUNK_SIZE));
    for (let i = 0; i < nChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(total, start + CHUNK_SIZE);
      const plain = new Uint8Array(await srcBlob.slice(start, end).arrayBuffer());
      const sealed = await sealChunk(key, baseNonce, i, plain);
      access.write(sealed, { at: offset });
      offset += sealed.byteLength;
      if (onProgress) onProgress(end, total);
    }
    access.flush();
    return { blobId, size: total };
  } finally {
    access.close();
  }
}

// Decrypt an entire blob back to a Blob (used for images, documents, export).
async function readDecrypted(vault, blobId, mime) {
  const key = await keyFor(vault);
  const dir = await blobsDir();
  const handle = await dir.getFileHandle(blobId);
  const access = await handle.createSyncAccessHandle();
  try {
    const size = access.getSize();
    const headerBuf = new Uint8Array(HEADER_SIZE);
    access.read(headerBuf, { at: 0 });
    const { baseNonce, plaintextSize } = parseHeader(headerBuf);
    const nChunks = Math.max(1, Math.ceil(plaintextSize / CHUNK_SIZE));
    const parts = [];
    let at = HEADER_SIZE;
    for (let i = 0; i < nChunks; i++) {
      const remainingCipher = size - at;
      const thisEnc = Math.min(ENC_CHUNK_SIZE, remainingCipher);
      const buf = new Uint8Array(thisEnc);
      access.read(buf, { at });
      at += thisEnc;
      const plain = await openChunk(key, baseNonce, i, buf);
      parts.push(plain);
    }
    return new Blob(parts, { type: mime || 'application/octet-stream' });
  } finally {
    access.close();
  }
}

async function deleteBlob(blobId) {
  if (!blobId) return;
  try {
    const dir = await blobsDir();
    await dir.removeEntry(blobId);
  } catch { /* already gone */ }
}

// Generate a downscaled thumbnail (image inputs only — video thumbnails are
// captured on the main thread and passed in). Kept in the worker so image
// plaintext never has to visit the main thread.
async function makeImageThumb(srcBlob, max = 320) {
  try {
    const bitmap = await createImageBitmap(srcBlob);
    const scale = Math.min(1, max / Math.max(bitmap.width, bitmap.height));
    const w = Math.max(1, Math.round(bitmap.width * scale));
    const h = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = new OffscreenCanvas(w, h);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0, w, h);
    bitmap.close();
    return await canvas.convertToBlob({ type: 'image/jpeg', quality: 0.72 });
  } catch {
    return null;
  }
}

// ---- RPC plumbing ---------------------------------------------------------

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  const reply = (result, transfer) => self.postMessage({ id, ok: true, result }, transfer || []);
  const fail = (err) => self.postMessage({ id, ok: false, error: String(err && err.message || err) });
  try {
    switch (op) {
      case 'init': {
        await ensureMainKey();
        const wraps = await loadWraps();
        const methods = Object.keys(wraps);
        reply({ ready: true, hasHidden: methods.length > 0, methods });
        break;
      }
      case 'setupHidden': reply(await setupHidden(args)); break;
      case 'addHiddenMethod': reply(await addHiddenMethod(args)); break;
      case 'removeHiddenMethod': reply(await removeHiddenMethod(args)); break;
      case 'unlockHidden': {
        const { key } = await unlockHidden(args);
        // Hand the session key back so the main thread can register it with the
        // service worker for hidden-video streaming. It stays non-extractable.
        reply({ ok: true, key });
        break;
      }
      case 'lockHidden': lockHidden(); reply({ ok: true }); break;
      case 'import': {
        const { vault, file, videoThumb, category } = args;
        const { blobId, size } = await writeEncrypted(vault, file, (loaded, total) => {
          self.postMessage({ id, progress: true, loaded, total });
        });
        let thumbId = null;
        let thumbBlob = videoThumb || null;
        if (!thumbBlob && category === 'photo') thumbBlob = await makeImageThumb(file);
        if (thumbBlob) {
          const t = await writeEncrypted(vault, thumbBlob, null);
          thumbId = t.blobId;
        }
        reply({ blobId, thumbId, size });
        break;
      }
      case 'read': {
        const { vault, blobId, mime } = args;
        const blob = await readDecrypted(vault, blobId, mime);
        reply({ blob });
        break;
      }
      case 'delete': {
        await deleteBlob(args.blobId);
        if (args.thumbId) await deleteBlob(args.thumbId);
        reply({ ok: true });
        break;
      }
      case 'exportVault': {
        reply(await exportVault(args));
        break;
      }
      case 'importArchive': {
        reply(await importArchive(args, (loaded, total) =>
          self.postMessage({ id, progress: true, loaded, total })));
        break;
      }
      default: fail(new Error('Unknown op ' + op));
    }
  } catch (err) {
    fail(err);
  }
};

// ---- portable .fwvault archive -------------------------------------------
// Framing + stream crypto live in archive.js (pure, IO-injected, unit-tested).
// Here we only wire it to the vault's own key derivation and OPFS read/write.

async function exportVault({ passphrase, records }) {
  // records: [{meta, vault, blobId}] gathered by the main thread from IndexedDB.
  const salt = randomBytes(16);
  const key = await deriveKeyFromPassphrase(passphrase, salt, ['encrypt']);
  const blob = await buildArchive({
    key,
    salt,
    randomBase: () => randomBytes(8),
    records: records.map((r) => ({
      meta: r.meta,
      readBlob: () => readDecrypted(r.vault, r.blobId, r.meta.mime),
    })),
  });
  return { blob };
}

async function importArchive({ passphrase, file, vault }, onProgress) {
  const buf = new Uint8Array(await file.arrayBuffer());
  const { salt } = parseArchiveFrames(buf);
  const key = await deriveKeyFromPassphrase(passphrase, salt, ['decrypt']);
  const imported = await extractArchive({
    key,
    buf,
    onProgress,
    // Re-encrypt each extracted file under the destination vault's data key.
    writeBlob: async (blob, meta) => {
      const { blobId } = await writeEncrypted(vault, blob, null);
      let thumbId = null;
      if (meta.category === 'photo') {
        const t = await makeImageThumb(blob);
        if (t) thumbId = (await writeEncrypted(vault, t, null)).blobId;
      }
      return { blobId, thumbId };
    },
  });
  return { imported };
}
