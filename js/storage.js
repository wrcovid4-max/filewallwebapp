// storage.js — main-thread facade over the worker (crypto/OPFS) and IndexedDB
// (metadata). The UI talks only to this module; it never touches OPFS or crypto
// directly. All heavy work is delegated to the worker via a small RPC.

import {
  STORE_FILES, STORE_FOLDERS, STORE_META, VAULT_MAIN, VAULT_HIDDEN,
  categoryForMime,
} from './config.js';
import {
  putRecord, getRecord, deleteRecord, getAll, kvGet, kvPut,
} from './idb.js';
import { uuid } from './crypto.js';

// ---- Worker RPC -----------------------------------------------------------

const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
let rpcId = 0;
const pending = new Map(); // id -> {resolve, reject, onProgress}

worker.onmessage = (e) => {
  const { id, ok, result, error, progress, loaded, total } = e.data;
  const entry = pending.get(id);
  if (!entry) return;
  if (progress) { entry.onProgress?.(loaded, total); return; }
  pending.delete(id);
  if (ok) entry.resolve(result); else entry.reject(new Error(error));
};

function call(op, args, onProgress, transfer) {
  const id = ++rpcId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, onProgress });
    worker.postMessage({ id, op, args }, transfer || []);
  });
}

// ---- lifecycle ------------------------------------------------------------

export async function init() {
  const res = await call('init', {});
  // A freshly loaded page always starts with the hidden vault LOCKED. The
  // service worker, however, survives page reloads and may still hold a hidden
  // session key from a previous page — drop it so a reload can't stream hidden
  // content until the user unlocks again.
  try {
    const reg = await navigator.serviceWorker?.ready;
    (navigator.serviceWorker?.controller || reg?.active)?.postMessage({ type: 'drop-key', vault: VAULT_HIDDEN });
  } catch { /* no SW — fine */ }
  return res;
}

// ---- persistence / quota --------------------------------------------------

export async function requestPersistence() {
  if (!navigator.storage?.persist) return { supported: false, persisted: false };
  const already = await navigator.storage.persisted?.();
  if (already) return { supported: true, persisted: true };
  const persisted = await navigator.storage.persist();
  return { supported: true, persisted };
}

export async function storageEstimate() {
  if (!navigator.storage?.estimate) return null;
  return navigator.storage.estimate();
}

// ---- hidden vault ---------------------------------------------------------

export async function setupHidden(method, secret) {
  const res = await call('setupHidden', { method, secret });
  // Register the fresh session key with the SW so hidden streaming works
  // immediately after first setup, without waiting for a re-unlock.
  if (res.key) registerKeyWithSW(VAULT_HIDDEN, res.key);
  return res;
}

export async function addHiddenMethod(unlockMethod, unlockSecret, newMethod, newSecret) {
  return call('addHiddenMethod', { unlockMethod, unlockSecret, newMethod, newSecret });
}

export async function removeHiddenMethod(method) {
  return call('removeHiddenMethod', { method });
}

export async function listHiddenMethods() {
  const wraps = (await kvGet(STORE_META, 'hiddenWraps')) || {};
  return Object.keys(wraps);
}

export async function unlockHidden(method, secret) {
  const res = await call('unlockHidden', { method, secret });
  // Register the returned session key with the service worker so hidden video
  // can stream. The CryptoKey stays non-extractable across the postMessage.
  registerKeyWithSW(VAULT_HIDDEN, res.key);
  return res;
}

export async function lockHidden() {
  await call('lockHidden', {});
  dropKeyFromSW(VAULT_HIDDEN);
}

export async function isHiddenConfigured() {
  const wraps = (await kvGet(STORE_META, 'hiddenWraps')) || {};
  return Object.keys(wraps).length > 0;
}

function registerKeyWithSW(vault, key) {
  navigator.serviceWorker?.controller?.postMessage({ type: 'set-key', vault, key });
}
function dropKeyFromSW(vault) {
  navigator.serviceWorker?.controller?.postMessage({ type: 'drop-key', vault });
}

// ---- files ----------------------------------------------------------------

// Import a File. Encrypts in the worker, then writes the metadata record here.
// videoThumb (a Blob) may be pre-captured on the main thread for videos.
export async function importFile(file, { hidden = false, folderId = null, videoThumb = null } = {}, onProgress) {
  const vault = hidden ? VAULT_HIDDEN : VAULT_MAIN;
  const category = categoryForMime(file.type);
  const { blobId, thumbId, size } = await call(
    'import',
    { vault, file, videoThumb, category },
    onProgress,
  );
  const record = {
    id: uuid(),
    name: file.name || 'Untitled',
    mime: file.type || 'application/octet-stream',
    size,
    dateAdded: Date.now(),
    folderId,
    hidden: hidden ? 1 : 0,
    category,
    blobId,
    thumbId,
  };
  await putRecord(STORE_FILES, record);
  return record;
}

export async function listFiles() {
  return getAll(STORE_FILES);
}

export async function listFolders() {
  return getAll(STORE_FOLDERS);
}

export async function getFile(id) {
  return getRecord(STORE_FILES, id);
}

// Decrypt a file to a Blob (for image/document viewing and export).
export async function readFileBlob(record) {
  const vault = record.hidden ? VAULT_HIDDEN : VAULT_MAIN;
  const { blob } = await call('read', { vault, blobId: record.blobId, mime: record.mime });
  return blob;
}

export async function readThumb(record) {
  if (!record.thumbId) return null;
  const vault = record.hidden ? VAULT_HIDDEN : VAULT_MAIN;
  const { blob } = await call('read', { vault, blobId: record.thumbId, mime: 'image/jpeg' });
  return blob;
}

export async function updateFile(record) {
  return putRecord(STORE_FILES, record);
}

export async function deleteFile(record) {
  await call('delete', { blobId: record.blobId, thumbId: record.thumbId });
  await deleteRecord(STORE_FILES, record.id);
}

// ---- folders --------------------------------------------------------------

export async function createFolder(name, color, hidden = false) {
  const folder = { id: uuid(), name, color, hidden: hidden ? 1 : 0, dateAdded: Date.now() };
  await putRecord(STORE_FOLDERS, folder);
  return folder;
}

export async function updateFolder(folder) {
  return putRecord(STORE_FOLDERS, folder);
}

export async function deleteFolder(folder, orphanFiles = true) {
  const files = await listFiles();
  for (const f of files) {
    if (f.folderId === folder.id) {
      if (orphanFiles) { f.folderId = null; await putRecord(STORE_FILES, f); }
      else await deleteFile(f);
    }
  }
  await deleteRecord(STORE_FOLDERS, folder.id);
}

// ---- settings (plain key/value) ------------------------------------------

export async function getSetting(key, fallback = null) {
  const v = await kvGet(STORE_META, 'setting:' + key);
  return v === undefined || v === null ? fallback : v;
}
export async function setSetting(key, value) {
  return kvPut(STORE_META, 'setting:' + key, value);
}

// ---- backup metadata ------------------------------------------------------

export async function getLastBackup() {
  return getSetting('lastBackup', null);
}
export async function setLastBackup(ts) {
  return setSetting('lastBackup', ts);
}

// ---- archive export / import ---------------------------------------------

export async function exportVault(passphrase, { includeHidden = false } = {}, onProgress) {
  const files = await listFiles();
  const records = files
    .filter((f) => includeHidden || !f.hidden)
    .map((f) => ({ meta: stripMeta(f), vault: f.hidden ? VAULT_HIDDEN : VAULT_MAIN, blobId: f.blobId }));
  const { blob } = await call('exportVault', { passphrase, records }, onProgress);
  return blob;
}

export async function importArchive(file, passphrase, { hidden = false } = {}, onProgress) {
  const vault = hidden ? VAULT_HIDDEN : VAULT_MAIN;
  const { imported } = await call('importArchive', { passphrase, file, vault }, onProgress);
  const created = [];
  for (const item of imported) {
    const record = {
      id: uuid(),
      name: item.meta.name,
      mime: item.meta.mime,
      size: item.meta.size,
      dateAdded: item.meta.dateAdded || Date.now(),
      folderId: null,
      hidden: hidden ? 1 : 0,
      category: item.meta.category,
      blobId: item.blobId,
      thumbId: item.thumbId,
    };
    await putRecord(STORE_FILES, record);
    created.push(record);
  }
  return created;
}

// Metadata that travels in the portable archive — no blobId (re-minted on import).
function stripMeta(f) {
  return {
    name: f.name, mime: f.mime, size: f.size, dateAdded: f.dateAdded, category: f.category,
  };
}
