// idb.js — thin promise wrapper over IndexedDB.
//
// Metadata only. File *names, mime types, sizes* live here and NOWHERE in OPFS —
// an OPFS blob is a UUID with no extension and no clue about what it holds.
// Also the home of the persisted non-extractable CryptoKey objects.
//
// Importable from the main thread, the dedicated worker and the service worker.

import {
  DB_NAME, DB_VERSION, STORE_META, STORE_FILES, STORE_FOLDERS, STORE_KEYS,
} from './config.js';

let dbPromise = null;

export function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META); // key/value, out-of-line keys
      }
      if (!db.objectStoreNames.contains(STORE_KEYS)) {
        db.createObjectStore(STORE_KEYS); // key/value CryptoKey handles
      }
      if (!db.objectStoreNames.contains(STORE_FILES)) {
        const s = db.createObjectStore(STORE_FILES, { keyPath: 'id' });
        s.createIndex('folderId', 'folderId');
        s.createIndex('hidden', 'hidden');
        s.createIndex('dateAdded', 'dateAdded');
      }
      if (!db.objectStoreNames.contains(STORE_FOLDERS)) {
        const s = db.createObjectStore(STORE_FOLDERS, { keyPath: 'id' });
        s.createIndex('hidden', 'hidden');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function tx(db, store, mode) {
  return db.transaction(store, mode).objectStore(store);
}

function reqToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Generic key/value helpers -------------------------------------------------

export async function kvGet(store, key) {
  const db = await openDB();
  return reqToPromise(tx(db, store, 'readonly').get(key));
}

export async function kvPut(store, key, value) {
  const db = await openDB();
  const os = tx(db, store, 'readwrite');
  return new Promise((resolve, reject) => {
    const r = os.put(value, key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}

export async function kvDelete(store, key) {
  const db = await openDB();
  const os = tx(db, store, 'readwrite');
  return new Promise((resolve, reject) => {
    const r = os.delete(key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}

// Record stores (keyPath 'id') ----------------------------------------------

export async function putRecord(store, record) {
  const db = await openDB();
  const os = tx(db, store, 'readwrite');
  return new Promise((resolve, reject) => {
    const r = os.put(record);
    r.onsuccess = () => resolve(record);
    r.onerror = () => reject(r.error);
  });
}

export async function getRecord(store, id) {
  const db = await openDB();
  return reqToPromise(tx(db, store, 'readonly').get(id));
}

export async function deleteRecord(store, id) {
  const db = await openDB();
  const os = tx(db, store, 'readwrite');
  return new Promise((resolve, reject) => {
    const r = os.delete(id);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}

export async function getAll(store) {
  const db = await openDB();
  return reqToPromise(tx(db, store, 'readonly').getAll());
}

export { STORE_META, STORE_FILES, STORE_FOLDERS, STORE_KEYS };
