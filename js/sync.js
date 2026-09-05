// sync.js — real-time Firestore/Storage sync against the SAME Firebase project the
// Android/iOS/watchOS/Wear OS apps use (see ../filewallAS/FIREBASE_BLUEPRINT.md).
//
// This reverses a decision baked into this build's own copy: the Security tab, the footer
// and the page <meta> description all say "no server, no account" — that was true until this
// file, and is being changed on explicit instruction. If you want that promise back, this
// module is the one thing to delete; nothing else in the app depends on it, and leaving
// firebase-config.js blank has the exact same effect without deleting anything (see below).
//
// Design, mirrored from the Android build's SyncCoordinator/SyncCrypto so the two interoperate
// on the same Firestore docs:
//   - Firestore holds metadata for every file/folder, always, once signed in — genuinely
//     harmless as plaintext (name, folder, flags, timestamps).
//   - File BYTES only ever leave the browser encrypted under a portable key derived from a
//     **sync passphrase** (crypto.js's existing deriveKeyFromPassphrase — the same function
//     the .fwvault export already uses, just with a different, dedicated passphrase). This is
//     deliberately NOT the browser's local per-file data key, which is generated per-device and
//     was never designed to be exportable. Until a sync passphrase is set, metadata syncs and
//     bytes don't — the Security card explains this in the UI, it doesn't fail silently.
//   - Hidden-vault items are included on purpose (explicit product decision): they sync
//     flagged `hidden: true`, encrypted like everything else. Nothing here special-cases them
//     beyond carrying the flag through, same as the Android build.
//   - Deterministic ids, `set(..., {merge:true})` only, never `addDoc()` — the whole
//     anti-duplication story in FIREBASE_BLUEPRINT.md §7 depends on this.
//   - The sync passphrase lives in `sessionStorage`, not `localStorage`: it's gone when the
//     tab/browser closes. That's a deliberate, more conservative choice than the native apps'
//     Keystore-backed storage — a browser has no hardware-backed secret store to seal it in,
//     so the honest trade-off is "type it again next session" over "sitting in plaintext on
//     disk indefinitely."

import { firebaseConfig, isConfigured } from './firebase-config.js';
import { FOLDER_COLORS } from './config.js';
import * as store from './storage.js';

const FIREBASE_SDK = 'https://www.gstatic.com/firebasejs/12.18.0/firebase';

let appPromise = null;
let authMod = null;
let fsMod = null;
let stMod = null;
let app = null;
let auth = null;
let db = null;
let fbStorage = null;

// Deliberately its own iteration count, not js/config.js's PBKDF2_ITERATIONS (600k, for the
// local .fwvault export) — this key has to be re-derivable byte-for-byte by the Android app
// from the same passphrase, and the Android side's SyncCrypto uses 210k. Keep these two in
// lockstep if either ever changes; a mismatch here means devices silently fail to decrypt
// each other's uploads with an otherwise-correct passphrase.
const SYNC_PBKDF2_ITERATIONS = 210_000;

const listeners = new Set();
let status = { state: 'signed-out' }; // signed-out | idle | syncing | synced | error

function setStatus(next) {
  status = next;
  listeners.forEach((fn) => fn(status));
}
export function onStatusChange(fn) {
  listeners.add(fn);
  fn(status);
  return () => listeners.delete(fn);
}
export function getStatus() {
  return status;
}

// ---------------------------------------------------------------------------
// Lazy Firebase init — mirrors FirebaseGate.kt: while unconfigured, every call
// below is a safe no-op and the app behaves exactly as it always has.
// ---------------------------------------------------------------------------

async function ensureFirebase() {
  if (!isConfigured()) return false;
  if (app) return true;
  if (!appPromise) {
    appPromise = (async () => {
      const [appMod, authM, fsM, stM] = await Promise.all([
        import(/* @vite-ignore */ `${FIREBASE_SDK}-app.js`),
        import(/* @vite-ignore */ `${FIREBASE_SDK}-auth.js`),
        import(/* @vite-ignore */ `${FIREBASE_SDK}-firestore.js`),
        import(/* @vite-ignore */ `${FIREBASE_SDK}-storage.js`),
      ]);
      authMod = authM; fsMod = fsM; stMod = stM;
      app = appMod.initializeApp(firebaseConfig);
      auth = authM.getAuth(app);
      db = fsM.getFirestore(app);
      fbStorage = stM.getStorage(app);
      // Best-effort offline cache. Deprecated in newer SDK releases in favour of
      // persistentLocalCache(), so guard the call itself, not just its promise —
      // an undefined export would otherwise throw synchronously before .catch() runs.
      if (typeof fsM.enableIndexedDbPersistence === 'function') {
        try { fsM.enableIndexedDbPersistence(db).catch(() => {}); } catch { /* ignore */ }
      }
    })();
  }
  await appPromise;
  return true;
}

export async function isAvailable() {
  return isConfigured();
}

export function isSignedIn() {
  return Boolean(auth?.currentUser);
}

export function currentUid() {
  return auth?.currentUser?.uid ?? null;
}

export async function signIn() {
  await ensureFirebase();
  const provider = new authMod.GoogleAuthProvider();
  await authMod.signInWithPopup(auth, provider);
  setStatus({ state: 'idle' });
}

export async function signOut() {
  if (!auth) return;
  await authMod.signOut(auth);
  sessionStorage.removeItem(PASSPHRASE_KEY);
  localStorage.removeItem(CURSOR_KEY);
  setStatus({ state: 'signed-out' });
}

// ---------------------------------------------------------------------------
// Sync passphrase (portable, not the browser's local per-file key)
// ---------------------------------------------------------------------------

const PASSPHRASE_KEY = 'filewall_sync_passphrase';

export function hasSyncPassphrase() {
  return Boolean(sessionStorage.getItem(PASSPHRASE_KEY));
}

export async function setSyncPassphrase(passphrase) {
  sessionStorage.setItem(PASSPHRASE_KEY, passphrase);
  await syncNow();
}

function readSyncPassphrase() {
  return sessionStorage.getItem(PASSPHRASE_KEY);
}

// ---------------------------------------------------------------------------
// Portable per-blob encryption — same shape as the Android build's SyncCrypto:
// [salt 16B][iv 12B][ciphertext+tag], self-contained so no external state is needed.
// ---------------------------------------------------------------------------

async function deriveSyncKey(passphrase, salt, usages) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: SYNC_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

async function encryptForSync(plainBytes, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveSyncKey(passphrase, salt, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes));
  const out = new Uint8Array(salt.length + iv.length + ct.length);
  out.set(salt, 0); out.set(iv, salt.length); out.set(ct, salt.length + iv.length);
  return out;
}

async function decryptForSync(payload, passphrase) {
  const salt = payload.slice(0, 16);
  const iv = payload.slice(16, 28);
  const ct = payload.slice(28);
  const key = await deriveSyncKey(passphrase, salt, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

// ---------------------------------------------------------------------------
// Canonical doc mapping — matches FIREBASE_BLUEPRINT.md §2.2/§2.3 exactly, so this
// build reads/writes the SAME documents the Android/iOS apps do for the same account.
// ---------------------------------------------------------------------------

function toFileDoc(record, uid) {
  return {
    id: record.id,
    ownerUid: uid,
    name: record.name,
    mimeType: record.mime,
    category: (record.category || 'other').toUpperCase(),
    sizeBytes: record.size || 0,
    width: 0,
    height: 0,
    folderId: record.folderId || null,
    storagePath: `users/${uid}/files/${record.id}`,
    thumbPath: record.thumbId ? `users/${uid}/thumbs/${record.id}` : null,
    checksum: record.checksum || null,
    hidden: Boolean(record.hidden),
    archived: false,
    deletedAt: 0,
    status: 'ready',
    createdAt: record.dateAdded || Date.now(),
    updatedAt: record.updatedAt || record.dateAdded || Date.now(),
  };
}

function fromFileDoc(doc) {
  return {
    hidden: Boolean(doc.hidden),
    folderId: doc.folderId || null,
    updatedAt: doc.updatedAt || Date.now(),
    dateAdded: doc.createdAt || Date.now(),
  };
}

function toFolderDoc(folder, uid) {
  return {
    id: folder.id,
    ownerUid: uid,
    name: folder.name,
    parentId: null,
    path: '/' + folder.name,
    colorIndex: FOLDER_COLOR_INDEX[folder.color] ?? 0,
    hidden: Boolean(folder.hidden),
    deletedAt: 0,
    createdAt: folder.dateAdded || Date.now(),
    updatedAt: folder.updatedAt || folder.dateAdded || Date.now(),
  };
}

// Android carries folder colour as a palette index, the web build as a hex string —
// this keeps the same FOLDER_COLORS palette order on both sides so a folder made on
// one platform doesn't show up an unrelated colour on the other.
const FOLDER_COLOR_INDEX = Object.fromEntries(FOLDER_COLORS.map((c, i) => [c, i]));

function folderFromDoc(doc) {
  return {
    name: doc.name,
    color: FOLDER_COLORS[doc.colorIndex ?? 0] || FOLDER_COLORS[0],
    hidden: Boolean(doc.hidden),
    dateAdded: doc.createdAt || Date.now(),
    updatedAt: doc.updatedAt || Date.now(),
  };
}

// ---------------------------------------------------------------------------
// The sync pass
// ---------------------------------------------------------------------------

const CURSOR_KEY = 'filewall_sync_settings_cursor';

export async function syncNow() {
  const available = await ensureFirebase();
  if (!available) { setStatus({ state: 'error', message: "Cloud sync isn't configured (see firebase-config.js)" }); return; }
  if (!isSignedIn()) { setStatus({ state: 'signed-out' }); return; }

  const uid = currentUid();
  try {
    setStatus({ state: 'syncing', label: 'Checking for changes…' });

    const { collection, doc, getDocs, setDoc } = fsMod;
    const filesCol = collection(db, 'users', uid, 'files');
    const foldersCol = collection(db, 'users', uid, 'folders');

    const [remoteFilesSnap, remoteFoldersSnap, localFiles, localFolders] = await Promise.all([
      getDocs(filesCol), getDocs(foldersCol), store.listFiles(), store.listFolders(),
    ]);
    const remoteFiles = new Map(remoteFilesSnap.docs.map((d) => [d.id, d.data()]));
    const remoteFolders = new Map(remoteFoldersSnap.docs.map((d) => [d.id, d.data()]));

    // ---- folders first (files reference folderId)
    for (const folder of localFolders) {
      const remote = remoteFolders.get(folder.id);
      const localDoc = toFolderDoc(folder, uid);
      if (!remote || (localDoc.updatedAt || 0) >= (remote.updatedAt || 0)) {
        await setDoc(doc(foldersCol, folder.id), localDoc, { merge: true });
      }
    }
    for (const [id, remote] of remoteFolders) {
      if (remote.deletedAt) continue;
      const local = localFolders.find((f) => f.id === id);
      if (!local || (remote.updatedAt || 0) > (local.updatedAt || 0)) {
        await store.updateFolder({ id, ...folderFromDoc(remote) });
      }
    }

    // ---- files: metadata always, bytes only with a sync passphrase set
    const passphrase = readSyncPassphrase();
    let bytesSkipped = 0;

    for (const record of localFiles) {
      const remote = remoteFiles.get(record.id);
      const localDoc = toFileDoc(record, uid);
      const isNewer = !remote || (localDoc.updatedAt || 0) >= (remote.updatedAt || 0);
      if (!isNewer) continue;

      let checksum = record.checksum || null;
      if (passphrase) {
        try {
          const plain = await store.readFileBlob(record);
          const cipher = await encryptForSync(new Uint8Array(await plain.arrayBuffer()), passphrase);
          const path = stMod.ref(fbStorage, `users/${uid}/files/${record.id}`);
          await stMod.uploadBytes(path, cipher);
          checksum = await sha256Hex(cipher);
        } catch (err) {
          console.warn('sync: upload failed for', record.id, err);
        }
      } else {
        bytesSkipped++;
      }
      await setDoc(doc(filesCol, record.id), { ...localDoc, checksum }, { merge: true });
    }

    for (const [id, remote] of remoteFiles) {
      const local = localFiles.find((f) => f.id === id);
      if (remote.deletedAt) {
        if (local) await store.deleteFile(local);
        continue;
      }
      if (local && (local.updatedAt || 0) >= (remote.updatedAt || 0)) continue;

      if (!passphrase) { bytesSkipped++; continue; } // metadata will still show via storage listing next pass once decided; for now skip silently
      try {
        const path = stMod.ref(fbStorage, `users/${uid}/files/${id}`);
        const cipher = new Uint8Array(await stMod.getBytes(path, 200 * 1024 * 1024));
        const plain = await decryptForSync(cipher, passphrase);
        const file = new File([plain], remote.name, { type: remote.mimeType });
        await store.ingestRemoteFile(id, file, fromFileDoc(remote));
      } catch (err) {
        console.warn('sync: download failed for', id, err);
      }
    }

    await syncSettings(uid);

    setStatus(
      bytesSkipped > 0 && !passphrase
        ? { state: 'error', message: 'Signed in, but no sync passphrase set — files stay metadata-only until one is' }
        : { state: 'synced', at: Date.now() },
    );
  } catch (err) {
    console.error('sync failed', err);
    setStatus({ state: 'error', message: err.message || 'Sync failed' });
  }
}

async function syncSettings(uid) {
  const { doc, getDoc, setDoc } = fsMod;
  const settingsRef = doc(db, 'users', uid, 'meta', 'settings');
  const remote = (await getDoc(settingsRef)).data();
  const localCursor = Number(localStorage.getItem(CURSOR_KEY) || 0);

  // Same safe subset as Android: cosmetic/organisational only, never security posture
  // (hidden-vault toggle, PIN fallback, biometric stay per-device on purpose).
  if (remote && (remote.updatedAt || 0) > localCursor) {
    if (remote.theme) await store.setSetting('theme', remote.theme);
    if (remote.gridView !== undefined) await store.setSetting('gridView', remote.gridView);
    localStorage.setItem(CURSOR_KEY, String(remote.updatedAt));
  } else {
    const theme = await store.getSetting('theme', 'system');
    const gridView = await store.getSetting('gridView', true);
    await setDoc(settingsRef, { theme, gridView, updatedAt: Date.now() }, { merge: true });
    localStorage.setItem(CURSOR_KEY, String(Date.now()));
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return 'sha256:' + Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
