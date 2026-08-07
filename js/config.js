// config.js — shared constants for FileWall.
// Kept dependency-free so it can be imported from the main thread, the
// dedicated worker, and the service worker alike.

export const APP_NAME = 'FileWall';

// IndexedDB
export const DB_NAME = 'filewall';
export const DB_VERSION = 1;
export const STORE_META = 'meta';     // key/value: config, wrapped hidden key, etc.
export const STORE_FILES = 'files';   // file metadata records (names live ONLY here)
export const STORE_FOLDERS = 'folders';
export const STORE_KEYS = 'keys';     // non-extractable CryptoKey objects

// OPFS
export const OPFS_DIR = 'blobs';      // encrypted file + thumbnail blobs, UUID names

// Crypto / file format
export const MAGIC = 0x4657564c;      // "FWVL"
export const FORMAT_VERSION = 1;
export const CHUNK_SIZE = 1024 * 1024;      // 1 MiB plaintext per chunk
export const GCM_TAG_BYTES = 16;            // AES-GCM auth tag
export const ENC_CHUNK_SIZE = CHUNK_SIZE + GCM_TAG_BYTES;
export const NONCE_BYTES = 12;              // AES-GCM nonce: 8 random base + 4 counter
export const NONCE_BASE_BYTES = 8;
export const PBKDF2_ITERATIONS = 600_000;   // matches the native apps' archive format
export const PBKDF2_SALT_BYTES = 16;

// Vault identifiers
export const VAULT_MAIN = 'main';
export const VAULT_HIDDEN = 'hidden';

// Categories
export const CAT_PHOTO = 'photo';
export const CAT_VIDEO = 'video';
export const CAT_DOC = 'doc';

export const CATEGORY_COLORS = {
  [CAT_PHOTO]: '#4CAF50',
  [CAT_VIDEO]: '#2196F3',
  [CAT_DOC]: '#FFC107',
};

// Folder colour palette (periwinkle-family + category hues)
export const FOLDER_COLORS = [
  '#B4C5FF', '#4CAF50', '#2196F3', '#FFC107',
  '#EF5350', '#AB47BC', '#26A69A', '#FF7043',
];

export function categoryForMime(mime) {
  if (!mime) return CAT_DOC;
  if (mime.startsWith('image/')) return CAT_PHOTO;
  if (mime.startsWith('video/')) return CAT_VIDEO;
  return CAT_DOC;
}

// Escalating lockout schedule (ms) after N consecutive wrong hidden-vault attempts.
// Index 0 => after the 5th wrong attempt, etc. Clamped at the last entry.
export const LOCKOUT_SCHEDULE_MS = [
  30_000,      // 30s
  60_000,      // 1m
  5 * 60_000,  // 5m
  15 * 60_000, // 15m
  60 * 60_000, // 1h
];
export const LOCKOUT_THRESHOLD = 5;
