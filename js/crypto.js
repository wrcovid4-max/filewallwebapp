// crypto.js — all cryptographic primitives for FileWall.
//
// Design notes (the reasoning is the only thing that survives a refactor):
//
//  * The vault DATA KEY is a non-extractable AES-GCM CryptoKey. It is generated
//    with extractable:false and stored *directly* in IndexedDB. The browser
//    structured-clones and persists the opaque key handle; no script — not ours,
//    not an attacker's injected script — can ever read its raw bytes back out.
//    This is the closest the web platform gets to the Android Keystore / iOS
//    Secure Enclave: the key exists, you can use it to encrypt/decrypt, but you
//    cannot exfiltrate it. See storage/idb for where it is persisted.
//
//  * The HIDDEN vault's data key is additionally *wrapped* by a key derived from
//    the user's passcode (PBKDF2) or a passkey's PRF secret (HKDF). Only the
//    wrapped bytes are stored. Without the passcode/biometric the hidden files
//    are undecryptable — that is the real security boundary of the hidden side.
//    (The main vault is intentionally always-available; its non-extractable key
//    protects against key exfiltration, not against an already-unlocked device.)
//
//  * Files are sealed as chunked AES-GCM, 1 MiB plaintext per chunk, each chunk
//    sealed independently with a distinct nonce. crypto.subtle.encrypt wants a
//    whole ArrayBuffer, so single-shot encrypting a 2 GB video would try to hold
//    it all in memory and kill the tab. Chunking bounds memory AND gives random
//    access, which the /vault-stream range player depends on.

import {
  CHUNK_SIZE, ENC_CHUNK_SIZE, GCM_TAG_BYTES, MAGIC, FORMAT_VERSION,
  NONCE_BYTES, NONCE_BASE_BYTES, PBKDF2_ITERATIONS, PBKDF2_SALT_BYTES,
} from './config.js';

const subtle = crypto.subtle;

// ---------------------------------------------------------------------------
// Data keys
// ---------------------------------------------------------------------------

// A fresh non-extractable AES-GCM key for a vault. The whole point is
// extractable:false — this handle can encrypt/decrypt forever but never reveals
// its bytes. Store the returned CryptoKey object directly in IndexedDB.
export function generateDataKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt', 'decrypt',
  ]);
}

// ---------------------------------------------------------------------------
// Nonce derivation
// ---------------------------------------------------------------------------

// Per-file: 8 random base bytes chosen once, stored in the file header. Per
// chunk we append a 4-byte big-endian counter, giving a unique 12-byte nonce
// per (file, chunk). Reusing a nonce under one key breaks AES-GCM, so the base
// must be random per file and the counter must never wrap within a file (a
// 4-byte counter covers 2^32 chunks = 4 PiB at 1 MiB/chunk — far beyond limits).
export function deriveChunkNonce(baseNonce8, chunkIndex) {
  const nonce = new Uint8Array(NONCE_BYTES);
  nonce.set(baseNonce8.subarray(0, NONCE_BASE_BYTES), 0);
  const dv = new DataView(nonce.buffer);
  dv.setUint32(NONCE_BASE_BYTES, chunkIndex >>> 0, false); // big-endian counter
  return nonce;
}

// ---------------------------------------------------------------------------
// File header
// ---------------------------------------------------------------------------
//
// Layout (little-endian scalars, fixed 32 bytes):
//   [0..4)   magic   uint32  "FWVL"
//   [4]      version uint8
//   [5]      reserved
//   [6..8)   chunkSizeKiB uint16   (chunk size in KiB; 1024 for 1 MiB)
//   [8..16)  baseNonce (8 bytes)
//   [16..24) plaintextSize (uint64, for exact trailing-chunk sizing)
//   [24..32) reserved
export const HEADER_BYTES = 32;

export function buildHeader(baseNonce8, plaintextSize) {
  const buf = new Uint8Array(HEADER_BYTES);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, MAGIC, false);
  dv.setUint8(4, FORMAT_VERSION);
  dv.setUint16(6, Math.round(CHUNK_SIZE / 1024), true);
  buf.set(baseNonce8.subarray(0, NONCE_BASE_BYTES), 8);
  dv.setBigUint64(16, BigInt(plaintextSize), true);
  return buf;
}

export function parseHeader(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = dv.getUint32(0, false);
  if (magic !== MAGIC) throw new Error('Not a FileWall blob (bad magic)');
  const version = dv.getUint8(4);
  const chunkSize = dv.getUint16(6, true) * 1024;
  const baseNonce = bytes.slice(8, 8 + NONCE_BASE_BYTES);
  const plaintextSize = Number(dv.getBigUint64(16, true));
  return { version, chunkSize, baseNonce, plaintextSize };
}

// ---------------------------------------------------------------------------
// Chunk seal / open
// ---------------------------------------------------------------------------

export async function sealChunk(key, baseNonce8, chunkIndex, plaintext) {
  const iv = deriveChunkNonce(baseNonce8, chunkIndex);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return new Uint8Array(ct); // plaintext.length + 16 (tag)
}

export async function openChunk(key, baseNonce8, chunkIndex, ciphertext) {
  const iv = deriveChunkNonce(baseNonce8, chunkIndex);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(pt);
}

// Given a plaintext byte range [start, end), which chunk indices cover it, and
// what is the plaintext offset of the first chunk. Used by the range streamer.
export function chunksForRange(start, end, chunkSize = CHUNK_SIZE) {
  const first = Math.floor(start / chunkSize);
  const last = Math.floor((end - 1) / chunkSize);
  return { first, last };
}

// Byte offset within the OPFS blob where chunk N's ciphertext begins.
export function chunkCiphertextOffset(chunkIndex, encChunkSize = ENC_CHUNK_SIZE) {
  return HEADER_BYTES + chunkIndex * encChunkSize;
}

// ---------------------------------------------------------------------------
// Passphrase / PRF key derivation
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

// PBKDF2-HMAC-SHA256, 600k iterations. Returns a non-extractable AES-GCM
// wrapping key. Used both for the hidden-vault passcode and the .fwvault export.
export async function deriveKeyFromPassphrase(passphrase, salt, usages = ['encrypt', 'decrypt']) {
  const base = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

// Run a WebAuthn PRF secret through HKDF to a wrapping key. PRF gives a stable
// 32-byte secret bound to the passkey/biometric; HKDF domain-separates it.
export async function deriveKeyFromPrf(prfSecret, salt, usages = ['encrypt', 'decrypt']) {
  const base = await subtle.importKey('raw', prfSecret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', salt, hash: 'SHA-256', info: enc.encode('filewall/hidden-wrap') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

// ---------------------------------------------------------------------------
// Wrapping the hidden data key
// ---------------------------------------------------------------------------
//
// The hidden data key must be recoverable after unlock, so unlike the main key
// it is created EXTRACTABLE, its raw bytes are AES-GCM-encrypted under the
// wrapping key, and only the wrapped blob is stored. On unlock we decrypt the
// bytes and re-import them as a NON-extractable key held only in memory for the
// session. So the raw bytes touch script memory only transiently at wrap/unwrap.

export async function generateWrappableKeyBytes() {
  const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt', 'decrypt',
  ]);
  const raw = new Uint8Array(await subtle.exportKey('raw', k));
  return raw;
}

export async function wrapKeyBytes(wrappingKey, rawKeyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, rawKeyBytes));
  return { iv, wrapped: ct };
}

export async function unwrapKeyToDataKey(wrappingKey, iv, wrapped) {
  const raw = await subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, wrapped);
  // Re-import NON-extractable: from here on the session key can be used but not read.
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Unwrap to the raw bytes (transiently) — only used when re-wrapping the same
// hidden key under an additional unlock method. Scrub the result after use.
export async function unwrapToRawBytes(wrappingKey, iv, wrapped) {
  const raw = await subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, wrapped);
  return new Uint8Array(raw);
}

// Import raw bytes as a NON-extractable session data key.
export function importDataKey(rawBytes) {
  return subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function randomSalt() {
  return randomBytes(PBKDF2_SALT_BYTES);
}

export function uuid() {
  return crypto.randomUUID();
}

// Hash a passcode for constant-ish storage (we still gate via crypto, but a
// PBKDF2 hash lets us verify the PIN without unwrapping the whole key first).
export async function hashPasscode(passcode, salt) {
  const base = await subtle.importKey('raw', enc.encode(passcode), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export { CHUNK_SIZE, ENC_CHUNK_SIZE, HEADER_BYTES as HEADER_SIZE, GCM_TAG_BYTES };
