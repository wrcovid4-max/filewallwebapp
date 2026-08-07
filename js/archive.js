// archive.js — the portable .fwvault format.
//
// One passphrase-derived key (PBKDF2 600k, done by the caller) over a body of
// independently-sealed chunked-GCM streams. Layout:
//
//   [0..4)   magic 'FWAR' (big-endian)
//   [4]      version (1)
//   [5]      saltLen
//   [6..6+saltLen)          PBKDF2 salt
//   [ ...16-byte manifest header: u32 sealedLen, u32 plaintextLen, 8B baseNonce ]
//   [ sealed manifest stream ]
//   [ sealed file stream #0 ][ sealed file stream #1 ] ...
//
// The manifest (JSON) lists each file's metadata, plaintext size, base nonce and
// sealed byte length, so extraction can walk the file streams in order. Each
// stream reuses the exact per-file chunked-GCM scheme (1 MiB chunks), so the
// archive body is byte-for-byte the same construction as an on-disk blob body —
// which is what makes one format across web/Android/iOS achievable.
//
// IO is injected (readFile/writeFile/makeThumb) so this module has zero OPFS or
// crypto-key-management dependencies and can be unit-tested in isolation.

import { CHUNK_SIZE, ENC_CHUNK_SIZE } from './config.js';
import { sealChunk, openChunk } from './crypto.js';

export const AR_MAGIC = 0x46574152; // 'FWAR'
export const AR_VERSION = 1;

export function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.byteLength;
  const out = new Uint8Array(len);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.byteLength; }
  return out;
}

// Seal a Blob into one Uint8Array of concatenated GCM chunks under `base` nonce.
export async function sealStream(key, base, blob) {
  const total = blob.size;
  const nChunks = Math.max(1, Math.ceil(total / CHUNK_SIZE));
  const out = [];
  for (let i = 0; i < nChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(total, start + CHUNK_SIZE);
    const plain = new Uint8Array(await blob.slice(start, end).arrayBuffer());
    out.push(await sealChunk(key, base, i, plain));
  }
  return concat(out);
}

// Open a concatenated GCM stream back to plaintext bytes.
export async function openStream(key, base, bytes, plaintextSize) {
  const nChunks = Math.max(1, Math.ceil(plaintextSize / CHUNK_SIZE));
  const parts = [];
  let at = 0;
  for (let i = 0; i < nChunks; i++) {
    const thisEnc = Math.min(ENC_CHUNK_SIZE, bytes.byteLength - at);
    parts.push(await openChunk(key, base, i, bytes.subarray(at, at + thisEnc)));
    at += thisEnc;
  }
  return concat(parts);
}

// Build a .fwvault Blob.
//   key     : AES-GCM CryptoKey derived from the passphrase (usage: encrypt)
//   salt    : the PBKDF2 salt used to derive `key`
//   records : [{ meta, readBlob: () => Promise<Blob> }]
//   randomBase() : returns 8 fresh random bytes
export async function buildArchive({ key, salt, records, randomBase, onProgress }) {
  const parts = [];
  const head = new Uint8Array(6 + salt.length);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, AR_MAGIC, false);
  dv.setUint8(4, AR_VERSION);
  dv.setUint8(5, salt.length);
  head.set(salt, 6);

  const manifestFiles = [];
  const fileParts = [];
  let done = 0;
  for (const r of records) {
    const blob = await r.readBlob();
    const base = randomBase();
    const sealed = await sealStream(key, base, blob);
    manifestFiles.push({
      meta: r.meta,
      plaintextSize: blob.size,
      baseNonce: Array.from(base),
      byteLength: sealed.byteLength,
    });
    fileParts.push(sealed);
    if (onProgress) onProgress(++done, records.length);
  }

  const manifestJson = new TextEncoder().encode(JSON.stringify({ files: manifestFiles }));
  const mBase = randomBase();
  const mSealed = await sealStream(key, mBase, new Blob([manifestJson]));
  const mHeader = new Uint8Array(16);
  const mdv = new DataView(mHeader.buffer);
  mdv.setUint32(0, mSealed.byteLength, false);
  mdv.setUint32(4, manifestJson.length, false);
  mHeader.set(mBase, 8);

  parts.push(head, mHeader, mSealed, ...fileParts);
  return new Blob(parts, { type: 'application/octet-stream' });
}

// Parse the fixed framing of a .fwvault buffer (no decryption yet).
export function parseArchiveFrames(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (dv.getUint32(0, false) !== AR_MAGIC) throw new Error('Not a .fwvault archive');
  const saltLen = dv.getUint8(5);
  const salt = buf.subarray(6, 6 + saltLen);
  let at = 6 + saltLen;
  const mByteLen = dv.getUint32(at, false); at += 4;
  const mPlainLen = dv.getUint32(at, false); at += 4;
  const mBase = buf.subarray(at, at + 8); at += 8;
  const mBytes = buf.subarray(at, at + mByteLen); at += mByteLen;
  return { salt, manifest: { base: mBase, bytes: mBytes, plaintextSize: mPlainLen }, filesStart: at };
}

// Extract a .fwvault buffer.
//   key      : AES-GCM CryptoKey derived from the passphrase (usage: decrypt)
//   buf      : Uint8Array of the whole archive
//   writeBlob(blob, meta) => Promise<{ blobId, thumbId }>
export async function extractArchive({ key, buf, writeBlob, onProgress }) {
  const frames = parseArchiveFrames(buf);
  let manifest;
  try {
    const bytes = await openStream(key, frames.manifest.base, frames.manifest.bytes, frames.manifest.plaintextSize);
    manifest = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error('Wrong passphrase or corrupt archive');
  }

  const imported = [];
  let at = frames.filesStart;
  let done = 0;
  for (const f of manifest.files) {
    const base = new Uint8Array(f.baseNonce);
    const bytes = buf.subarray(at, at + f.byteLength); at += f.byteLength;
    const plain = await openStream(key, base, bytes, f.plaintextSize);
    const blob = new Blob([plain], { type: f.meta.mime });
    const { blobId, thumbId } = await writeBlob(blob, f.meta);
    imported.push({ meta: f.meta, blobId, thumbId });
    if (onProgress) onProgress(++done, manifest.files.length);
  }
  return imported;
}
