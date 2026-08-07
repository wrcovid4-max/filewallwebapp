# FileWall — browser-native encrypted vault

A private vault for photos, videos and documents that runs **entirely in your
browser**. No server, no backend, no account, no build step. Files are encrypted
on your device with keys the page itself cannot read. Open one URL and it works.

It is a folder of static files: plain HTML, CSS and ES modules. Drag the folder
onto any static host and it runs.

## Run it

FileWall needs a **secure context** — `https://…` **or** `http://localhost`.
It uses Service Workers, OPFS and (optionally) passkeys, and browsers only enable
those on a secure origin. You cannot just double-click `index.html`
(a `file://` page can't load ES modules or register a service worker).

### On your Mac, full features (recommended)

Serve the folder over `http://localhost` and open it there:

- **No Terminal:** use a free one-click GUI static server (e.g. *Servez* or
  *Simple Web Server*), point it at this folder, open the `http://localhost:PORT`
  it gives you.
- **With Terminal:** `cd` into the folder and run any static server, e.g.
  `python3 -m http.server 8080`, then open `http://localhost:8080`.

Everything works here: offline, streaming video, biometric unlock, PWA install.

### Over your wifi (phone on the same network)

Reaching the Mac at `http://192.168.x.x:PORT` **works but is degraded**: a bare
LAN IP over plain HTTP is *not* a secure context, so the service worker
(offline + streaming video player), PWA install, and biometric unlock are
disabled by the browser. The passphrase-protected vault still works.

To get full features on the phone you need HTTPS in front of the LAN — a free
mesh/tunnel such as Tailscale's `serve` can provide it.

### On a static host

Drag the folder onto any static host (Netlify Drop, GitHub Pages, …). You get
real HTTPS and every feature, on every device.

## What it does

- **Encrypted files in the browser.** AES-GCM, chunked (1 MiB) so multi-gigabyte
  videos never blow up tab memory. Encrypted blobs live in OPFS under opaque UUID
  names; file names/metadata live only in IndexedDB.
- **A hidden vault** behind a passcode and/or a passkey (Touch ID / Face ID /
  Windows Hello via the WebAuthn PRF extension). The hidden data key is wrapped by
  your passcode/biometric — locked, its files can't be decrypted at all.
- **Streaming video** via a service worker that serves `Range` requests from
  `/vault-stream/<id>`, decrypting only the chunks you seek to. Plaintext never
  fully materialises.
- **Portable backups.** Export the whole vault as one `.fwvault` file
  (PBKDF2-600k passphrase, same chunked-GCM body). Import by picker or drag-drop.
- **A PWA** you can install to your home screen; opens offline after first visit.

## Honest limits

This vault lives in your browser's storage. **Clearing your browsing data erases
it permanently — there is no copy and no recovery.** If the browser denies
persistent storage it may clear the vault when space runs low (Safari can clear
it after ~a week of not visiting). Keep an exported backup. And it protects
against someone *browsing* your files — not against someone examining an
already-unlocked machine with developer tools. The Security → Limits panel says
all of this in the app.

## Layout

```
index.html          app shell + all views
manifest.json       PWA manifest
sw.js               service worker: shell precache + /vault-stream range decrypt
css/styles.css      the whole visual system (dark default, light theme)
js/config.js        shared constants
js/crypto.js        crypto primitives (why-comments live here)
js/archive.js       portable .fwvault format (pure, IO-injected, unit-tested)
js/idb.js           IndexedDB metadata + persisted non-extractable keys
js/worker.js        dedicated worker: OPFS sync-access IO + bulk crypto
js/webauthn.js      passkey / PRF biometric unlock
js/storage.js       main-thread facade over the worker + IndexedDB
js/ui.js            UI controller
js/app.js           bootstrap + feature detection
icons/              shield logo (SVG + PNG)
```

Crypto and file IO run in the worker; the UI runs on the main thread; they talk
by `postMessage`. Keys are non-extractable `CryptoKey` handles persisted in
IndexedDB — the closest the web gets to the Android Keystore.

## Browser support

Chrome/Edge 108+, Safari 16+, Firefox 114+ (needs module workers + OPFS). If a
required capability is missing, FileWall shows a screen naming exactly what,
rather than a half-working vault.
