// server.mjs — a tiny, zero-dependency static server for FileWall.
//
// No npm install, no packages — just Node's built-ins. It serves THIS folder
// (the app) over http on localhost + your LAN IP, so you can bookmark the links
// and "click to open". Run it with:
//
//     node server.mjs            # serves on port 8080
//     node server.mjs 8081       # serves on a different port (for a 2nd app)
//     PORT=9000 node server.mjs  # or via env var
//
// It binds to 0.0.0.0 so a phone on the same wifi can reach it at your Mac's IP.
// Reminder: localhost = full features; a bare LAN IP over http is not a secure
// context, so the service worker / offline / biometric unlock are disabled there.

import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, normalize, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { networkInterfaces } from 'node:os';

const ROOT = fileURLToPath(new URL('.', import.meta.url)); // this folder
const PORT = Number(process.argv[2] || process.env.PORT || 8080);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
  '.txt': 'text/plain; charset=utf-8',
};

const server = http.createServer(async (req, res) => {
  try {
    let pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (pathname.endsWith('/')) pathname += 'index.html';

    // Resolve inside ROOT and refuse anything that escapes it (no path traversal).
    const filePath = normalize(join(ROOT, pathname));
    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403); res.end('Forbidden'); return;
    }

    // If it's a directory, serve its index.html.
    let target = filePath;
    try {
      const s = await stat(target);
      if (s.isDirectory()) target = join(target, 'index.html');
    } catch { /* fall through to readFile, which will 404 */ }

    const data = await readFile(target);
    const type = MIME[extname(target).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': type,
      // Let the service worker manage its own caching; don't let the browser
      // hold stale module files while you're iterating.
      'Cache-Control': 'no-cache',
      // Allow a service worker registered at the root to control the whole app.
      'Service-Worker-Allowed': '/',
    });
    res.end(data);
  } catch (err) {
    if (err && err.code === 'ENOENT') { res.writeHead(404); res.end('Not found'); }
    else { res.writeHead(500); res.end('Server error'); console.error(err); }
  }
});

function lanIPs() {
  const out = [];
  for (const list of Object.values(networkInterfaces())) {
    for (const ni of list || []) {
      if (ni.family === 'IPv4' && !ni.internal) out.push(ni.address);
    }
  }
  return out;
}

server.listen(PORT, '0.0.0.0', () => {
  const ips = lanIPs();
  console.log('\n  FileWall is being served.  (Press Ctrl+C to stop.)\n');
  console.log('  Open on THIS Mac  (full features):');
  console.log(`     http://localhost:${PORT}/\n`);
  if (ips.length) {
    console.log('  Open from your PHONE on the same wifi  (passcode vault only —');
    console.log('  offline / streaming / biometrics are off over a bare IP):');
    for (const ip of ips) console.log(`     http://${ip}:${PORT}/`);
    console.log('');
  }
});
