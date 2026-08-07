// ui.js — main-thread UI controller. Talks only to storage.js and webauthn.js.
// No direct crypto or OPFS here; all of that lives behind the worker.

import * as store from './storage.js';
import * as wa from './webauthn.js';
import {
  CATEGORY_COLORS, FOLDER_COLORS, CAT_PHOTO, CAT_VIDEO, CAT_DOC,
  categoryForMime, LOCKOUT_SCHEDULE_MS, LOCKOUT_THRESHOLD,
} from './config.js';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  files: [], folders: [],
  tab: 'vault',
  vault: 'unlocked',        // which set the vault browser shows
  hiddenUnlocked: false,
  hiddenMethods: [],
  currentFolder: null,
  sort: 'dateAdded', dir: -1,
  viewMode: 'grid',
  selecting: false,
  selected: new Set(),
  search: '',
  theme: 'system',
  autolockMs: 30000,
  passkeyId: null,
  // passcode entry buffers
  pinBuffer: '',
  pinStage: 'enter',        // 'enter' | 'confirm' | 'unlock'
  pinFirst: '',
  wrongCount: 0,
  lockedUntil: 0,
};

const thumbUrls = new Map(); // fileId -> objectURL (revoked on re-render)
let autolockTimer = null;

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

export async function init() {
  const info = await store.init();
  state.hiddenMethods = info.methods || [];
  await loadSettings();
  await refresh();
  wireTabs();
  wireVaultControls();
  wireImport();
  wireHiddenGate();
  wireSecurity();
  wireViewer();
  wireAutolock();
  applyTheme(state.theme);
  await refreshStorageUI();
  await refreshPersistence();
}

async function loadSettings() {
  state.theme = await store.getSetting('theme', 'system');
  state.autolockMs = await store.getSetting('autolockMs', 30000);
  state.viewMode = await store.getSetting('viewMode', 'grid');
  state.sort = await store.getSetting('sort', 'dateAdded');
  state.dir = await store.getSetting('dir', -1);
  state.passkeyId = await store.getSetting('passkeyId', null);
}

async function refresh() {
  state.files = await store.listFiles();
  state.folders = await store.listFolders();
  renderFolders();
  renderFiles();
}

// ---------------------------------------------------------------------------
// Tabs & navigation
// ---------------------------------------------------------------------------

function wireTabs() {
  $$('.tab').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
}

function switchTab(tab) {
  state.tab = tab;
  $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.view').forEach((v) => v.classList.remove('active'));
  $('#view-' + tab).classList.add('active');
  $('#fab-upload').classList.toggle('hidden', tab === 'security' || tab === 'hidden');
  if (tab === 'hidden') renderHiddenGate();
  if (tab === 'security') refreshSecurityUI();
}

// ---------------------------------------------------------------------------
// Vault controls (search, pill, sort, view, select)
// ---------------------------------------------------------------------------

function wireVaultControls() {
  $('#search').addEventListener('input', (e) => { state.search = e.target.value.trim().toLowerCase(); renderFiles(); });

  $$('#vault-pill .pill').forEach((p) => p.addEventListener('click', () => onPillSwitch(p.dataset.vault)));

  const sortSel = $('#sort');
  sortSel.value = state.sort;
  sortSel.addEventListener('change', async () => { state.sort = sortSel.value; await store.setSetting('sort', state.sort); renderFiles(); });

  $('#sort-dir').addEventListener('click', async () => {
    state.dir = -state.dir;
    $('#sort-dir').textContent = state.dir < 0 ? '↓' : '↑';
    await store.setSetting('dir', state.dir);
    renderFiles();
  });
  $('#sort-dir').textContent = state.dir < 0 ? '↓' : '↑';

  const vt = $('#view-toggle');
  vt.addEventListener('click', async () => {
    state.viewMode = state.viewMode === 'grid' ? 'list' : 'grid';
    vt.textContent = state.viewMode === 'grid' ? '▦' : '☰';
    await store.setSetting('viewMode', state.viewMode);
    renderFiles();
  });
  vt.textContent = state.viewMode === 'grid' ? '▦' : '☰';

  $('#select-toggle').addEventListener('click', () => toggleSelectMode());
  $('#sel-cancel').addEventListener('click', () => toggleSelectMode(false));
  $('#sel-delete').addEventListener('click', () => bulkDelete());
  $('#sel-move').addEventListener('click', () => bulkMove());
}

function onPillSwitch(which) {
  if (which === 'hidden') {
    if (state.hiddenMethods.length === 0) { switchTab('hidden'); return; }  // set up
    if (!state.hiddenUnlocked) { switchTab('hidden'); return; }             // unlock
    state.vault = 'hidden';
  } else {
    state.vault = 'unlocked';
  }
  $$('#vault-pill .pill').forEach((p) => p.classList.toggle('active', p.dataset.vault === (state.vault === 'hidden' ? 'hidden' : 'unlocked')));
  state.currentFolder = null;
  renderFolders();
  renderFiles();
}

function toggleSelectMode(force) {
  state.selecting = force === undefined ? !state.selecting : force;
  state.selected.clear();
  $('#select-toggle').classList.toggle('active', state.selecting);
  $('#selection-bar').classList.toggle('hidden', !state.selecting);
  renderFiles();
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

function visibleFolders() {
  const wantHidden = state.vault === 'hidden' ? 1 : 0;
  return state.folders.filter((f) => (f.hidden || 0) === wantHidden);
}

function renderFolders() {
  const host = $('#folders');
  host.innerHTML = '';
  for (const folder of visibleFolders()) {
    const count = state.files.filter((f) => f.folderId === folder.id).length;
    const card = el('div', 'folder-card' + (state.currentFolder === folder.id ? ' active' : ''));
    card.innerHTML = `
      <div class="folder-swatch" style="background:${folder.color}"></div>
      <button class="folder-overflow" title="Options">⋯</button>
      <div>
        <div class="folder-name">${escapeHtml(folder.name)}</div>
        <div class="folder-count">${count} item${count === 1 ? '' : 's'}</div>
      </div>`;
    card.addEventListener('click', (e) => {
      if (e.target.closest('.folder-overflow')) { openFolderMenu(folder); return; }
      state.currentFolder = state.currentFolder === folder.id ? null : folder.id;
      renderFolders(); renderFiles();
    });
    host.appendChild(card);
  }
  const add = el('div', 'new-folder');
  add.innerHTML = '<span>＋ New Folder</span>';
  add.addEventListener('click', () => openNewFolder());
  host.appendChild(add);
}

function openNewFolder() {
  openModal(`
    <h3>New folder</h3>
    <input class="field" id="nf-name" placeholder="Folder name" maxlength="60" />
    <div class="color-grid" id="nf-colors"></div>
    <div class="btn-row">
      <button class="btn ghost" data-close>Cancel</button>
      <button class="btn" id="nf-create">Create</button>
    </div>`, (root) => {
    let color = FOLDER_COLORS[0];
    const grid = $('#nf-colors', root);
    FOLDER_COLORS.forEach((c, i) => {
      const d = el('div', 'color-dot' + (i === 0 ? ' active' : ''));
      d.style.background = c;
      d.addEventListener('click', () => { color = c; $$('.color-dot', grid).forEach((x) => x.classList.remove('active')); d.classList.add('active'); });
      grid.appendChild(d);
    });
    $('#nf-create', root).addEventListener('click', async () => {
      const name = $('#nf-name', root).value.trim() || 'Folder';
      await store.createFolder(name, color, state.vault === 'hidden');
      closeModal(); await refresh();
    });
    $('#nf-name', root).focus();
  });
}

function openFolderMenu(folder) {
  openModal(`
    <h3>${escapeHtml(folder.name)}</h3>
    <div class="menu">
      <button id="fm-rename">Rename</button>
      <button id="fm-color">Change colour</button>
      <button id="fm-delete" class="danger">Delete folder</button>
      <button data-close>Cancel</button>
    </div>`, (root) => {
    $('#fm-rename', root).addEventListener('click', () => {
      closeModal();
      promptText('Rename folder', folder.name, async (name) => {
        folder.name = name; await store.updateFolder(folder); await refresh();
      });
    });
    $('#fm-color', root).addEventListener('click', () => {
      closeModal(); openFolderColor(folder);
    });
    $('#fm-delete', root).addEventListener('click', async () => {
      closeModal();
      confirmModal(`Delete “${escapeHtml(folder.name)}”? Files inside will move back to the vault root.`, async () => {
        await store.deleteFolder(folder, true);
        if (state.currentFolder === folder.id) state.currentFolder = null;
        await refresh();
      });
    });
  });
}

function openFolderColor(folder) {
  openModal(`
    <h3>Folder colour</h3>
    <div class="color-grid" id="fc-colors"></div>
    <div class="btn-row"><button class="btn ghost" data-close>Done</button></div>`, (root) => {
    const grid = $('#fc-colors', root);
    FOLDER_COLORS.forEach((c) => {
      const d = el('div', 'color-dot' + (c === folder.color ? ' active' : ''));
      d.style.background = c;
      d.addEventListener('click', async () => {
        folder.color = c; await store.updateFolder(folder); await refresh();
        $$('.color-dot', grid).forEach((x) => x.classList.remove('active')); d.classList.add('active');
      });
      grid.appendChild(d);
    });
  });
}

// ---------------------------------------------------------------------------
// File grid
// ---------------------------------------------------------------------------

function visibleFiles() {
  const wantHidden = state.vault === 'hidden' ? 1 : 0;
  let list = state.files.filter((f) => (f.hidden || 0) === wantHidden);
  if (state.currentFolder) list = list.filter((f) => f.folderId === state.currentFolder);
  if (state.search) list = list.filter((f) => f.name.toLowerCase().includes(state.search));
  const key = state.sort;
  list.sort((a, b) => {
    let av = a[key], bv = b[key];
    if (key === 'name' || key === 'category') { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); return av < bv ? state.dir : av > bv ? -state.dir : 0; }
    return (av - bv) * state.dir;
  });
  return list;
}

function renderFiles() {
  // revoke stale thumbnail URLs
  for (const url of thumbUrls.values()) URL.revokeObjectURL(url);
  thumbUrls.clear();

  const host = $('#files');
  host.className = 'files' + (state.viewMode === 'list' ? ' list' : '');
  host.innerHTML = '';
  const list = visibleFiles();

  $('#item-count').textContent = `${list.length} item${list.length === 1 ? '' : 's'}`;
  $('#selection-count').textContent = `${state.selected.size} selected`;

  const showEmpty = list.length === 0 && visibleFolders().length === 0 && !state.search;
  $('#empty-state').classList.toggle('hidden', !showEmpty);

  for (const f of list) {
    const tile = el('div', 'tile' + (state.selecting ? ' selectable' : '') + (state.selected.has(f.id) ? ' selected' : ''));
    const badgeClass = f.category === CAT_PHOTO ? 'photo' : f.category === CAT_VIDEO ? 'video' : 'doc';
    const badgeText = f.category === CAT_PHOTO ? 'Photo' : f.category === CAT_VIDEO ? 'Video' : 'Doc';
    tile.innerHTML = `
      <div class="select-mark"></div>
      <div class="thumb"><span class="placeholder">${iconFor(f.category)}</span></div>
      <div class="meta">
        <div class="fname">${escapeHtml(f.name)}</div>
        <span class="badge ${badgeClass}">${badgeText}</span>
      </div>`;
    tile.addEventListener('click', () => onTileClick(f));
    host.appendChild(tile);
    loadThumb(f, tile);
  }
}

async function loadThumb(f, tile) {
  if (!f.thumbId) return;
  try {
    const blob = await store.readThumb(f);
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    thumbUrls.set(f.id, url);
    const thumb = $('.thumb', tile);
    if (thumb) { thumb.style.backgroundImage = `url(${url})`; thumb.innerHTML = ''; }
  } catch { /* leave placeholder */ }
}

function onTileClick(f) {
  if (state.selecting) {
    if (state.selected.has(f.id)) state.selected.delete(f.id); else state.selected.add(f.id);
    renderFiles();
    return;
  }
  openViewer(f);
}

// ---------------------------------------------------------------------------
// Import (file picker + drag & drop)
// ---------------------------------------------------------------------------

function wireImport() {
  const input = $('#file-input');
  $('#fab-upload').addEventListener('click', () => input.click());
  input.addEventListener('change', () => { if (input.files.length) importFiles([...input.files]); input.value = ''; });

  const overlay = $('#drop-overlay');
  let dragDepth = 0;
  window.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; overlay.classList.remove('hidden'); });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('dragleave', (e) => { e.preventDefault(); if (--dragDepth <= 0) { dragDepth = 0; overlay.classList.add('hidden'); } });
  window.addEventListener('drop', (e) => {
    e.preventDefault(); dragDepth = 0; overlay.classList.add('hidden');
    const files = [...(e.dataTransfer?.files || [])];
    if (files.length) importFiles(files);
  });
}

async function importFiles(files) {
  const total = files.reduce((s, f) => s + f.size, 0);
  let doneBytes = 0;
  showToast(`Encrypting ${files.length} file${files.length === 1 ? '' : 's'}…`, 0);
  const hidden = state.vault === 'hidden';
  for (const file of files) {
    const category = categoryForMime(file.type);
    let videoThumb = null;
    if (category === CAT_VIDEO) videoThumb = await captureVideoThumb(file).catch(() => null);
    let fileDone = 0;
    await store.importFile(file, { hidden, folderId: state.currentFolder, videoThumb }, (loaded) => {
      fileDone = loaded;
      updateToast((doneBytes + fileDone) / total);
    });
    doneBytes += file.size;
    updateToast(doneBytes / total);
  }
  hideToast();
  await refresh();
  await refreshStorageUI();
  await maybeNudgeBackup();
}

// Capture a poster frame from a video on the main thread (workers can't decode
// video). Small and transient; the big plaintext still goes straight to the worker.
function captureVideoThumb(file) {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const v = document.createElement('video');
    v.muted = true; v.playsInline = true; v.preload = 'metadata'; v.src = url;
    const cleanup = () => URL.revokeObjectURL(url);
    v.addEventListener('loadeddata', () => { try { v.currentTime = Math.min(1, (v.duration || 2) / 2); } catch { resolve(null); cleanup(); } });
    v.addEventListener('seeked', () => {
      const scale = Math.min(1, 320 / Math.max(v.videoWidth, v.videoHeight));
      const c = document.createElement('canvas');
      c.width = Math.max(1, Math.round(v.videoWidth * scale));
      c.height = Math.max(1, Math.round(v.videoHeight * scale));
      c.getContext('2d').drawImage(v, 0, 0, c.width, c.height);
      c.toBlob((b) => { resolve(b); cleanup(); }, 'image/jpeg', 0.72);
    });
    v.addEventListener('error', () => { resolve(null); cleanup(); });
    setTimeout(() => { resolve(null); cleanup(); }, 8000);
  });
}

// ---------------------------------------------------------------------------
// Bulk actions
// ---------------------------------------------------------------------------

function bulkDelete() {
  if (!state.selected.size) return;
  confirmModal(`Delete ${state.selected.size} item(s)? This cannot be undone.`, async () => {
    const targets = state.files.filter((f) => state.selected.has(f.id));
    for (const f of targets) await store.deleteFile(f);
    toggleSelectMode(false);
    await refresh(); await refreshStorageUI();
  });
}

function bulkMove() {
  if (!state.selected.size) return;
  const folders = visibleFolders();
  const options = folders.map((f) => `<button data-fid="${f.id}">${escapeHtml(f.name)}</button>`).join('');
  openModal(`
    <h3>Move to folder</h3>
    <div class="menu">
      <button data-fid="">Vault root</button>
      ${options}
    </div>`, (root) => {
    $$('.menu button', root).forEach((b) => b.addEventListener('click', async () => {
      const fid = b.dataset.fid || null;
      const targets = state.files.filter((f) => state.selected.has(f.id));
      for (const f of targets) { f.folderId = fid; await store.updateFile(f); }
      closeModal(); toggleSelectMode(false); await refresh();
    }));
  });
}

// ---------------------------------------------------------------------------
// Viewer
// ---------------------------------------------------------------------------

let viewerUrl = null;

async function openViewer(f) {
  const viewer = $('#viewer');
  const stage = $('#viewer-stage');
  stage.innerHTML = '<div class="doc-preview muted">Decrypting…</div>';
  viewer.classList.remove('hidden');
  $('#viewer-details').classList.add('hidden');
  renderDetails(f);

  try {
    if (f.category === CAT_VIDEO) {
      // Stream through the service worker so plaintext never fully materialises.
      stage.innerHTML = '';
      const v = document.createElement('video');
      v.controls = true; v.autoplay = true; v.playsInline = true;
      v.src = `${location.origin}/vault-stream/${f.id}`;
      stage.appendChild(v);
    } else if (f.category === CAT_PHOTO) {
      const blob = await store.readFileBlob(f);
      if (viewerUrl) URL.revokeObjectURL(viewerUrl);
      viewerUrl = URL.createObjectURL(blob);
      stage.innerHTML = '';
      const img = document.createElement('img');
      img.src = viewerUrl;
      enableZoom(img, stage);
      stage.appendChild(img);
    } else {
      const blob = await store.readFileBlob(f);
      if (viewerUrl) URL.revokeObjectURL(viewerUrl);
      viewerUrl = URL.createObjectURL(blob);
      if (f.mime === 'application/pdf') {
        stage.innerHTML = `<iframe src="${viewerUrl}" style="width:100%;height:100%;border:0;background:#fff"></iframe>`;
      } else {
        stage.innerHTML = `<div class="doc-preview"><p>${escapeHtml(f.name)}</p><a class="btn" href="${viewerUrl}" download="${escapeHtml(f.name)}">Download to view</a></div>`;
      }
    }
  } catch (err) {
    stage.innerHTML = `<div class="doc-preview muted">Could not open: ${escapeHtml(String(err.message || err))}</div>`;
  }
}

function renderDetails(f) {
  const d = $('#viewer-details');
  d.innerHTML = `
    <h3>${escapeHtml(f.name)}</h3>
    <div class="detail-row"><span class="k">Type</span><span>${escapeHtml(f.mime || '—')}</span></div>
    <div class="detail-row"><span class="k">Size</span><span>${fmtBytes(f.size)}</span></div>
    <div class="detail-row"><span class="k">Added</span><span>${new Date(f.dateAdded).toLocaleString()}</span></div>
    <div class="detail-row"><span class="k">Category</span><span>${f.category}</span></div>
    <div class="btn-row">
      <button class="btn" id="vd-export">Export</button>
      <button class="btn ghost" id="vd-move">Move</button>
      <button class="btn ghost" id="vd-rename">Rename</button>
      <button class="btn ghost danger" id="vd-delete">Delete</button>
    </div>`;
  $('#vd-export', d).addEventListener('click', () => exportSingle(f));
  $('#vd-move', d).addEventListener('click', () => { state.selected = new Set([f.id]); bulkMove(); });
  $('#vd-rename', d).addEventListener('click', () => {
    promptText('Rename', f.name, async (name) => { f.name = name; await store.updateFile(f); renderDetails(f); await refresh(); });
  });
  $('#vd-delete', d).addEventListener('click', () => {
    confirmModal('Delete this file? This cannot be undone.', async () => { await store.deleteFile(f); closeViewer(); await refresh(); await refreshStorageUI(); });
  });
}

async function exportSingle(f) {
  const blob = await store.readFileBlob(f);
  await saveBlob(blob, f.name);
}

function enableZoom(img, stage) {
  let scale = 1;
  img.style.transformOrigin = 'center center';
  stage.onwheel = (e) => {
    e.preventDefault();
    scale = Math.min(6, Math.max(1, scale + (e.deltaY < 0 ? 0.2 : -0.2)));
    img.style.transform = `scale(${scale})`;
  };
  img.ondblclick = () => { scale = scale > 1 ? 1 : 2.5; img.style.transform = `scale(${scale})`; };
}

function wireViewer() {
  $('#viewer-close').addEventListener('click', closeViewer);
  $('#viewer-info-btn').addEventListener('click', () => $('#viewer-details').classList.toggle('hidden'));
}

function closeViewer() {
  const stage = $('#viewer-stage');
  stage.innerHTML = '';
  if (viewerUrl) { URL.revokeObjectURL(viewerUrl); viewerUrl = null; }
  $('#viewer').classList.add('hidden');
}

// ---------------------------------------------------------------------------
// Hidden vault gate
// ---------------------------------------------------------------------------

function wireHiddenGate() {
  $$('#keypad button').forEach((b) => {
    if (b.id === 'key-del' || b.id === 'key-bio') return;
    b.addEventListener('click', () => onPinDigit(b.textContent.trim()));
  });
  $('#key-del').addEventListener('click', () => { state.pinBuffer = state.pinBuffer.slice(0, -1); renderPinDots(); });
  $('#key-bio').addEventListener('click', () => biometricUnlock());
  $('#hidden-biometric').addEventListener('click', () => biometricUnlock());
}

function renderHiddenGate() {
  const configured = state.hiddenMethods.length > 0;
  const hasPin = state.hiddenMethods.includes('pass');
  const hasBio = state.hiddenMethods.includes('prf');
  state.pinBuffer = ''; state.pinFirst = '';
  if (!configured) {
    state.pinStage = 'enter';
    $('#hidden-title').textContent = 'Set a passcode';
    $('#hidden-sub').textContent = 'Choose a 4-digit passcode for the hidden vault.';
  } else {
    state.pinStage = 'unlock';
    $('#hidden-title').textContent = 'Hidden vault';
    $('#hidden-sub').textContent = hasPin ? 'Enter your passcode to continue.' : 'Use biometrics to continue.';
  }
  // Show biometric affordance only when a passkey method exists.
  $('#key-bio').classList.toggle('hidden', !(configured && hasBio));
  $('#hidden-biometric').classList.toggle('hidden', !(configured && hasBio && !hasPin));
  $('#keypad').classList.toggle('hidden', configured && !hasPin);
  $('#passcode-dots').classList.toggle('hidden', configured && !hasPin);
  renderPinDots();
  updateLockoutUI();
  if (configured && hasBio && !hasPin) biometricUnlock();
}

function renderPinDots() {
  $$('#passcode-dots span').forEach((s, i) => s.classList.toggle('filled', i < state.pinBuffer.length));
}

async function onPinDigit(d) {
  if (Date.now() < state.lockedUntil) return;
  if (state.pinBuffer.length >= 4) return;
  state.pinBuffer += d;
  renderPinDots();
  if (state.pinBuffer.length === 4) setTimeout(handlePinComplete, 120);
}

async function handlePinComplete() {
  const pin = state.pinBuffer;
  const configured = state.hiddenMethods.length > 0;
  if (!configured) {
    if (state.pinStage === 'enter') {
      state.pinFirst = pin; state.pinBuffer = ''; renderPinDots();
      state.pinStage = 'confirm';
      $('#hidden-sub').textContent = 'Confirm your passcode.';
      return;
    }
    // confirm stage
    if (pin !== state.pinFirst) {
      state.pinBuffer = ''; renderPinDots(); state.pinStage = 'enter';
      $('#hidden-sub').textContent = "Didn't match — set a passcode again.";
      return;
    }
    await store.setupHidden('pass', pin);
    state.hiddenMethods = await store.listHiddenMethods();
    state.hiddenUnlocked = true;
    onHiddenOpened();
    return;
  }
  // unlock
  try {
    await store.unlockHidden('pass', pin);
    state.wrongCount = 0;
    state.hiddenUnlocked = true;
    onHiddenOpened();
  } catch {
    state.pinBuffer = ''; renderPinDots();
    registerWrongAttempt();
  }
}

function registerWrongAttempt() {
  state.wrongCount++;
  if (state.wrongCount >= LOCKOUT_THRESHOLD) {
    const idx = Math.min(state.wrongCount - LOCKOUT_THRESHOLD, LOCKOUT_SCHEDULE_MS.length - 1);
    state.lockedUntil = Date.now() + LOCKOUT_SCHEDULE_MS[idx];
  }
  updateLockoutUI();
}

function updateLockoutUI() {
  const msg = $('#lockout-msg');
  if (Date.now() >= state.lockedUntil) {
    msg.classList.add('hidden');
    if (state.wrongCount > 0 && state.wrongCount < LOCKOUT_THRESHOLD) {
      msg.classList.remove('hidden');
      msg.textContent = `${LOCKOUT_THRESHOLD - state.wrongCount} attempt(s) before lockout`;
    }
    return;
  }
  msg.classList.remove('hidden');
  const tick = () => {
    const left = Math.ceil((state.lockedUntil - Date.now()) / 1000);
    if (left <= 0) { msg.classList.add('hidden'); return; }
    msg.textContent = `Too many attempts — locked for ${left}s`;
    setTimeout(tick, 1000);
  };
  tick();
}

async function biometricUnlock() {
  if (!state.hiddenMethods.includes('prf') || !state.passkeyId) return;
  try {
    const secret = await wa.getPrfSecret(state.passkeyId);
    if (!secret) throw new Error('No PRF result');
    await store.unlockHidden('prf', secret);
    state.wrongCount = 0;
    state.hiddenUnlocked = true;
    onHiddenOpened();
  } catch (err) {
    $('#hidden-sub').textContent = 'Biometric unlock failed. Try again.';
  }
}

function onHiddenOpened() {
  state.vault = 'hidden';
  $$('#vault-pill .pill').forEach((p) => p.classList.toggle('active', p.dataset.vault === 'hidden'));
  state.currentFolder = null;
  switchTab('vault');
  renderFolders(); renderFiles();
  resetAutolock();
}

function lockHiddenNow() {
  if (!state.hiddenUnlocked) return;
  store.lockHidden();
  state.hiddenUnlocked = false;
  if (state.vault === 'hidden') {
    state.vault = 'unlocked';
    $$('#vault-pill .pill').forEach((p) => p.classList.toggle('active', p.dataset.vault === 'unlocked'));
    state.currentFolder = null;
    renderFolders(); renderFiles();
  }
}

// ---------------------------------------------------------------------------
// Auto-lock
// ---------------------------------------------------------------------------

function wireAutolock() {
  ['pointerdown', 'keydown', 'touchstart'].forEach((ev) =>
    window.addEventListener(ev, resetAutolock, { passive: true }));
  document.addEventListener('visibilitychange', () => { if (document.hidden) lockHiddenNow(); });
  resetAutolock();
}

function resetAutolock() {
  clearTimeout(autolockTimer);
  if (!state.autolockMs || state.autolockMs <= 0) return;
  autolockTimer = setTimeout(() => lockHiddenNow(), state.autolockMs);
}

// ---------------------------------------------------------------------------
// Security panel
// ---------------------------------------------------------------------------

function wireSecurity() {
  $$('#seg-theme button').forEach((b) => b.addEventListener('click', async () => {
    state.theme = b.dataset.theme;
    $$('#seg-theme button').forEach((x) => x.classList.toggle('active', x === b));
    await store.setSetting('theme', state.theme);
    applyTheme(state.theme);
  }));
  $$('#seg-autolock button').forEach((b) => b.addEventListener('click', async () => {
    state.autolockMs = Number(b.dataset.lock);
    $$('#seg-autolock button').forEach((x) => x.classList.toggle('active', x === b));
    await store.setSetting('autolockMs', state.autolockMs);
    resetAutolock();
  }));

  $('#tg-hidden').addEventListener('change', (e) => onToggleHidden(e.target.checked));
  $('#tg-bio').addEventListener('change', (e) => onToggleBio(e.target.checked));
  $('#tg-pin').addEventListener('change', (e) => onTogglePin(e.target.checked));

  $('#btn-export').addEventListener('click', () => exportArchive());
  $('#btn-import').addEventListener('click', () => $('#archive-input').click());
  $('#archive-input').addEventListener('change', () => { const f = $('#archive-input').files[0]; if (f) importArchiveFlow(f); $('#archive-input').value = ''; });
}

async function refreshSecurityUI() {
  state.hiddenMethods = await store.listHiddenMethods();
  $('#tg-hidden').checked = state.hiddenMethods.length > 0;
  $('#tg-bio').checked = state.hiddenMethods.includes('prf');
  $('#tg-pin').checked = state.hiddenMethods.includes('pass');
  const avail = wa.webauthnAvailable();
  $('#bio-availability').textContent = avail
    ? 'A passkey (Touch ID / Face ID / Windows Hello) can unlock the hidden vault on this browser.'
    : 'This browser does not expose passkeys with PRF — use the PIN fallback.';
  $$('#seg-theme button').forEach((x) => x.classList.toggle('active', x.dataset.theme === state.theme));
  $$('#seg-autolock button').forEach((x) => x.classList.toggle('active', Number(x.dataset.lock) === state.autolockMs));
  await refreshBackupStatus();
  await refreshStorageUI();
  await refreshPersistence();
}

async function onToggleHidden(on) {
  if (on) {
    if (state.hiddenMethods.length === 0) switchTab('hidden');
  } else {
    if (state.hiddenMethods.length === 0) return;
    const hiddenFiles = state.files.filter((f) => f.hidden);
    confirmModal(
      `Disable the hidden vault? This permanently deletes its unlock key and its ${hiddenFiles.length} file(s). ` +
      'They cannot be recovered — the key is destroyed, so re-creating the vault with the same passcode will NOT bring them back.',
      async () => {
        // Must be unlocked to read the blobs we are deleting; if locked, we can
        // still drop metadata + blobs by id (no decryption needed to delete).
        for (const f of hiddenFiles) await store.deleteFile(f);
        for (const folder of state.folders.filter((x) => x.hidden)) await store.deleteFolder(folder, false);
        for (const m of [...state.hiddenMethods]) await store.removeHiddenMethod(m);
        lockHiddenNow();
        state.hiddenMethods = await store.listHiddenMethods();
        state.passkeyId = null;
        await store.setSetting('passkeyId', null);
        await refresh();
        await refreshSecurityUI();
      },
      () => refreshSecurityUI());
  }
}

async function onTogglePin(on) {
  if (on) {
    if (state.hiddenMethods.includes('pass')) return;
    if (state.hiddenMethods.length === 0) { switchTab('hidden'); return; }
    // Add PIN as an additional method — need to unlock via existing method.
    addPinMethod();
  } else {
    if (!state.hiddenMethods.includes('pass')) return;
    if (state.hiddenMethods.length <= 1) { $('#tg-pin').checked = true; alert('Keep at least one unlock method.'); return; }
    await store.removeHiddenMethod('pass');
    state.hiddenMethods = await store.listHiddenMethods();
    await refreshSecurityUI();
  }
}

function addPinMethod() {
  // Ask for existing unlock (biometric) then a new PIN.
  promptPin('Set a 4-digit PIN', async (pin) => {
    try {
      let unlockMethod, unlockSecret;
      if (state.hiddenMethods.includes('prf')) {
        const secret = await wa.getPrfSecret(state.passkeyId);
        unlockMethod = 'prf'; unlockSecret = secret;
      }
      await store.addHiddenMethod(unlockMethod, unlockSecret, 'pass', pin);
      state.hiddenMethods = await store.listHiddenMethods();
      await refreshSecurityUI();
    } catch (err) { alert('Could not add PIN: ' + err.message); await refreshSecurityUI(); }
  }, () => refreshSecurityUI());
}

async function onToggleBio(on) {
  if (on) {
    if (!wa.webauthnAvailable()) { $('#tg-bio').checked = false; alert('Passkeys are not available in this browser.'); return; }
    try {
      const { credentialId, enabled } = await wa.registerPasskey();
      if (!enabled) { $('#tg-bio').checked = false; alert('This device registered a passkey but it does not support the PRF extension needed for encryption. Use the PIN fallback.'); return; }
      state.passkeyId = credentialId;
      await store.setSetting('passkeyId', credentialId);
      const secret = await wa.getPrfSecret(credentialId);
      if (state.hiddenMethods.length === 0) {
        await store.setupHidden('prf', secret);
      } else if (state.hiddenMethods.includes('pass')) {
        // Need the existing PIN to add biometric as a second method.
        promptPin('Enter your PIN to add biometrics', async (pin) => {
          await store.addHiddenMethod('pass', pin, 'prf', secret);
          state.hiddenMethods = await store.listHiddenMethods();
          await refreshSecurityUI();
        }, () => { $('#tg-bio').checked = false; });
        return;
      } else {
        await store.addHiddenMethod('prf', secret, 'prf', secret);
      }
      state.hiddenMethods = await store.listHiddenMethods();
      await refreshSecurityUI();
    } catch (err) {
      $('#tg-bio').checked = false;
      alert('Biometric setup failed: ' + (err.message || err));
    }
  } else {
    if (!state.hiddenMethods.includes('prf')) return;
    if (state.hiddenMethods.length <= 1) { $('#tg-bio').checked = true; alert('Keep at least one unlock method.'); return; }
    await store.removeHiddenMethod('prf');
    state.hiddenMethods = await store.listHiddenMethods();
    await refreshSecurityUI();
  }
}

// ---------------------------------------------------------------------------
// Storage / persistence UI
// ---------------------------------------------------------------------------

async function refreshStorageUI() {
  const cats = { [CAT_PHOTO]: 0, [CAT_VIDEO]: 0, [CAT_DOC]: 0 };
  for (const f of state.files) cats[f.category] = (cats[f.category] || 0) + f.size;
  const totalUsed = cats[CAT_PHOTO] + cats[CAT_VIDEO] + cats[CAT_DOC];
  $('#storage-used').textContent = totalUsed ? fmtBytes(totalUsed) + ' stored' : 'Empty vault';

  const bar = $('#storage-bar');
  if (bar) {
    bar.innerHTML = '';
    const denom = totalUsed || 1;
    for (const cat of [CAT_PHOTO, CAT_VIDEO, CAT_DOC]) {
      const span = el('span');
      span.style.width = `${(cats[cat] / denom) * 100}%`;
      span.style.background = CATEGORY_COLORS[cat];
      bar.appendChild(span);
    }
    const legend = $('#storage-legend');
    legend.innerHTML = `
      <span><span class="dot" style="background:${CATEGORY_COLORS[CAT_PHOTO]}"></span>Photos ${fmtBytes(cats[CAT_PHOTO])}</span>
      <span><span class="dot" style="background:${CATEGORY_COLORS[CAT_VIDEO]}"></span>Videos ${fmtBytes(cats[CAT_VIDEO])}</span>
      <span><span class="dot" style="background:${CATEGORY_COLORS[CAT_DOC]}"></span>Docs ${fmtBytes(cats[CAT_DOC])}</span>`;
    const est = await store.storageEstimate();
    if (est) {
      $('#storage-est').textContent = `${fmtBytes(est.usage || 0)} used of ~${fmtBytes(est.quota || 0)} available to this site.`;
    }
  }
}

async function refreshPersistence() {
  const el2 = $('#persist-status');
  if (!el2) return;
  const res = await store.requestPersistence();
  if (!res.supported) { el2.className = 'persist-status warn'; el2.textContent = 'This browser does not support persistent storage — keep a backup.'; return; }
  if (res.persisted) { el2.className = 'persist-status ok'; el2.textContent = '✓ Storage is persistent — the browser will not clear the vault to reclaim space.'; }
  else { el2.className = 'persist-status warn'; el2.textContent = '⚠ Storage is not persistent. The browser may clear the vault when space runs low. Keep an exported backup.'; }
}

// ---------------------------------------------------------------------------
// Backup / archive
// ---------------------------------------------------------------------------

async function refreshBackupStatus() {
  const ts = await store.getLastBackup();
  const el3 = $('#backup-status');
  if (!ts) { el3.innerHTML = '<strong style="color:var(--doc)">No backup yet.</strong> Export one now — clearing browser data would erase everything.'; return; }
  const days = Math.floor((Date.now() - ts) / 86400000);
  const when = new Date(ts).toLocaleString();
  if (days >= 14) el3.innerHTML = `<strong style="color:var(--doc)">Last backup ${days} days ago</strong> (${when}). Consider exporting again.`;
  else el3.textContent = `Last backup: ${when}.`;
}

async function maybeNudgeBackup() {
  const ts = await store.getLastBackup();
  if (!ts) return; // don't nag on very first import; Security panel already warns
}

function exportArchive() {
  const includeHidden = state.hiddenUnlocked;
  promptPassphrase('Export encrypted archive', `Choose a passphrase to protect the .fwvault file. ${includeHidden ? 'The unlocked hidden vault will be included.' : 'Hidden files are excluded (unlock them first to include).'}`, async (pass) => {
    showToast('Building encrypted archive…', 0);
    try {
      const blob = await store.exportVault(pass, { includeHidden }, (done, total) => updateToast(done / total));
      hideToast();
      await saveBlob(blob, `filewall-${new Date().toISOString().slice(0, 10)}.fwvault`);
      await store.setLastBackup(Date.now());
      await refreshBackupStatus();
    } catch (err) { hideToast(); alert('Export failed: ' + err.message); }
  });
}

function importArchiveFlow(file) {
  promptPassphrase('Import archive', 'Enter the passphrase for this .fwvault file.', async (pass) => {
    showToast('Decrypting & importing…', 0);
    try {
      const created = await store.importArchive(file, pass, { hidden: state.vault === 'hidden' && state.hiddenUnlocked }, (done, total) => updateToast(done / total));
      hideToast();
      await refresh(); await refreshStorageUI();
      alert(`Imported ${created.length} file(s).`);
    } catch (err) { hideToast(); alert('Import failed: ' + err.message); }
  });
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

function applyTheme(theme) {
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
}

// ---------------------------------------------------------------------------
// Modals / prompts
// ---------------------------------------------------------------------------

function openModal(html, onMount) {
  const host = $('#modal-host');
  host.innerHTML = `<div class="modal">${html}</div>`;
  host.classList.remove('hidden');
  host.onclick = (e) => { if (e.target === host || e.target.hasAttribute('data-close')) closeModal(); };
  onMount?.(host);
}
function closeModal() { const host = $('#modal-host'); host.classList.add('hidden'); host.innerHTML = ''; }

function confirmModal(message, onYes, onNo) {
  openModal(`
    <h3>Please confirm</h3>
    <p class="modal-note">${message}</p>
    <div class="btn-row">
      <button class="btn ghost" id="cf-no">Cancel</button>
      <button class="btn danger" id="cf-yes">Confirm</button>
    </div>`, (root) => {
    $('#cf-no', root).addEventListener('click', () => { closeModal(); onNo?.(); });
    $('#cf-yes', root).addEventListener('click', async () => { closeModal(); await onYes(); });
  });
}

function promptText(title, value, onOk) {
  openModal(`
    <h3>${title}</h3>
    <input class="field" id="pt-input" value="${escapeHtml(value)}" maxlength="120" />
    <div class="btn-row"><button class="btn ghost" data-close>Cancel</button><button class="btn" id="pt-ok">Save</button></div>`, (root) => {
    const input = $('#pt-input', root); input.focus(); input.select();
    $('#pt-ok', root).addEventListener('click', async () => { const v = input.value.trim(); if (v) { closeModal(); await onOk(v); } });
  });
}

function promptPassphrase(title, note, onOk) {
  openModal(`
    <h3>${title}</h3>
    <p class="modal-note">${note}</p>
    <input class="field" id="pp-input" type="password" placeholder="Passphrase" />
    <div class="btn-row"><button class="btn ghost" data-close>Cancel</button><button class="btn" id="pp-ok">Continue</button></div>`, (root) => {
    const input = $('#pp-input', root); input.focus();
    const go = async () => { const v = input.value; if (v && v.length >= 4) { closeModal(); await onOk(v); } else input.placeholder = 'At least 4 characters'; };
    $('#pp-ok', root).addEventListener('click', go);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  });
}

function promptPin(title, onOk, onCancel) {
  openModal(`
    <h3>${title}</h3>
    <input class="field" id="pin-input" inputmode="numeric" pattern="[0-9]*" maxlength="4" placeholder="4-digit PIN" />
    <div class="btn-row"><button class="btn ghost" id="pin-cancel">Cancel</button><button class="btn" id="pin-ok">Set</button></div>`, (root) => {
    const input = $('#pin-input', root); input.focus();
    $('#pin-cancel', root).addEventListener('click', () => { closeModal(); onCancel?.(); });
    $('#pin-ok', root).addEventListener('click', async () => {
      const v = input.value.trim();
      if (/^\d{4}$/.test(v)) { closeModal(); await onOk(v); } else input.placeholder = 'Enter exactly 4 digits';
    });
  });
}

// ---------------------------------------------------------------------------
// Toast (progress)
// ---------------------------------------------------------------------------

function showToast(msg, frac) { $('#toast-msg').textContent = msg; $('#toast-fill').style.width = `${(frac || 0) * 100}%`; $('#toast').classList.remove('hidden'); }
function updateToast(frac) { $('#toast-fill').style.width = `${Math.min(1, frac || 0) * 100}%`; }
function hideToast() { $('#toast').classList.add('hidden'); }

// ---------------------------------------------------------------------------
// Save helper — showSaveFilePicker (Chromium) or <a download> fallback
// ---------------------------------------------------------------------------

async function saveBlob(blob, filename) {
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: filename });
      const w = await handle.createWritable();
      await w.write(blob); await w.close();
      return;
    } catch (err) { if (err.name === 'AbortError') return; /* fall through */ }
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; document.body.appendChild(a); a.click();
  a.remove(); setTimeout(() => URL.revokeObjectURL(url), 4000);
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function iconFor(cat) { return cat === CAT_PHOTO ? '🖼' : cat === CAT_VIDEO ? '🎞' : '📄'; }
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}
