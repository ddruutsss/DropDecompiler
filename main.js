const { app, BrowserWindow, Menu, ipcMain, dialog, shell, clipboard, Notification, safeStorage, nativeTheme } = require('electron');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { spawn } = require('child_process');
const AdmZip = require('adm-zip');
const { Tools, decompile, countFiles, isUrl, SUPPORTED_EXTS, rebuildFolder } = require('./src/core');
const ai = require('./src/ai');
const { capture } = require('./src/capture');

// The installed app keeps using the same data folder as `npm start` (settings, history and the
// ~1 GB of downloaded decompilers), instead of one named after the product.
if (app.isPackaged) app.setPath('userData', path.join(app.getPath('appData'), 'drop-decompiler'));

const MAX_LIST = 100000;
const MAX_READ = 8 * 1024 * 1024;
const MAX_HISTORY = 100;
const IS_WIN = process.platform === 'win32';

// Title-bar colours per UI theme (Windows draws min/max/close with these).
const OVERLAY = {
  dark: { color: '#1b1e23', symbolColor: '#d8dbe0', bg: '#16181c' },
  light: { color: '#eef0f5', symbolColor: '#1d2330', bg: '#f7f8fb' },
};

const DEFAULTS = {
  theme: 'dark',
  codeTheme: 'auto',
  fontSize: 13,
  ghidraTimeout: 60,
  verifyBuild: true, // test-build .NET output with `dotnet build` and fix what it can
  notify: true,
  autoReadme: true,
  wrapLines: false,
  sidebarWidth: 340,
  treeWidth: 300,
  sidebarHidden: false,
  aiModel: ai.DEFAULT_MODEL,
  aiAutoReconstruct: false, // start the AI reconstruction as soon as a file is decompiled
  webMaxPages: 20, // pages of a website visited per link
  // Accuracy: get as close to the original source as the program allows.
  symbols: true, // download debug symbols (PDB) from the Microsoft / NuGet symbol servers
  originalSources: true, // download published original sources (Source Link, Maven Central, source maps)
  thoroughNative: false, // extra Ghidra analyzers: better function signatures, slower
  androidDeobf: false, // give obfuscated Android names readable placeholders (when there is no mapping file)
  iosCode: true, // decompile an iOS app's executable with Ghidra (slow) in addition to headers / Swift interfaces
};
const THEMES = ['dark', 'light', 'system'];

/** 'dark' or 'light': the theme actually shown ('system' follows Windows). */
function effectiveTheme() {
  if (settings.theme === 'light') return 'light';
  if (settings.theme === 'dark') return 'dark';
  return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
}

function applyTheme() {
  nativeTheme.themeSource = THEMES.includes(settings.theme) ? settings.theme : 'dark';
  if (!win || win.isDestroyed()) return;
  const t = OVERLAY[effectiveTheme()];
  win.setTitleBarOverlay({ color: t.color, symbolColor: t.symbolColor, height: 36 });
  win.setBackgroundColor(t.bg);
  sendUI('theme', effectiveTheme());
}

let win;
let tools;
let settings = {};
let history = [];
let bookmarks = {};
const knownOutDirs = new Set(); // only these may be browsed by the renderer

// ---------------------------------------------------------------- persistence

const dataFile = (name) => path.join(app.getPath('userData'), name);

function readJson(name, fallback) {
  try { return JSON.parse(fs.readFileSync(dataFile(name), 'utf8')); } catch { return fallback; }
}

// Written to a temp file first so a crash mid-write can't leave half a file.
const writeQueue = new Map();
function writeJson(name, value) {
  const text = JSON.stringify(value, null, 2);
  const prev = writeQueue.get(name) || Promise.resolve();
  const next = prev.then(async () => {
    const file = dataFile(name);
    await fsp.writeFile(file + '.tmp', text);
    await fsp.rename(file + '.tmp', file);
  }).catch(() => {});
  writeQueue.set(name, next);
  return next;
}

function loadState() {
  settings = { ...DEFAULTS, ...readJson('settings.json', {}) };
  if (!settings.outputRoot) settings.outputRoot = path.join(app.getPath('documents'), 'DropDecompiler Output');
  history = readJson('history.json', []).filter((h) => h && h.outDir);
  bookmarks = readJson('bookmarks.json', {});
  for (const h of history) knownOutDirs.add(path.resolve(h.outDir));
}

const saveSettings = () => writeJson('settings.json', settings);
const saveHistory = () => writeJson('history.json', history);
const saveBookmarks = () => writeJson('bookmarks.json', bookmarks);

function addHistory(entry) {
  const key = path.resolve(entry.outDir);
  history = history.filter((h) => path.resolve(h.outDir) !== key);
  history.unshift({ ...entry, outDir: key, date: Date.now() });
  history.length = Math.min(history.length, MAX_HISTORY);
  knownOutDirs.add(key);
  saveHistory();
  return history[0];
}

// ---------------------------------------------------------------- window

function argFiles(argv) {
  return argv
    .slice(1)
    .filter((a) => !a.startsWith('-') && path.resolve(a) !== path.resolve(__dirname))
    .map((a) => path.resolve(a))
    .filter((a) => { try { return fs.statSync(a).isFile(); } catch { return false; } });
}

function createWindow() {
  nativeTheme.themeSource = THEMES.includes(settings.theme) ? settings.theme : 'dark';
  const theme = OVERLAY[effectiveTheme()];
  const b = settings.bounds || {};
  win = new BrowserWindow({
    width: b.width || 1440,
    height: b.height || 900,
    x: b.x,
    y: b.y,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: theme.bg,
    title: 'DropDecompiler',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    show: false,
    // Custom title bar with the menu is drawn by the page; Windows still supplies min/max/close.
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: theme.color, symbolColor: theme.symbolColor, height: 36 },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  if (settings.maximized) win.maximize();
  win.once('ready-to-show', () => win.show());
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  // Never navigate away or open pop-ups when something is dropped or clicked.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.once('did-finish-load', () => {
    const files = argFiles(process.argv);
    if (files.length) win.webContents.send('add-files', files);
  });
  win.on('close', () => {
    settings.maximized = win.isMaximized();
    if (!settings.maximized && !win.isMinimized()) settings.bounds = win.getBounds();
    saveSettings();
  });
}

function sendUI(channel, data) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, data);
}

// ---------------------------------------------------------------- job queue

const queue = [];
const controllers = new Map(); // job id -> AbortController of the running job
let running = false;

function send(id, data) {
  sendUI('job-event', { id, ...data });
  if (!win || win.isDestroyed()) return;
  if (typeof data.progress === 'number' && data.progress >= 0) win.setProgressBar(data.progress / 100);
  if (data.status === 'running') win.setProgressBar(2, { mode: 'indeterminate' });
}

function notify(title, body, id) {
  if (!settings.notify || !Notification.isSupported() || (win && win.isFocused())) return;
  const n = new Notification({ title, body, icon: path.join(__dirname, 'assets', 'icon.png') });
  n.on('click', () => {
    if (win.isMinimized()) win.restore();
    win.focus();
    sendUI('focus-job', id);
  });
  n.show();
  win.flashFrame(true);
}

function displayName(file) {
  if (!isUrl(file)) return path.basename(file);
  const u = new URL(file);
  return u.host + (u.pathname === '/' ? '' : u.pathname);
}

async function pump() {
  if (running) return;
  running = true;
  while (queue.length) {
    const { id, file } = queue.shift();
    const ctl = new AbortController();
    controllers.set(id, ctl);
    send(id, { status: 'running' });
    try {
      await fsp.mkdir(settings.outputRoot, { recursive: true });
      const result = await decompile(tools, file, settings.outputRoot, (message, opts = {}) => send(id, { log: message, ...opts }), {
        signal: ctl.signal,
        ghidraTimeout: settings.ghidraTimeout,
        verifyBuild: settings.verifyBuild,
        iosCode: settings.iosCode,
        capture, // websites are loaded in a hidden browser window
        maxPages: settings.webMaxPages,
        symbols: settings.symbols,
        originalSources: settings.originalSources,
        thorough: settings.thoroughNative,
        androidDeobf: settings.androidDeobf,
      });
      const entry = addHistory({ ...result, file, name: displayName(file), created: true });
      send(id, { status: 'done', result: entry });
      notify('Decompiled ' + displayName(file), `${result.files.toLocaleString()} files · ${result.engineName}`, id);
    } catch (err) {
      if (err.cancelled) send(id, { status: 'cancelled' });
      else {
        send(id, { status: 'error', error: err.message });
        notify('Could not decompile ' + displayName(file), err.message.split('\n')[0], id);
      }
    } finally {
      controllers.delete(id);
    }
  }
  running = false;
  if (win && !win.isDestroyed()) win.setProgressBar(-1);
}

// ---------------------------------------------------------------- files

function assertKnown(dir) {
  const resolved = path.resolve(String(dir));
  if (!knownOutDirs.has(resolved)) throw new Error('Unknown output folder');
  return resolved;
}

function inside(root, rel) {
  const full = path.resolve(root, String(rel || ''));
  if (full !== root && !full.startsWith(root + path.sep)) throw new Error('Invalid path');
  return full;
}

async function listFiles(root) {
  const out = [];
  async function walk(dir, rel) {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      if (out.length >= MAX_LIST) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (r === '.dropdecompiler.json') continue; // DropDecompiler's own notes, not output
      if (e.isDirectory()) await walk(path.join(dir, e.name), r);
      else out.push(r);
    }
  }
  await walk(root, '');
  return out;
}

/** Text of a file, or null for binary / huge files. */
async function readText(full, limit = MAX_READ) {
  const fh = await fsp.open(full, 'r');
  try {
    const { size } = await fh.stat();
    const len = Math.min(size, limit);
    const buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, 0);
    if (buf.subarray(0, 8000).includes(0)) return { binary: true, size };
    return { text: buf.toString('utf8'), size, truncated: size > limit };
  } finally {
    await fh.close();
  }
}

// ---------------------------------------------------------------- search

const NOT_TEXT = /\.(png|jpe?g|gif|webp|ico|bmp|svgz|so|dll|exe|jar|zip|class|dex|arsc|ttf|otf|woff2?|mp3|ogg|wav|mp4|bin|dat|db|pdb|res|lib|obj)$/i;
const MAX_HITS = 5000;
let searchGen = 0;

function buildRegex({ query, regex, caseSensitive, wholeWord }) {
  let src = regex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (wholeWord) src = `\\b(?:${src})\\b`;
  try {
    return new RegExp(src, caseSensitive ? '' : 'i');
  } catch (e) {
    throw new Error('Invalid regular expression: ' + e.message.replace(/^Invalid regular expression: /, ''));
  }
}

async function search(opts) {
  const gen = ++searchGen;
  const started = Date.now();
  const root = assertKnown(opts.outDir);
  const re = buildRegex(opts);
  let files = await listFiles(root);
  if (opts.scope) files = files.filter((f) => f.startsWith(opts.scope + '/') || f === opts.scope);
  files = files.filter((f) => !NOT_TEXT.test(f));

  const results = [];
  let hits = 0;
  let truncated = false;
  const BATCH = 32;
  for (let i = 0; i < files.length && !truncated; i += BATCH) {
    if (gen !== searchGen) return { cancelled: true };
    const batch = files.slice(i, i + BATCH);
    const texts = await Promise.all(batch.map((rel) => readText(path.join(root, rel), 4 * 1024 * 1024).catch(() => null)));
    for (let k = 0; k < batch.length && !truncated; k++) {
      const t = texts[k];
      if (!t || t.binary || !re.test(t.text)) continue;
      const lines = t.text.split('\n');
      const matches = [];
      for (let n = 0; n < lines.length; n++) {
        const m = re.exec(lines[n]);
        if (!m) continue;
        // Long (e.g. minified) lines are cut down to a window around the match.
        const line = lines[n].replace(/\r$/, '');
        const start = Math.max(0, m.index - 50);
        matches.push({ line: n + 1, col: m.index, len: m[0].length, text: line.slice(start, start + 220), cut: start });
        if (++hits >= MAX_HITS) { truncated = true; break; }
      }
      results.push({ rel: batch[k], matches });
    }
    if (i % (BATCH * 8) === 0) sendUI('search-progress', { done: i + batch.length, total: files.length });
  }
  return { results, hits, files: files.length, truncated, ms: Date.now() - started };
}

// ---------------------------------------------------------------- zip

// The OS tar (bsdtar, ships with Windows 10+) writes zips without blocking this process; AdmZip is the fallback.
function tarZip(srcDir, zipPath) {
  return new Promise((resolve) => {
    const tar = IS_WIN ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
    const child = spawn(tar, ['-a', '-c', '-f', zipPath, '-C', path.dirname(srcDir), path.basename(srcDir)], { windowsHide: true });
    child.on('error', () => resolve(false));
    child.on('close', (code) => resolve(code === 0));
  });
}

async function zipFolder(srcDir, zipPath) {
  await fsp.rm(zipPath, { force: true });
  if (await tarZip(srcDir, zipPath)) {
    const st = await fsp.stat(zipPath).catch(() => null);
    if (st && st.size > 0) return;
  }
  const zip = new AdmZip();
  zip.addLocalFolder(srcDir, path.basename(srcDir));
  await zip.writeZipPromise(zipPath);
}

// ---------------------------------------------------------------- IPC

const handle = (ch, fn) => ipcMain.handle(ch, (_e, arg) => fn(arg));

handle('enqueue', ({ id, file }) => {
  file = String(file).trim();
  if (/^www\.\S+$/i.test(file)) file = 'https://' + file;
  queue.push({ id, file });
  send(id, { status: 'queued' });
  pump();
});

handle('cancel-job', (id) => {
  const i = queue.findIndex((q) => q.id === id);
  if (i !== -1) {
    queue.splice(i, 1);
    send(id, { status: 'cancelled' });
  }
  controllers.get(id)?.abort();
});

handle('pick-files', async () => {
  const r = await dialog.showOpenDialog(win, {
    title: 'Choose files to decompile',
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Decompilable files', extensions: SUPPORTED_EXTS.map((e) => e.slice(1)) },
      { name: 'All files', extensions: ['*'] },
    ],
  });
  return r.canceled ? [] : r.filePaths;
});

// Opens any folder (e.g. output from an earlier version) in the source browser.
handle('open-folder', async (dir) => {
  if (!dir) {
    const r = await dialog.showOpenDialog(win, {
      title: 'Open a folder of decompiled source',
      defaultPath: settings.outputRoot,
      properties: ['openDirectory'],
    });
    if (r.canceled || !r.filePaths[0]) return null;
    dir = r.filePaths[0];
  }
  const outDir = path.resolve(dir);
  const existing = history.find((h) => path.resolve(h.outDir) === outDir);
  const files = await countFiles(outDir);
  return addHistory(existing ? { ...existing, files } : {
    outDir, name: path.basename(outDir), file: null, label: 'DIR', engine: 'folder', engineName: 'Folder', files, created: false,
  });
});

handle('get-settings', () => ({
  ...settings,
  aiKeyEnc: undefined,
  effectiveTheme: effectiveTheme(),
  defaults: DEFAULTS,
  supported: SUPPORTED_EXTS,
  version: app.getVersion(),
  versions: { electron: process.versions.electron, chrome: process.versions.chrome, node: process.versions.node },
  toolsDir: tools.dir,
}));

handle('set-settings', (patch) => {
  for (const k of Object.keys(DEFAULTS)) if (patch && k in patch) settings[k] = patch[k];
  settings.ghidraTimeout = Math.max(5, Math.min(3600, Number(settings.ghidraTimeout) || DEFAULTS.ghidraTimeout));
  settings.fontSize = Math.max(9, Math.min(28, Number(settings.fontSize) || DEFAULTS.fontSize));
  if (!ai.MODELS[settings.aiModel]) settings.aiModel = DEFAULTS.aiModel;
  settings.webMaxPages = Math.max(1, Math.min(1000, Math.round(Number(settings.webMaxPages)) || DEFAULTS.webMaxPages));
  settings.aiAutoReconstruct = !!settings.aiAutoReconstruct;
  if (!THEMES.includes(settings.theme)) settings.theme = DEFAULTS.theme;
  for (const k of ['symbols', 'originalSources', 'thoroughNative', 'androidDeobf', 'iosCode', 'verifyBuild', 'notify', 'autoReadme', 'wrapLines']) settings[k] = !!settings[k];
  if (patch && 'theme' in patch) applyTheme();
  saveSettings();
  return { ...settings, aiKeyEnc: undefined };
});

handle('choose-output', async () => {
  const r = await dialog.showOpenDialog(win, {
    title: 'Choose where decompiled source is saved',
    defaultPath: settings.outputRoot,
    properties: ['openDirectory', 'createDirectory'],
  });
  if (!r.canceled && r.filePaths[0]) {
    settings.outputRoot = r.filePaths[0];
    saveSettings();
  }
  return settings.outputRoot;
});

handle('list-files', async (outDir) => listFiles(assertKnown(outDir)));
handle('read-file', async ({ outDir, rel }) => readText(inside(assertKnown(outDir), rel)));
handle('full-path', ({ outDir, rel }) => inside(assertKnown(outDir), rel));

handle('search', (opts) => search(opts));
handle('cancel-search', () => { searchGen++; });

handle('open-path', (p) => shell.openPath(assertKnown(p)));
handle('copy-text', (text) => clipboard.writeText(String(text)));
handle('open-output-root', async () => {
  await fsp.mkdir(settings.outputRoot, { recursive: true });
  return shell.openPath(settings.outputRoot);
});
handle('show-file', ({ outDir, rel }) => shell.showItemInFolder(inside(assertKnown(outDir), rel)));

handle('export-zip', async ({ outDir, sub }) => {
  const root = assertKnown(outDir);
  const src = inside(root, sub);
  const r = await dialog.showSaveDialog(win, {
    title: sub ? `Save ${path.basename(src)} as ZIP` : 'Save source code as ZIP',
    defaultPath: path.join(path.dirname(root), path.basename(src) + '.zip'),
    filters: [{ name: 'ZIP archive', extensions: ['zip'] }],
  });
  if (r.canceled || !r.filePath) return null;
  await zipFolder(src, r.filePath);
  shell.showItemInFolder(r.filePath);
  return r.filePath;
});

// Builds an output folder again (after the user edited the decompiled code).
const rebuilding = new Set();
handle('rebuild', async (outDir) => {
  const root = assertKnown(outDir);
  if (rebuilding.has(root)) throw new Error('This project is already being rebuilt.');
  if (running) throw new Error('Wait until the current decompile job has finished.');
  rebuilding.add(root);
  try {
    const log = (msg) => sendUI('rebuild-log', { outDir: root, log: msg });
    const build = await rebuildFolder(root, { log, javaExe: () => tools.anyJdk(log) });
    const files = await countFiles(root);
    const entry = history.find((h) => path.resolve(h.outDir) === root);
    if (entry) {
      entry.build = build;
      entry.files = files;
      saveHistory();
    }
    return { build, files };
  } finally {
    rebuilding.delete(root);
  }
});

handle('save-file-as', async ({ outDir, rel }) => {
  const src = inside(assertKnown(outDir), rel);
  const r = await dialog.showSaveDialog(win, {
    title: 'Save a copy of ' + path.basename(src),
    defaultPath: path.join(app.getPath('documents'), path.basename(src)),
  });
  if (r.canceled || !r.filePath) return null;
  await fsp.copyFile(src, r.filePath);
  return r.filePath;
});

handle('get-history', async () => {
  return Promise.all(history.map(async (h) => ({ ...h, missing: !(await fsp.access(h.outDir).then(() => true, () => false)) })));
});

handle('remove-history', async ({ outDir, deleteFiles }) => {
  const key = assertKnown(outDir);
  const entry = history.find((h) => path.resolve(h.outDir) === key);
  if (deleteFiles) {
    // Only folders DropDecompiler created itself can be deleted, never a folder the user opened.
    if (!entry || !entry.created) throw new Error('Only output created by DropDecompiler can be deleted.');
    const r = await dialog.showMessageBox(win, {
      type: 'warning',
      buttons: ['Delete', 'Cancel'],
      defaultId: 1,
      cancelId: 1,
      title: 'Delete decompiled output',
      message: `Delete "${path.basename(key)}"?`,
      detail: `${key}\n\nThe folder and everything in it is moved to the Recycle Bin.`,
    });
    if (r.response !== 0) return false;
    await shell.trashItem(key).catch(() => fsp.rm(key, { recursive: true, force: true }));
  }
  history = history.filter((h) => path.resolve(h.outDir) !== key);
  delete bookmarks[key];
  saveHistory();
  saveBookmarks();
  return true;
});

handle('get-bookmarks', (outDir) => bookmarks[assertKnown(outDir)] || []);
handle('set-bookmarks', ({ outDir, list }) => {
  const key = assertKnown(outDir);
  if (Array.isArray(list) && list.length) bookmarks[key] = list.slice(0, 2000);
  else delete bookmarks[key];
  saveBookmarks();
});

handle('tool-status', () => tools.status());
handle('remove-tool', (key) => {
  if (running) throw new Error('Wait until the current job has finished.');
  return tools.remove(key);
});
handle('open-tools-dir', async () => {
  await fsp.mkdir(tools.dir, { recursive: true });
  return shell.openPath(tools.dir);
});

handle('app-action', (action) => {
  if (action === 'quit') app.quit();
  else if (action === 'devtools') win.webContents.toggleDevTools();
  else if (action === 'reload') win.webContents.reload();
  else if (action === 'fullscreen') win.setFullScreen(!win.isFullScreen());
  else if (action === 'minimize') win.minimize();
  else if (action === 'website') shell.openExternal('https://github.com/NationalSecurityAgency/ghidra');
  else if (action === 'api-keys') shell.openExternal('https://console.anthropic.com/settings/keys');
});

// ---------------------------------------------------------------- AI assistant

// The API key is stored encrypted with the OS key store (DPAPI on Windows); ANTHROPIC_API_KEY also works.
function getApiKey() {
  if (settings.aiKeyEnc && safeStorage.isEncryptionAvailable()) {
    try { return safeStorage.decryptString(Buffer.from(settings.aiKeyEnc, 'base64')); } catch { /* re-enter it */ }
  }
  return process.env.ANTHROPIC_API_KEY || null;
}

// "Sign in with Anthropic": `ant auth login` (Anthropic's CLI) stores an OAuth profile under
// %APPDATA%\Anthropic; the Anthropic SDK finds and refreshes it by itself, so no key has to be pasted.
function anthropicProfile() {
  const dir = process.env.ANTHROPIC_CONFIG_DIR || path.join(app.getPath('appData'), 'Anthropic');
  let name = process.env.ANTHROPIC_PROFILE || '';
  if (!name) { try { name = fs.readFileSync(path.join(dir, 'active_config'), 'utf8').trim(); } catch { /* none */ } }
  name ||= 'default';
  const signedIn = fs.existsSync(path.join(dir, 'configs', name + '.json')) && fs.existsSync(path.join(dir, 'credentials', name + '.json'));
  return signedIn ? name : null;
}

let loginChild = null;

function runAnt(args, timeoutMs) {
  return tools.antCli((m) => sendUI('ai-login-log', m)).then((exe) => new Promise((resolve, reject) => {
    const child = spawn(exe, args, { windowsHide: true });
    if (args[1] === 'login') loginChild = child;
    let out = '';
    const add = (c) => {
      out = (out + c.toString()).slice(-6000);
      sendUI('ai-login-log', c.toString().trim());
    };
    child.stdout.on('data', add);
    child.stderr.on('data', add);
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => { clearTimeout(timer); loginChild = null; resolve({ code, out }); });
  }));
}

handle('ai-login', async () => {
  if (loginChild) throw new Error('A sign-in is already open in your browser.');
  // Opens the browser on Anthropic's sign-in page and waits for it to finish (up to 5 minutes).
  const r = await runAnt(['auth', 'login'], 5 * 60 * 1000);
  const profile = anthropicProfile();
  if (!profile) throw new Error('Sign-in did not finish.' + (r.out.trim() ? '\n' + r.out.trim().split('\n').slice(-3).join('\n') : ''));
  return profile;
});
handle('ai-login-cancel', () => loginChild?.kill());
handle('ai-logout', async () => {
  await runAnt(['auth', 'logout'], 30000);
  return !anthropicProfile();
});

const conversations = new Map(); // output folder -> ai.Conversation

function conversationFor(outDir) {
  const root = assertKnown(outDir);
  let conv = conversations.get(root);
  if (!conv) {
    const h = history.find((x) => path.resolve(x.outDir) === root) || {};
    const inputFile = h.file && fs.existsSync(h.file) ? h.file : null;
    conv = new ai.Conversation({ root, job: { name: h.name, engine: h.engine, engineName: h.engineName, label: h.label }, inputFile });
    conversations.set(root, conv);
  }
  return conv;
}

handle('ai-config', () => ({
  hasKey: !!getApiKey() || !!anthropicProfile(),
  savedKey: !!settings.aiKeyEnc,
  profile: anthropicProfile(),
  keyFromEnv: !settings.aiKeyEnc && !!process.env.ANTHROPIC_API_KEY,
  webMaxPages: settings.webMaxPages,
  model: settings.aiModel,
  autoReconstruct: settings.aiAutoReconstruct,
  models: Object.entries(ai.MODELS).map(([id, m]) => ({ id, name: m.name, price: `$${m.input} / $${m.output} per million tokens` })),
}));

handle('ai-set-key', (key) => {
  key = String(key || '').trim();
  if (!key) settings.aiKeyEnc = undefined;
  else {
    if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows could not encrypt the key on this account.');
    settings.aiKeyEnc = safeStorage.encryptString(key).toString('base64');
  }
  saveSettings();
  return !!getApiKey();
});

handle('ai-send', ({ outDir, text, mode, currentFile }) => {
  const conv = conversationFor(outDir);
  const root = conv.root;
  if (conv.busy) throw new Error('The assistant is already working on this folder.');
  // Runs in the background; progress arrives as 'ai-event' messages.
  conv.send({
    apiKey: getApiKey(),
    model: settings.aiModel,
    mode,
    text: String(text || ''),
    currentFile: currentFile ? String(currentFile) : null,
    emit: (ev) => sendUI('ai-event', { outDir: root, ...ev }),
  }).catch((e) => sendUI('ai-event', { outDir: root, type: 'error', message: e.message }));
  return true;
});

handle('ai-stop', (outDir) => conversations.get(assertKnown(outDir))?.stop());
handle('ai-reset', (outDir) => {
  const root = assertKnown(outDir);
  if (conversations.get(root)?.busy) throw new Error('Stop the assistant first.');
  conversations.delete(root);
});

// ---------------------------------------------------------------- lifecycle

// One window only: files dropped onto the launcher while the app is open go to the running window.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', (_e, argv) => {
    if (!win) return;
    if (win.isMinimized()) win.restore();
    win.focus();
    const files = argFiles(argv);
    if (files.length) sendUI('add-files', files);
  });
  app.whenReady().then(() => {
    Menu.setApplicationMenu(null); // the menu bar is drawn by the page
    loadState();
    tools = new Tools(path.join(app.getPath('userData'), 'tools'));
    createWindow();
    nativeTheme.on('updated', () => { if (settings.theme === 'system') applyTheme(); });
  });
  app.on('window-all-closed', () => {
    for (const c of controllers.values()) c.abort();
    for (const c of conversations.values()) c.stop();
    app.quit();
  });
}
