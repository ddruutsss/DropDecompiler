// Decompiler engine: detects file types, downloads the needed tools on demand,
// and runs the right decompiler. Has no Electron dependency so it can be tested from plain Node.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');
const zlib = require('zlib');
const AdmZip = require('adm-zip');
const rebuild = require('./rebuild');
const { decompileLua, isLua, luaKind, LUA_EXTS } = require('./lua');
const { decompileManifest, isManifest } = require('./manifest');
const { decompileGeneric } = require('./generic');
const { decompileWebsite, isUrl } = require('./website');
const originals = require('./originals');
const ios = require('./ios');
const frameworks = require('./frameworks');
const { isMachO } = require('./macho');

const IS_WIN = process.platform === 'win32';
const EXE = IS_WIN ? '.exe' : '';
const UA = { 'User-Agent': 'DropDecompiler' };

const JAVA_EXTS = ['.jar', '.war', '.ear', '.class', '.jmod'];
const ANDROID_EXTS = ['.apk', '.apks', '.apkm', '.xapk', '.aab', '.aar', '.dex', '.smali', '.arsc'];
const DOTNET_EXTS = ['.dll', '.exe', '.winmd', '.netmodule'];
const DOTNET_ARCHIVE_EXTS = ['.nupkg', '.snupkg'];
// Native code is recognised by its header (PE / ELF / Mach-O), these are just for the file picker.
const NATIVE_EXTS = ['.sys', '.ocx', '.cpl', '.scr', '.drv', '.efi', '.so', '.dylib', '.elf', '.ko', '.o', '.axf'];
const SUPPORTED_EXTS = [...JAVA_EXTS, ...ANDROID_EXTS, ...DOTNET_EXTS, ...DOTNET_ARCHIVE_EXTS, ...NATIVE_EXTS, ...LUA_EXTS, '.manifest', '.ipa', '.zip'];

// unluac (Lua 5.0-5.4) has no binary releases on GitHub: its source (a mirror of the official repository,
// pinned to a commit) is compiled with javac the first time a Lua bytecode file is dropped.
const UNLUAC_SRC = 'https://codeload.github.com/viruscamp/unluac/zip/9c59af46483a932a47224bf2ac84ad8a63094da5';
const PYCDC_SRC = 'https://codeload.github.com/zrax/pycdc/zip/b4289760970dbc399684f1e155ec6d1ea1cc787e';
const LUAJIT_DECOMPILER_URL ='https://github.com/marsinator358/luajit-decompiler-v2/releases/download/Mar_24_2024/luajit-decompiler-v2.exe';

// Ghidra is pinned because the export script is compiled against its API.
const GHIDRA_URL =
  'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip';
const GHIDRA_SCRIPT = 'DropDecompilerExport.java';
const GHIDRA_THOROUGH_SCRIPT = 'DropDecompilerThorough.java'; // pre-script: extra analyzers for "thorough analysis"
const GHIDRA_FUNC_TIMEOUT = 60; // seconds per function before Ghidra gives up and we fall back to assembly

// ---------------------------------------------------------------- helpers

async function exists(p) {
  try { await fsp.access(p); return true; } catch { return false; }
}

class CancelledError extends Error {
  constructor() {
    super('Cancelled');
    this.cancelled = true;
  }
}

function checkCancel(signal) {
  if (signal?.aborted) throw new CancelledError();
}

// Kills the whole process tree: Ghidra and JADX start helper processes of their own.
function killTree(child) {
  if (child.exitCode !== null || child.killed) return;
  if (IS_WIN) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true }).on('error', () => child.kill());
  else child.kill('SIGKILL');
}

function run(cmd, args, { onLine, env, cwd, signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new CancelledError());
    const child = spawn(cmd, args, { env: { ...process.env, ...env }, cwd, windowsHide: true });
    const onAbort = () => killTree(child);
    signal?.addEventListener('abort', onAbort, { once: true });
    let tail = '';
    // Separate line buffers per stream so chunks split mid-line are reassembled.
    const feeder = () => {
      let partial = '';
      const emit = (l) => l.trim() && onLine?.(l);
      return {
        data(chunk) {
          const text = chunk.toString();
          tail = (tail + text).slice(-4000);
          const lines = (partial + text).split(/\r?\n|\r/);
          partial = lines.pop();
          lines.forEach(emit);
        },
        flush() { emit(partial); partial = ''; },
      };
    };
    const out = feeder();
    const err = feeder();
    child.stdout.on('data', out.data);
    child.stderr.on('data', err.data);
    child.on('error', (e) => { signal?.removeEventListener('abort', onAbort); reject(e); });
    child.on('close', (code) => {
      signal?.removeEventListener('abort', onAbort);
      out.flush();
      err.flush();
      if (signal?.aborted) reject(new CancelledError());
      else resolve({ code, tail });
    });
  });
}

// Windows keeps files locked for a moment after a process is killed, so deletes retry.
const rmrf = (p) => fsp.rm(p, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });

async function dirSize(dir) {
  let total = 0;
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    let ents;
    try { ents = await fsp.readdir(d, { withFileTypes: true }); } catch { continue; }
    await Promise.all(ents.map(async (e) => {
      const p = path.join(d, e.name);
      if (e.isDirectory()) stack.push(p);
      else {
        // Read the size first: `total += await …` would read `total` before the await and lose updates.
        const size = await fsp.stat(p).then((st) => st.size, () => 0);
        total += size;
      }
    }));
  }
  return total;
}

async function download(url, dest, onProgress) {
  const res = await fetch(url, { headers: UA, redirect: 'follow' });
  if (!res.ok) throw new Error(`Download failed (HTTP ${res.status}): ${url}`);
  const total = Number(res.headers.get('content-length')) || 0;
  let got = 0;
  let lastPct = -1;
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  const body = Readable.fromWeb(res.body);
  body.on('data', (c) => {
    got += c.length;
    const pct = total ? Math.floor((got * 100) / total) : -1;
    if (pct !== lastPct && pct % 2 === 0) { lastPct = pct; onProgress?.(pct, got); }
  });
  const tmp = dest + '.part';
  await pipeline(body, fs.createWriteStream(tmp));
  await fsp.rename(tmp, dest);
}

async function githubAsset(repo, nameRegex, fallbackUrl) {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, { headers: UA });
    if (res.ok) {
      const rel = await res.json();
      const asset = rel.assets.find((a) => nameRegex.test(a.name));
      if (asset) return asset.browser_download_url;
    }
  } catch { /* fall through to pinned version */ }
  return fallbackUrl;
}

async function findFile(dir, predicate, depth = 4) {
  if (depth < 0 || !(await exists(dir))) return null;
  for (const ent of await fsp.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isFile() && predicate(full)) return full;
    if (ent.isDirectory()) {
      const hit = await findFile(full, predicate, depth - 1);
      if (hit) return hit;
    }
  }
  return null;
}

async function countFiles(dir) {
  let n = 0;
  for (const ent of await fsp.readdir(dir, { withFileTypes: true })) {
    if (ent.isDirectory()) n += await countFiles(path.join(dir, ent.name));
    else n++;
  }
  return n;
}

// Big archives are unpacked with the OS tar (bsdtar reads zip; ships with Windows 10+ and macOS)
// so the main process isn't blocked and the whole zip isn't loaded into memory. AdmZip is the fallback.
async function extractArchive(archive, dest) {
  await fsp.mkdir(dest, { recursive: true });
  const tar = IS_WIN ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  if (IS_WIN || process.platform === 'darwin' || !/\.zip$/i.test(archive)) {
    try {
      const { code } = await run(tar, ['-xf', archive, '-C', dest]);
      if (code === 0) return;
    } catch { /* no tar: fall back */ }
  }
  new AdmZip(archive).extractAllTo(dest, true);
}

async function moveInto(srcDir, destDir) {
  await fsp.mkdir(destDir, { recursive: true });
  for (const name of await fsp.readdir(srcDir)) {
    const from = path.join(srcDir, name);
    const to = path.join(destDir, name);
    try {
      await fsp.rename(from, to);
    } catch {
      await fsp.cp(from, to, { recursive: true }); // across drives
      await fsp.rm(from, { recursive: true, force: true });
    }
  }
}

async function readHead(file, bytes = 65536) {
  const fh = await fsp.open(file, 'r');
  try {
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await fh.read(buf, 0, bytes, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

// ---------------------------------------------------------------- detection

function isDotNetPE(buf) {
  try {
    if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return false; // "MZ"
    const pe = buf.readUInt32LE(0x3c);
    if (pe + 24 + 240 > buf.length || buf.readUInt32LE(pe) !== 0x00004550) return false; // "PE\0\0"
    const opt = pe + 24;
    const magic = buf.readUInt16LE(opt);
    const dataDirs = opt + (magic === 0x20b ? 112 : 96);
    const clr = dataDirs + 14 * 8; // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    return buf.readUInt32LE(clr) !== 0 && buf.readUInt32LE(clr + 4) !== 0;
  } catch {
    return false;
  }
}

// .NET single-file apps are a native "apphost" with the assemblies appended. The host contains this
// 32-byte signature, preceded by the 64-bit offset of the bundle manifest (0 in an unbundled host).
const BUNDLE_SIG = Buffer.from('8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae', 'hex');

async function findBundleHeader(file) {
  const fh = await fsp.open(file, 'r');
  try {
    const { size } = await fh.stat();
    const limit = Math.min(size, 64 * 1024 * 1024); // the signature lives in the host, near the start
    const chunk = Buffer.alloc(4 * 1024 * 1024);
    for (let pos = 0; pos < limit; pos += chunk.length - 64) {
      const { bytesRead } = await fh.read(chunk, 0, chunk.length, pos);
      const buf = chunk.subarray(0, bytesRead);
      for (let i = buf.indexOf(BUNDLE_SIG); i !== -1; i = buf.indexOf(BUNDLE_SIG, i + 1)) {
        if (i < 8) continue;
        const offset = Number(buf.readBigInt64LE(i - 8));
        if (offset > 0 && offset < size) return offset;
      }
      if (bytesRead < chunk.length) break;
    }
    return 0;
  } finally {
    await fh.close();
  }
}

function nativeKind(head) {
  const m4 = head.subarray(0, 4).toString('hex');
  if (m4 === '7f454c46') return 'ELF';
  if (['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe'].includes(m4)) return 'MACHO';
  // Universal Mach-O shares 0xCAFEBABE with Java classes; it is followed by a small arch count,
  // whereas a class file is followed by its version (major >= 45).
  if (m4 === 'cafebabe' && head.length >= 8 && head.readUInt32BE(4) > 0 && head.readUInt32BE(4) < 45) return 'MACHO';
  return null;
}

/** Returns { engine, label } or throws a friendly error. */
async function detect(file) {
  const ext = path.extname(file).toLowerCase();
  const head = await readHead(file);
  const magic = head.subarray(0, 4);
  const label = ext ? ext.slice(1).toUpperCase() : 'FILE';

  const native = nativeKind(head);
  if (native) return { engine: 'native', label: ext && ext !== '.bin' ? label : native };

  const lua = luaKind(head);
  if (lua.kind === 'lua' || lua.kind === 'luajit') return { engine: 'lua', label: ext ? label : 'LUAC' };
  if (isManifest(file, head)) return { engine: 'manifest', label: 'MANIFEST' };
  if (isLua(file, head)) return { engine: 'lua', label };

  if (magic.equals(Buffer.from([0xca, 0xfe, 0xba, 0xbe]))) return { engine: 'java', label: 'CLASS' };
  if (head.subarray(0, 4).toString('latin1') === 'dex\n') return { engine: 'android', label: 'DEX' };

  if (head.subarray(0, 2).toString('latin1') === 'MZ') {
    if (isDotNetPE(head)) return { engine: 'dotnet', label };
    // A .NET app published as a single file looks native but carries real assemblies inside.
    if (await findBundleHeader(file)) return { engine: 'dotnet-bundle', label };
    return { engine: 'native', label };
  }

  if (ext === '.ipa' && head.subarray(0, 2).toString('latin1') === 'PK') return { engine: 'ios', label: 'IPA' };
  if (ANDROID_EXTS.includes(ext)) return { engine: 'android', label };
  if (JAVA_EXTS.includes(ext)) return { engine: 'java', label };
  if (DOTNET_ARCHIVE_EXTS.includes(ext)) return { engine: 'dotnet-archive', label };

  if (head.subarray(0, 2).toString('latin1') === 'PK') {
    // Generic zip: look inside to decide.
    const names = new AdmZip(file).getEntries().map((e) => e.entryName.toLowerCase());
    if (ios.isIpa(file, names)) return { engine: 'ios', label: 'IPA' };
    if (names.some((n) => n.endsWith('.dex') || n.endsWith('.apk') || n === 'androidmanifest.xml')) {
      return { engine: 'android', label };
    }
    if (names.some((n) => n.endsWith('.class'))) return { engine: 'java', label };
    if (names.some((n) => n.endsWith('.dll') || n.endsWith('.exe'))) return { engine: 'dotnet-archive', label };
    if (names.some((n) => LUA_EXTS.some((e) => n.endsWith(e)))) return { engine: 'lua', label };
    return { engine: 'generic', label };
  }

  // Anything else: identified, opened up as far as possible, and left to the AI assistant.
  return { engine: 'generic', label };
}

// ---------------------------------------------------------------- tools

const TOOL_INFO = [
  { key: 'ghidra', name: 'Ghidra', used: 'Native EXE / DLL / SO', match: /^ghidra(\.part)?$|^ghidra-scripts$/ },
  { key: 'jdk', name: 'Java JDK (for Ghidra)', used: 'Native EXE / DLL / SO', match: /^jdk-\d+(\.part)?$/ },
  { key: 'jre', name: 'Java runtime', used: 'Java and Android', match: /^jre$/ },
  { key: 'vineflower', name: 'Vineflower', used: 'Java JAR / CLASS', match: /^vineflower\.jar$/ },
  { key: 'jadx', name: 'JADX', used: 'Android APK / DEX', match: /^jadx$/ },
  { key: 'ilspy', name: 'ILSpy (ilspycmd)', used: '.NET DLL / EXE', match: /^ilspy$/ },
  { key: 'unluac', name: 'unluac', used: 'Lua 5.x bytecode', match: /^unluac(\.part)?$/ },
  { key: 'luajit', name: 'LuaJIT Decompiler v2', used: 'LuaJIT bytecode', match: /^luajit-decompiler$/ },
  { key: 'pycdc', name: 'pycdc (Python decompiler)', used: 'Python apps (PyInstaller)', match: /^pycdc(\.part)?$/ },
  { key: 'ant', name: 'Anthropic CLI', used: 'Sign in with Anthropic (AI assistant)', match: /^ant(\.part)?$/ },
];

class Tools {
  constructor(toolsDir) {
    this.dir = toolsDir;
    this.pending = new Map();
  }

  /** Installed decompilers and runtimes, with their size on disk. */
  async status() {
    const out = [];
    for (const t of TOOL_INFO) {
      let names = [];
      try { names = (await fsp.readdir(this.dir)).filter((n) => t.match.test(n)); } catch { /* no tools dir yet */ }
      let size = 0;
      for (const n of names) {
        const p = path.join(this.dir, n);
        const st = await fsp.stat(p);
        size += st.isDirectory() ? await dirSize(p) : st.size;
      }
      out.push({ key: t.key, name: t.name, used: t.used, installed: names.length > 0, size, busy: this.pending.size > 0 });
    }
    return out;
  }

  /** Deletes a downloaded tool; it is downloaded again the next time it's needed. */
  async remove(key) {
    const t = TOOL_INFO.find((x) => x.key === key);
    if (!t) throw new Error('Unknown tool');
    if (this.pending.size) throw new Error('A tool is being installed right now — try again when it has finished.');
    for (const n of await fsp.readdir(this.dir)) {
      if (t.match.test(n)) await rmrf(path.join(this.dir, n));
    }
  }

  // Run each installer at most once at a time, even if several jobs ask for it.
  once(key, fn) {
    if (!this.pending.has(key)) {
      const p = fn().finally(() => this.pending.delete(key));
      this.pending.set(key, p);
    }
    return this.pending.get(key);
  }

  async systemJava() {
    const candidates = [];
    if (process.env.JAVA_HOME) candidates.push(path.join(process.env.JAVA_HOME, 'bin', 'java' + EXE));
    candidates.push('java');
    for (const cmd of candidates) {
      try {
        const { tail } = await run(cmd, ['-version']);
        const m = tail.match(/version "(\d+)(?:\.(\d+))?/);
        if (!m) continue;
        const major = m[1] === '1' ? Number(m[2]) : Number(m[1]);
        if (major >= 17) return cmd;
      } catch { /* not found */ }
    }
    return null;
  }

  java(log) {
    return this.once('java', async () => {
      const jreDir = path.join(this.dir, 'jre');
      const isJava = (f) => path.basename(f) === 'java' + EXE && path.basename(path.dirname(f)) === 'bin';
      let java = await findFile(jreDir, isJava);
      if (java) return java;
      java = await this.systemJava();
      if (java) return java;

      const osName = IS_WIN ? 'windows' : process.platform === 'darwin' ? 'mac' : 'linux';
      const arch = process.arch === 'arm64' ? 'aarch64' : 'x64';
      const url = `https://api.adoptium.net/v3/binary/latest/21/ga/${osName}/${arch}/jre/hotspot/normal/eclipse`;
      const archive = path.join(this.dir, IS_WIN ? 'jre.zip' : 'jre.tar.gz');
      log('Java not found — downloading a portable Java 21 runtime (one-time, ~45 MB)…');
      await download(url, archive, (pct) => log(`Downloading Java… ${pct}%`, { progress: pct }));
      log('Extracting Java…');
      await fsp.rm(jreDir, { recursive: true, force: true });
      await fsp.mkdir(jreDir, { recursive: true });
      if (IS_WIN) new AdmZip(archive).extractAllTo(jreDir, true);
      else await run('tar', ['-xzf', archive, '-C', jreDir]);
      await fsp.rm(archive, { force: true });
      java = await findFile(jreDir, isJava);
      if (!java) throw new Error('Java download finished but java executable was not found.');
      return java;
    });
  }

  vineflower(log) {
    return this.once('vineflower', async () => {
      const jar = path.join(this.dir, 'vineflower.jar');
      if (await exists(jar)) return jar;
      log('Downloading Vineflower Java decompiler (one-time)…');
      const url = await githubAsset(
        'Vineflower/vineflower',
        /^vineflower-[\d.]+\.jar$/,
        'https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar'
      );
      await download(url, jar, (pct) => log(`Downloading Vineflower… ${pct}%`, { progress: pct }));
      return jar;
    });
  }

  jadx(log) {
    return this.once('jadx', async () => {
      const jadxDir = path.join(this.dir, 'jadx');
      const isAllJar = (f) => /jadx-.*-all\.jar$/.test(path.basename(f));
      let jar = await findFile(jadxDir, isAllJar);
      if (jar) return jar;
      log('Downloading JADX Android decompiler (one-time)…');
      const url = await githubAsset(
        'skylot/jadx',
        /^jadx-[\d.]+\.zip$/,
        'https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip'
      );
      const archive = path.join(this.dir, 'jadx.zip');
      await download(url, archive, (pct) => log(`Downloading JADX… ${pct}%`, { progress: pct }));
      await fsp.rm(jadxDir, { recursive: true, force: true });
      new AdmZip(archive).extractAllTo(jadxDir, true);
      await fsp.rm(archive, { force: true });
      jar = await findFile(jadxDir, isAllJar);
      if (!jar) throw new Error('JADX download finished but its jar was not found.');
      return jar;
    });
  }

  /** Version and home of a java executable, or null if it can't be run. */
  async javaInfo(cmd) {
    try {
      const { tail } = await run(cmd, ['-XshowSettings:properties', '-version']);
      const ver = tail.match(/java\.specification\.version = (\d+)/);
      const home = tail.match(/java\.home = (.+)/);
      if (ver && home) return { major: Number(ver[1]), home: home[1].trim() };
    } catch { /* not found */ }
    return null;
  }

  /** A full JDK (Ghidra compiles its scripts, so a JRE won't do) of at least `minMajor`. Returns the java path. */
  jdk(minMajor, log) {
    return this.once('jdk' + minMajor, async () => {
      const jdkDir = path.join(this.dir, `jdk-${minMajor}`);
      const isJavac = (f) => path.basename(f) === 'javac' + EXE && path.basename(path.dirname(f)) === 'bin';
      const javaNextTo = (javac) => path.join(path.dirname(javac), 'java' + EXE);
      let javac = await findFile(jdkDir, isJavac);
      if (javac) return javaNextTo(javac);

      const candidates = [];
      if (process.env.JAVA_HOME) candidates.push(path.join(process.env.JAVA_HOME, 'bin', 'java' + EXE));
      candidates.push('java');
      for (const cmd of candidates) {
        const info = await this.javaInfo(cmd);
        const sysJavac = info && path.join(info.home, 'bin', 'javac' + EXE);
        if (info && info.major >= minMajor && (await exists(sysJavac))) return javaNextTo(sysJavac);
      }

      const osName = IS_WIN ? 'windows' : process.platform === 'darwin' ? 'mac' : 'linux';
      const arch = process.arch === 'arm64' ? 'aarch64' : 'x64';
      const url = `https://api.adoptium.net/v3/binary/latest/${minMajor}/ga/${osName}/${arch}/jdk/hotspot/normal/eclipse`;
      const archive = path.join(this.dir, IS_WIN ? `jdk-${minMajor}.zip` : `jdk-${minMajor}.tar.gz`);
      log(`Ghidra needs a Java ${minMajor} JDK — downloading a portable one (one-time, ~200 MB)…`);
      await download(url, archive, (pct) => log(`Downloading JDK ${minMajor}… ${pct}%`, { progress: pct, quiet: pct % 10 !== 0 }));
      log(`Extracting JDK ${minMajor}…`);
      const tmp = jdkDir + '.part';
      await fsp.rm(tmp, { recursive: true, force: true });
      await extractArchive(archive, tmp);
      await fsp.rm(archive, { force: true });
      await fsp.rm(jdkDir, { recursive: true, force: true });
      await fsp.rename(tmp, jdkDir);
      javac = await findFile(jdkDir, isJavac);
      if (!javac) throw new Error('JDK download finished but javac was not found.');
      return javaNextTo(javac);
    });
  }

  /** Any JDK (javac) for recompiling Java: one already downloaded, the system's, or a new Java 21. Returns java's path. */
  async anyJdk(log) {
    const isJavac = (f) => path.basename(f) === 'javac' + EXE && path.basename(path.dirname(f)) === 'bin';
    let names = [];
    try { names = (await fsp.readdir(this.dir)).filter((n) => /^jdk-\d+$/.test(n)).sort((a, b) => b.localeCompare(a, undefined, { numeric: true })); } catch { /* none */ }
    for (const n of names) {
      const javac = await findFile(path.join(this.dir, n), isJavac);
      if (javac) return path.join(path.dirname(javac), 'java' + EXE);
    }
    return this.jdk(17, log);
  }

  /** Installs Ghidra on first use. Returns { home, version, javaMin, vmargs, classpath }. */
  ghidra(log) {
    return this.once('ghidra', async () => {
      const root = path.join(this.dir, 'ghidra');
      const isProps = (f) => path.basename(f) === 'application.properties' && path.basename(path.dirname(f)) === 'Ghidra';
      let props = await findFile(root, isProps, 2);
      if (!props) {
        const archive = path.join(this.dir, 'ghidra.zip');
        log('Downloading the Ghidra decompiler (one-time, ~570 MB — this can take a while)…');
        await download(GHIDRA_URL, archive, (pct) =>
          log(`Downloading Ghidra… ${pct}%`, { progress: pct, quiet: pct % 10 !== 0 })
        );
        log('Extracting Ghidra (about a minute)…');
        const tmp = root + '.part';
        await fsp.rm(tmp, { recursive: true, force: true });
        await extractArchive(archive, tmp);
        await fsp.rm(archive, { force: true });
        await fsp.rm(root, { recursive: true, force: true });
        await fsp.rename(tmp, root);
        props = await findFile(root, isProps, 2);
        if (!props) throw new Error('Ghidra download finished but its files were not found.');
      }
      const home = path.dirname(path.dirname(props));
      const kv = Object.fromEntries(
        (await fsp.readFile(props, 'utf8')).split(/\r?\n/).filter((l) => l.includes('=')).map((l) => {
          const i = l.indexOf('=');
          return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
        })
      );
      // JVM flags Ghidra's own launcher would pass (support/launch.properties).
      const osKey = IS_WIN ? 'VMARGS_WINDOWS' : process.platform === 'darwin' ? 'VMARGS_MACOS' : 'VMARGS_LINUX';
      const vmargs = (await fsp.readFile(path.join(home, 'support', 'launch.properties'), 'utf8'))
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.startsWith('VMARGS=') || l.startsWith(osKey + '='))
        .map((l) => l.slice(l.indexOf('=') + 1).trim())
        .filter(Boolean);
      return {
        home,
        version: kv['application.version'] || '?',
        javaMin: Number(kv['application.java.min']) || 21,
        vmargs,
        classpath: path.join(home, 'Ghidra', 'Framework', 'Utility', 'lib', 'Utility.jar'),
      };
    });
  }

  /** unluac compiled from source on first use. Returns { java, classpath }. */
  unluac(log) {
    return this.once('unluac', async () => {
      const dir = path.join(this.dir, 'unluac');
      const classes = path.join(dir, 'classes');
      const java = await this.java(log);
      if (await exists(path.join(classes, 'unluac', 'Main.class'))) return { java, classpath: classes };

      const javaExe = await this.anyJdk(log);
      const javac = path.join(path.dirname(javaExe), 'javac' + EXE);
      log('Downloading the unluac Lua decompiler (one-time)…');
      const tmp = dir + '.part';
      await rmrf(tmp);
      const archive = path.join(this.dir, 'unluac-src.zip');
      await download(UNLUAC_SRC, archive);
      await extractArchive(archive, path.join(tmp, 'src'));
      await fsp.rm(archive, { force: true });
      const main = await findFile(path.join(tmp, 'src'), (f) => f.endsWith(path.join('unluac', 'Main.java')), 6);
      if (!main) throw new Error('The unluac download did not contain its source code.');
      const srcRoot = path.dirname(path.dirname(main));
      const sources = [];
      (function walk(d) {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) walk(p);
          else if (e.name.endsWith('.java')) sources.push(p);
        }
      })(srcRoot);
      const list = path.join(tmp, 'sources.txt');
      await fsp.writeFile(list, sources.map((s) => `"${s.split(path.sep).join('/')}"`).join('\n'));
      log('Compiling unluac…');
      // --release 8 so any Java runtime (the bundled Java 21 or an older system Java) can run it.
      const { code, tail } = await run(javac, ['--release', '8', '-nowarn', '-encoding', 'UTF-8', '-d', path.join(tmp, 'classes'), '@' + list]);
      if (code !== 0) throw new Error('Could not compile unluac:\n' + tail);
      await rmrf(dir);
      await fsp.mkdir(dir, { recursive: true });
      await fsp.rename(path.join(tmp, 'classes'), classes);
      await rmrf(tmp);
      return { java, classpath: classes };
    });
  }

  /** luajit-decompiler-v2 (Windows only). Returns the exe path. */
  luajitDecompiler(log) {
    return this.once('luajit', async () => {
      if (!IS_WIN) throw new Error('LuaJIT bytecode can only be decompiled on Windows (luajit-decompiler-v2 is a Windows program).');
      const exe = path.join(this.dir, 'luajit-decompiler', 'luajit-decompiler-v2.exe');
      if (await exists(exe)) return exe;
      log('Downloading LuaJIT Decompiler v2 (one-time)…');
      await download(LUAJIT_DECOMPILER_URL, exe);
      return exe;
    });
  }

  /**
   * Anthropic's official CLI (`ant`), used for "Sign in with Anthropic": `ant auth login` signs in through the
   * browser and stores a profile that the Anthropic SDK (and so the AI assistant) uses without an API key.
   * A copy already on PATH is used first. Returns the exe path.
   */
  /**
   * pycdc (Decompyle++), a Python bytecode decompiler. It has no binary releases, so it is built from its
   * source (pinned commit) with Visual Studio's C++ compiler and CMake the first time it is needed.
   */
  pycdc(log = () => {}) {
    return this.once('pycdc', async () => {
      const exe = path.join(this.dir, 'pycdc', 'pycdc.exe');
      if (await exists(exe)) return exe;
      const msvc = require('./msvc');
      const vs = await msvc.findVs();
      const cmake = await msvc.findCmake();
      if (!vs || !cmake) throw new Error('building the Python decompiler needs Visual Studio\'s C++ tools and CMake');
      log('Building the pycdc Python decompiler (one-time, about a minute)…');
      const tmp = path.join(this.dir, 'pycdc.part');
      await rmrf(tmp);
      const archive = path.join(this.dir, 'pycdc-src.zip');
      await download(PYCDC_SRC, archive);
      await extractArchive(archive, path.join(tmp, 'src'));
      await fsp.rm(archive, { force: true });
      const lists = await findFile(path.join(tmp, 'src'), (f) => path.basename(f) === 'CMakeLists.txt', 2);
      if (!lists) throw new Error('the pycdc download has no CMakeLists.txt');
      const build = path.join(tmp, 'build');
      let r = await run(cmake, ['-S', path.dirname(lists), '-B', build, '-A', 'x64']);
      if (r.code !== 0) throw new Error('CMake configuration failed:\n' + r.tail);
      r = await run(cmake, ['--build', build, '--config', 'Release']);
      const built = await findFile(build, (f) => path.basename(f).toLowerCase() === 'pycdc.exe', 4);
      if (!built) throw new Error('pycdc did not build:\n' + r.tail);
      await fsp.mkdir(path.dirname(exe), { recursive: true });
      await fsp.copyFile(built, exe);
      await rmrf(tmp);
      return exe;
    });
  }

  antCli(log = () => {}) {
    return this.once('ant', async () => {
      const local = path.join(this.dir, 'ant', 'ant' + EXE);
      if (await exists(local)) return local;
      for (const dir of (process.env.PATH || '').split(path.delimiter)) {
        const p = dir && path.join(dir, 'ant' + EXE);
        if (p && (await exists(p))) return p;
      }
      const osName = IS_WIN ? 'windows' : process.platform === 'darwin' ? 'darwin' : 'linux';
      const arch = process.arch === 'arm64' ? 'arm64' : process.arch === 'ia32' ? '386' : 'amd64';
      const ext = IS_WIN ? 'zip' : 'tar.gz';
      const url = await githubAsset('anthropics/anthropic-cli', new RegExp(`^ant_[\\d.]+_${osName}_${arch}\\.${ext.replace('.', '\\.')}$`),
        `https://github.com/anthropics/anthropic-cli/releases/download/v2.9.0/ant_2.9.0_${osName}_${arch}.${ext}`);
      log('Downloading the Anthropic CLI for sign-in (one-time)…');
      const archive = path.join(this.dir, `ant.${ext}`);
      await download(url, archive);
      const tmp = path.join(this.dir, 'ant.part');
      await rmrf(tmp);
      await extractArchive(archive, tmp);
      await fsp.rm(archive, { force: true });
      const exe = await findFile(tmp, (f) => path.basename(f) === 'ant' + EXE, 3);
      if (!exe) throw new Error('The Anthropic CLI download did not contain ant' + EXE);
      await fsp.mkdir(path.dirname(local), { recursive: true });
      await fsp.rename(exe, local);
      await rmrf(tmp);
      return local;
    });
  }

  ilspy(log) {
    return this.once('ilspy', async () => {
      const toolPath = path.join(this.dir, 'ilspy');
      // On Windows the tool path holds a .cmd shim; the real exe lives under .store (spawn can't run .cmd directly).
      const findExe = async () =>
        IS_WIN
          ? findFile(toolPath, (f) => path.basename(f).toLowerCase() === 'ilspycmd.exe', 10)
          : (await exists(path.join(toolPath, 'ilspycmd'))) ? path.join(toolPath, 'ilspycmd') : null;
      let exe = await findExe();
      if (exe) return exe;
      log('Installing ILSpy .NET decompiler (one-time)…');
      let result;
      try {
        result = await run('dotnet', ['tool', 'install', 'ilspycmd', '--tool-path', toolPath], {
          env: { DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_GENERATE_ASPNET_CERTIFICATE: 'false' },
        });
      } catch {
        throw new Error(
          'The .NET SDK is required to decompile .NET files. Install it from https://dotnet.microsoft.com/download and try again.'
        );
      }
      exe = await findExe();
      if (result.code !== 0 || !exe) throw new Error('Failed to install ilspycmd:\n' + result.tail);
      return exe;
    });
  }
}

// ---------------------------------------------------------------- decompilers

async function uniqueDir(base) {
  let dir = base;
  for (let i = 2; await exists(dir); i++) dir = `${base} (${i})`;
  await fsp.mkdir(dir, { recursive: true });
  return dir;
}

/** Jars bundled inside a jar/war/ear (Spring Boot, web apps, fat jars), extracted to `dir`. */
async function bundledJars(file, dir) {
  if (!/\.(jar|war|ear|zip)$/i.test(file)) return [];
  let entries;
  try { entries = new AdmZip(file).getEntries(); } catch { return []; }
  const out = [];
  for (const e of entries) {
    if (e.isDirectory || !/\.jar$/i.test(e.entryName) || out.length >= 400) continue;
    const dest = path.join(dir, `${out.length}_${path.basename(e.entryName)}`);
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(dest, e.getData());
    out.push(dest);
  }
  return out;
}

async function decompileJava(tools, file, outDir, log, { signal, originalSources = true } = {}) {
  const java = await tools.java(log);
  const vf = await tools.vineflower(log);
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-java-'));
  try {
    // Libraries the program ships with give Vineflower the types it needs to choose the right overloads,
    // generic arguments and casts, so the output is closer to the original source.
    const libs = await bundledJars(file, tmp);
    if (libs.length) log(`Using ${libs.length} bundled librar${libs.length === 1 ? 'y' : 'ies'} as context for more accurate types`);
    log('Decompiling with Vineflower…');
    let classes = 0;
    checkCancel(signal);
    const { code, tail } = await run(java, ['-jar', vf, '-dgs=1', '--verify-anonymous-classes=1', '-log=INFO',
      ...libs.map((l) => `-e=${l}`), file, outDir], {
      signal,
      onLine: (l) => {
        if (/Decompiling class/i.test(l)) {
          classes++;
          if (classes % 25 === 0) log(`…${classes} classes decompiled`);
        } else if (!/^INFO:\s*(\.\.\.|Loading|Preprocessing|Scanning)/.test(l)) {
          log(l);
        }
      },
    });
    if (code !== 0) throw new Error('Vineflower failed:\n' + tail);
  } finally {
    await rmrf(tmp).catch(() => {});
  }

  // Archives come out as a source jar — unpack it so the source is browsable.
  for (const ent of await fsp.readdir(outDir)) {
    const p = path.join(outDir, ent);
    if (/\.(jar|war|ear|zip|jmod)$/i.test(ent) && (await fsp.stat(p)).isFile()) {
      log(`Unpacking ${ent}…`);
      new AdmZip(p).extractAllTo(outDir, true);
      await fsp.rm(p, { force: true });
    }
  }

  // A library that publishes its sources (a -sources.jar next to it, or on Maven Central) has its exact
  // original code available: use it alongside the decompiled code.
  if (originalSources !== false && /\.(jar|war|ear)$/i.test(file)) {
    const r = await originals.javaOriginalSources(file, path.join(outDir, 'original-source'), { signal, log }).catch(() => null);
    if (r?.files) await writeOriginalNote(outDir, `${r.files.toLocaleString('en')} original source files from ${r.from.join(', ')}.`);
  }
}

/** A ProGuard / R8 mapping file for an Android app: next to it, or inside an app bundle. */
async function findAndroidMapping(file, tmp) {
  const dir = path.dirname(file);
  const stem = path.basename(file).replace(/\.[^.]+$/, '');
  for (const name of [`${stem}.mapping.txt`, `${stem}-mapping.txt`, 'mapping.txt', 'proguard.map', `${stem}.map`]) {
    const p = path.join(dir, name);
    if (await exists(p)) return p;
  }
  if (/\.aab$/i.test(file)) {
    try {
      const e = new AdmZip(file).getEntries().find((x) => /BUNDLE-METADATA\/com\.android\.tools\.build\.obfuscation\/proguard\.map$/i.test(x.entryName));
      if (e) {
        const p = path.join(tmp, 'proguard.map');
        await fsp.writeFile(p, e.getData());
        return p;
      }
    } catch { /* not a zip */ }
  }
  return null;
}

async function decompileAndroid(tools, file, outDir, log, { signal, androidDeobf = false } = {}) {
  const java = await tools.java(log);
  const jadx = await tools.jadx(log);
  checkCancel(signal);
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-jadx-'));
  const extra = [
    // Original names that survive in Kotlin metadata, SourceDebugExtension and null-checks.
    '-Pkotlin-smap.class-alias-source-dbg=yes', '--use-kotlin-methods-for-var-names', 'apply-and-hide',
  ];
  const mapping = await findAndroidMapping(file, tmp);
  if (mapping) {
    // ProGuard / R8 files map original -> obfuscated; JADX applies mappings the other way unless inverted.
    extra.push('--mappings-path', mapping, '-Prename-mappings.invert=yes');
    log(`Using the ProGuard/R8 mapping ${path.basename(mapping)}: original class, method and field names are restored`);
  } else if (androidDeobf) {
    extra.push('--deobf');
  }
  log('Decompiling with JADX (large apps can take a few minutes)…');
  let lastPct = -1;
  const { code, tail } = await run(
    java,
    // APKs and app bundles are saved as an Android Studio (Gradle) project; plain DEX/JAR input as source only.
    ['-XX:MaxRAMPercentage=70.0', '-cp', jadx, 'jadx.cli.JadxCLI', '--show-bad-code', ...extra,
      ...(/\.(apk|aab|aar|xapk|apks|apkm)$/i.test(file) ? ['--export-gradle'] : []), '-d', outDir, file],
    {
      signal,
      onLine: (l) => {
        const m = l.match(/progress:\s*(\d+) of (\d+)/);
        if (m) {
          const pct = Math.floor((Number(m[1]) * 100) / Math.max(1, Number(m[2])));
          if (pct !== lastPct) {
            lastPct = pct;
            log(`Decompiling classes ${m[1]} / ${m[2]} (${pct}%)`, { progress: pct, quiet: pct % 10 !== 0 });
          }
        } else if (!/progress:/.test(l)) {
          log(l.replace(/^INFO\s+-\s*/, ''));
        }
      },
    }
  );
  await rmrf(tmp).catch(() => {});
  // JADX exits non-zero if *some* methods failed, which is common — keep the output if there is any.
  if (code !== 0) {
    if ((await countFiles(outDir)) === 0) throw new Error('JADX failed:\n' + tail);
    log('JADX finished with some errors (some methods could not be fully decompiled).', { warn: true });
  }
  if (/\.(apk|aab)$/i.test(file)) await androidFrameworks(tools, file, outDir, log, signal);
}

/**
 * Cross-platform frameworks inside an Android package (React Native, Cordova/Capacitor, Xamarin/MAUI,
 * Flutter, Unity): JADX only sees the Java/Kotlin host. Findings go to FRAMEWORKS.md.
 */
async function androidFrameworks(tools, file, outDir, log, signal) {
  let entries;
  try { entries = new AdmZip(file).getEntries(); } catch { return; }
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-fw-'));
  try {
    const files = [];
    for (const e of entries) {
      if (e.isDirectory) continue;
      const rel = e.entryName.replace(/\\/g, '/');
      // Only what is analysed is extracted; the rest is just listed (for detection).
      const want = /(^|\/)(index\.android\.bundle|[^/]+\.jsbundle)$/i.test(rel) || /(^|\/)assets\/(www|public)\//i.test(rel) || /\.dll$/i.test(rel);
      let abs = null;
      if (want) {
        const dest = path.resolve(tmp, ...rel.split('/').filter((s) => s && s !== '..'));
        if (!dest.startsWith(tmp + path.sep)) continue;
        await fsp.mkdir(path.dirname(dest), { recursive: true });
        await fsp.writeFile(dest, e.getData());
        abs = dest;
      }
      files.push({ rel, abs });
    }
    const fw = await frameworks.analyzeFrameworks(files.filter((f) => f.abs || !/\.dll$/i.test(f.rel)), outDir, {
      log, signal,
      dotnet: (dll, dir) => tools.ilspy(log).then((exe) => ilspyOne(exe, dll, dir, log, signal, path.dirname(dll))),
    });
    if (fw.detected.length) {
      await fsp.writeFile(path.join(outDir, 'FRAMEWORKS.md'), [`# ${fw.detected.join(', ')}`, '',
        'This Android app is built with a cross-platform framework, so its real code is not (only) the Java/Kotlin decompiled by JADX:', '',
        ...fw.notes, ''].join('\n'));
      log(`Cross-platform app: ${fw.detected.join(', ')} (see FRAMEWORKS.md)`);
    }
  } finally {
    await rmrf(tmp).catch(() => {});
  }
}

/** Adds a line to ORIGINAL-SOURCE.md, which explains the original-source/ folder. */
async function writeOriginalNote(outDir, line) {
  const file = path.join(outDir, 'ORIGINAL-SOURCE.md');
  if (!(await exists(file))) {
    await fsp.writeFile(file, [
      '# Original source', '',
      'This program still points to its original source code, so `original-source/` holds the **exact files its',
      'authors wrote** (with their comments and formatting), next to the decompiled code. Use them to read and',
      'rebuild; the decompiled code shows what is actually in this build when the two differ.', '', '',
    ].join('\n'));
  }
  await fsp.appendFile(file, `- ${line}\n`);
}

/**
 * Decompiles one assembly into `outDir`. With `acc.outRoot`, also recovers what the build left behind:
 * its PDB (local files, embedded, or from the NuGet / Microsoft symbol servers) so ILSpy uses the original
 * local variable names, and the exact source files (embedded in the PDB or via Source Link) into
 * <outRoot>/original-source/<assembly>/.
 */
async function ilspyOne(exe, dll, outDir, log, signal, refDir, acc = {}) {
  // -p writes a compilable SDK-style project: WinForms designer code, WPF XAML (from BAML), .resx,
  // icons and the manifest. A method it can't decompile must not lose the whole assembly.
  const args = ['-p', '--nested-directories', '--disable-updatecheck', '--ignore-decompilation-errors', '-o', outDir];
  if (refDir) args.push('-r', refDir);
  let input = dll;
  let usePdb = await exists(dll.replace(/\.(dll|exe)$/i, '.pdb'));
  const work = acc.outRoot ? await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-pdb-')) : null;
  try {
    if (acc.outRoot) {
      const asm = path.basename(dll).replace(/\.(dll|exe|winmd)$/i, '');
      const r = await originals.dotnetOriginalSources(dll, acc.originalSources === false ? null : path.join(acc.outRoot, 'original-source', asm), {
        symbols: acc.symbols !== false, download: acc.originalSources !== false, workDir: work, signal, log,
      }).catch(() => null);
      if (r?.files) {
        const how = [r.embedded && `${r.embedded} embedded in its debug symbols`, r.downloaded && `${r.downloaded} downloaded through Source Link`].filter(Boolean).join(', ');
        log(`${asm}: ${r.files} original source files recovered (${how})`);
        await writeOriginalNote(acc.outRoot, `\`original-source/${asm}/\`: ${r.files} of ${r.total} source files (${how}).`);
      }
      if (r?.embeddedPdb) usePdb = true;
      // A downloaded PDB must sit next to the assembly for ILSpy: decompile a copy placed beside it.
      if (r?.pdb && path.dirname(r.pdb) === work) {
        input = path.join(work, path.basename(dll));
        await fsp.copyFile(dll, input);
        const want = input.replace(/\.(dll|exe|winmd)$/i, '.pdb');
        if (r.pdb !== want) await fsp.rename(r.pdb, want);
        usePdb = true;
      }
    }
    const attempt = (withPdb, file) => run(exe, [...args, ...(withPdb ? ['-usepdb'] : []), file], {
      env: { DOTNET_ROLL_FORWARD: 'Major' }, signal, onLine: (l) => log(l),
    });
    let { code, tail } = await attempt(usePdb, input);
    const empty = async () => !(await exists(outDir)) || (await countFiles(outDir)) === 0;
    if (code !== 0 && usePdb && (await empty())) {
      log('ILSpy could not use the debug symbols; decompiling without them.', { warn: true });
      ({ code, tail } = await attempt(false, dll));
    }
    if (code !== 0 && (await empty())) throw new Error('ILSpy failed:\n' + tail);
  } finally {
    if (work) await rmrf(work).catch(() => {});
  }
}

async function decompileDotNet(tools, file, outDir, log, { signal, symbols, originalSources } = {}) {
  const exe = await tools.ilspy(log);
  checkCancel(signal);
  log('Decompiling with ILSpy…');
  await ilspyOne(exe, file, path.join(outDir, path.basename(file).replace(/\.[^.]+$/, '')), log, signal, path.dirname(file),
    { outRoot: outDir, symbols, originalSources });
}

async function decompileDotNetArchive(tools, file, outDir, log, { signal, symbols, originalSources } = {}) {
  const exe = await tools.ilspy(log);
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-'));
  try {
    const entries = new AdmZip(file).getEntries().filter((e) => !e.isDirectory && /\.(dll|exe)$/i.test(e.entryName));
    let done = 0;
    for (const entry of entries) {
      const dll = path.join(tmp, String(done), path.basename(entry.entryName));
      await fsp.mkdir(path.dirname(dll), { recursive: true });
      await fsp.writeFile(dll, entry.getData());
      if (!isDotNetPE(await readHead(dll))) { log(`Skipping native binary ${entry.entryName}`); continue; }
      log(`Decompiling ${entry.entryName}…`, { progress: Math.floor((done * 100) / entries.length) });
      const target = path.join(outDir, entry.entryName.replace(/[\\/]/g, '_').replace(/\.(dll|exe)$/i, ''));
      checkCancel(signal);
      await ilspyOne(exe, dll, target, log, signal, path.dirname(dll), { outRoot: outDir, symbols, originalSources });
      done++;
    }
    if (!done) throw new Error('No .NET assemblies were found inside this archive.');
  } finally {
    await rmrf(tmp).catch(() => {});
  }
}

// ---- .NET single-file bundles

function readBundleManifest(buf) {
  let p = 0;
  const u32 = () => { const v = buf.readUInt32LE(p); p += 4; return v; };
  const i64 = () => { const v = Number(buf.readBigInt64LE(p)); p += 8; return v; };
  const str = () => { // BinaryWriter string: 7-bit encoded length, then UTF-8
    let len = 0;
    for (let shift = 0, b = 0x80; b & 0x80; shift += 7) { b = buf[p++]; len |= (b & 0x7f) << shift; }
    const s = buf.toString('utf8', p, p + len);
    p += len;
    return s;
  };
  const major = u32();
  u32(); // minor
  const count = u32();
  str(); // bundle id
  if (major >= 2) p += 8 * 5; // deps.json / runtimeconfig.json locations + flags
  const files = [];
  for (let i = 0; i < count; i++) {
    const offset = i64();
    const size = i64();
    const compressed = major >= 6 ? i64() : 0;
    const type = buf[p++];
    files.push({ offset, size, compressed, type, rel: str() });
  }
  return files;
}

// Framework pieces of a self-contained bundle, used when there's no deps.json to tell us.
const FRAMEWORK_FILE = /^(System|Microsoft|mscorlib|netstandard|WindowsBase|Presentation\w*|UIAutomation\w*|Accessibility|DirectWriteForwarder|ReachFramework|WindowsFormsIntegration|coreclr|clrjit|clrgc|hostfxr|hostpolicy|mscordaccore\w*|mscordbi|mscorrc|createdump|msquic|vcruntime\w*|D3DCompiler\w*|PenImc\w*|wpfgfx\w*)\./i;

async function decompileDotNetBundle(tools, file, outDir, log, { signal, symbols, originalSources } = {}) {
  const exe = await tools.ilspy(log);
  const headerOffset = await findBundleHeader(file);
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-'));
  const fh = await fsp.open(file, 'r');
  try {
    const { size } = await fh.stat();
    const mbuf = Buffer.alloc(Math.min(size - headerOffset, 32 * 1024 * 1024));
    await fh.read(mbuf, 0, mbuf.length, headerOffset);
    const files = readBundleManifest(mbuf);
    log(`.NET single-file app — unpacking ${files.length} bundled files…`);

    const extracted = [];
    for (const f of files) {
      const dest = path.resolve(tmp, f.rel);
      if (!dest.startsWith(tmp + path.sep)) continue;
      const raw = Buffer.alloc(f.compressed || f.size);
      await fh.read(raw, 0, raw.length, f.offset);
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      await fsp.writeFile(dest, f.compressed ? zlib.inflateRawSync(raw) : raw);
      extracted.push({ ...f, rel: f.rel.replace(/\\/g, '/'), dest, name: path.basename(dest) });
    }

    // deps.json says which assemblies are the app's own ("project"), NuGet packages, or the runtime.
    const kind = new Map();
    const deps = extracted.find((f) => f.name.endsWith('.deps.json'));
    if (deps) {
      try {
        const j = JSON.parse((await fsp.readFile(deps.dest, 'utf8')).replace(/^﻿/, ''));
        for (const target of Object.values(j.targets || {})) {
          for (const [key, lib] of Object.entries(target)) {
            const type = j.libraries?.[key]?.type;
            for (const p of [...Object.keys(lib.runtime || {}), ...Object.keys(lib.native || {})]) {
              kind.set(path.basename(p).toLowerCase(), type);
            }
          }
        }
      } catch { /* ignore a bad deps.json */ }
    }
    const hasProjects = [...kind.values()].includes('project');
    const mainName = path.basename(file).replace(/\.[^.]+$/, '').toLowerCase() + '.dll';

    const appAsms = [];
    const keep = [];
    let skipped = 0;
    for (const f of extracted) {
      const k = kind.get(f.name.toLowerCase());
      const framework = k ? k === 'runtimepack' || k === 'referenceassembly' : FRAMEWORK_FILE.test(f.name);
      const managed = /\.(dll|exe)$/i.test(f.name) && isDotNetPE(await readHead(f.dest));
      if (managed && (f.name.toLowerCase() === mainName || (hasProjects ? k === 'project' : !framework))) appAsms.push(f);
      else if (framework) skipped++;
      else keep.push(f);
    }
    appAsms.sort((a, b) => (b.name.toLowerCase() === mainName) - (a.name.toLowerCase() === mainName));
    if (!appAsms.length) throw new Error('This .NET single-file app contains no application assemblies to decompile.');

    for (const [i, f] of appAsms.entries()) {
      log(`Decompiling ${f.name}…`, { progress: Math.floor((i * 100) / appAsms.length) });
      checkCancel(signal);
      await ilspyOne(exe, f.dest, path.join(outDir, f.name.replace(/\.(dll|exe)$/i, '')), log, signal, tmp, { outRoot: outDir, symbols, originalSources });
    }
    for (const f of keep) {
      const dest = path.join(outDir, '_bundle', ...f.rel.split('/'));
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      await fsp.copyFile(f.dest, dest);
    }
    const libs = keep.filter((f) => /\.(dll|exe)$/i.test(f.name)).length;
    log(
      `Decompiled ${appAsms.length} app assembl${appAsms.length === 1 ? 'y' : 'ies'}` +
        (keep.length ? `; ${keep.length} other files saved in _bundle${libs ? ` (${libs} libraries — drop one in to decompile it)` : ''}` : '') +
        (skipped ? `; ${skipped} .NET runtime files skipped` : '')
    );
  } finally {
    await fh.close();
    await rmrf(tmp).catch(() => {});
  }
}

// ---- native code (Ghidra)

// "INFO  ANALYZING all memory and code: … (HeadlessAnalyzer)  " → "ANALYZING all memory and code: …"
function cleanGhidraLine(l) {
  return l.replace(/^\s*(INFO|WARN|ERROR|DEBUG)\s+/, '').replace(/\s+\([\w$.]+\)\s*$/, '').trim();
}

function fmtElapsed(ms) {
  if (ms < 10000) return `${(ms / 1000).toFixed(1)}s`;
  const s = Math.round(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s` : `${s}s`;
}

async function decompileNative(tools, file, outDir, log, opts = {}) {
  const { signal, ghidraTimeout = GHIDRA_FUNC_TIMEOUT, symbols = true, thorough = false } = opts;
  let { names = null } = opts;
  // Windows EXE/DLL: what is it really? (toolchain, wrapped Python / JavaScript / Java, Delphi forms…)
  let native = null;
  if ((await readHead(file, 2)).toString('latin1') === 'MZ') {
    native = await require('./native').analyzeNative(tools, file, outDir, log, {
      decompileJar: (jar, dir) => fsp.mkdir(dir, { recursive: true }).then(() => decompileJava(tools, jar, dir, log, opts)),
    }).catch((e) => { log('Program analysis failed: ' + e.message, { warn: true }); return null; });
    if (native?.skipGhidra) {
      const toolchain = await fsp.readFile(path.join(outDir, 'TOOLCHAIN.md'), 'utf8').catch(() => '');
      await fsp.writeFile(path.join(outDir, 'README.md'), toolchain.replace(/^# How this program was built/, `# ${path.basename(file)}`));
      log('The real program was extracted; the launcher EXE itself was not decompiled.');
      return;
    }
  }
  log('Native machine code: Ghidra will rebuild it as C-like pseudo-code (names and types are reconstructed, not the original source).');
  const head = (await readHead(file, 4096)).toString('latin1');
  if (head.includes('UPX0') && head.includes('UPX1')) {
    log('This program is packed with UPX, so most of the output will be the unpacker. For real code, unpack it first (upx -d) and drop the result.', { warn: true });
  }
  const ghidra = await tools.ghidra(log);
  const java = await tools.jdk(ghidra.javaMin, log);

  // Kept in a fixed folder (rewritten only when changed) so Ghidra reuses its compiled copy.
  const scriptDir = path.join(tools.dir, 'ghidra-scripts');
  for (const name of [GHIDRA_SCRIPT, GHIDRA_THOROUGH_SCRIPT]) {
    const script = await fsp.readFile(path.join(__dirname, 'ghidra', name), 'utf8');
    const scriptDest = path.join(scriptDir, name);
    if (!(await exists(scriptDest)) || (await fsp.readFile(scriptDest, 'utf8')) !== script) {
      await fsp.mkdir(scriptDir, { recursive: true });
      await fsp.writeFile(scriptDest, script);
    }
  }
  if (thorough) log('Thorough analysis: extra Ghidra analyzers recover function parameters and return types (slower).');

  const work = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-'));
  let heartbeat;
  try {
    // Mach-O (macOS / iOS): class-dump and Swift interfaces from the metadata, and their method addresses
    // so Ghidra's functions get the real names.
    if (!names && isMachO(await readHead(file, 8))) {
      try {
        const r = await ios.dumpImage(await fsp.readFile(file), path.basename(file), outDir, log);
        if (r.objc) log(`Objective-C: ${r.objc.classes} classes, ${r.objc.methods} methods → headers/`);
        if (r.swift) log(`Swift: ${r.swift.total} types → swift/`);
        if (r.macho.encrypted) log('This binary is FairPlay-encrypted: its code can only be decompiled after it is decrypted.', { warn: true });
        if (r.methods.length) { names = path.join(work, 'names.txt'); await fsp.writeFile(names, ios.namesFile(r.methods)); }
      } catch (e) { log('Mach-O metadata could not be read: ' + e.message, { warn: true }); }
    }
    // Ghidra gets an ASCII-named copy: the Windows java launcher garbles non-ANSI arguments.
    const inDir = path.join(work, 'in');
    const projDir = path.join(work, 'project');
    const outTmp = path.join(work, 'out');
    for (const d of [inDir, projDir, outTmp]) await fsp.mkdir(d);
    const input = path.join(inDir, path.basename(file).replace(/[^\w.\-]/g, '_'));
    await fsp.copyFile(file, input);
    // A .pdb next to the binary gives Ghidra the real function names and types.
    const stem = file.replace(/\.[^.\\/]+$/, '');
    let havePdb = false;
    for (const pdb of [stem + '.pdb', file + '.pdb']) {
      if (await exists(pdb)) {
        await fsp.copyFile(pdb, path.join(inDir, path.basename(pdb)));
        log(`Using debug symbols from ${path.basename(pdb)}`);
        havePdb = true;
        break;
      }
    }
    // Without a local PDB, ask Microsoft's symbol server: it has the PDBs of Windows and of Microsoft's
    // programs and libraries, which give Ghidra the real function names, types and structures.
    if (!havePdb && symbols !== false) {
      const dbg = await originals.readPeDebug(file).catch(() => null);
      if (dbg?.codeView && !dbg.codeView.portable) {
        log('Looking for debug symbols on the Microsoft symbol server…');
        const got = await originals.fetchPdb(dbg.codeView, inDir, { signal, log }).catch(() => null);
        if (!got) log('No public debug symbols for this program: names are reconstructed by Ghidra.', { quiet: true });
      }
    }

    const cpus = Math.max(1, os.cpus().length - 1);
    const heapGb = Math.max(2, Math.min(16, Math.floor(os.totalmem() / 2 ** 30 / 3)));
    const args = [
      ...ghidra.vmargs,
      `-Xmx${heapGb}G`, '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2', `-Duser.home=${os.homedir()}`,
      '-cp', ghidra.classpath, 'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless',
      projDir, 'DropDecompiler', '-import', input,
      '-scriptPath', [scriptDir, path.join(ghidra.home, 'Ghidra', 'Features', 'Decompiler', 'ghidra_scripts')].join(';'),
      ...(thorough ? ['-preScript', GHIDRA_THOROUGH_SCRIPT] : []),
      // C++ (MSVC with RTTI): rebuild classes, vtables, constructors/destructors and `this` types first.
      ...(native?.cpp ? ['-postScript', 'RecoverClassesFromRTTIScript.java'] : []),
      '-postScript', GHIDRA_SCRIPT, outTmp, String(ghidraTimeout), ...(names ? [names] : []),
      '-max-cpu', String(cpus), '-deleteProject',
    ];

    log(`Starting Ghidra ${ghidra.version}…`);
    let started = Date.now();
    let analyzing = false;
    let loading = false;
    const errors = [];
    checkCancel(signal);
    const { code, tail } = await run(java, args, {
      cwd: work,
      signal,
      onLine: (raw) => {
        const l = cleanGhidraLine(raw);
        const ddx = l.match(/DDX:(\w+) ?(.*)$/);
        if (ddx) {
          analyzing = false;
          if (ddx[1] === 'PROGRESS') {
            const [done, total] = ddx[2].split('/').map(Number);
            const pct = Math.floor((done * 100) / Math.max(1, total));
            log(`Decompiling functions ${done.toLocaleString()} / ${total.toLocaleString()} (${pct}%)`, { progress: pct });
          } else {
            log(ddx[2]);
          }
        } else if (/^IMPORTING:/.test(l) && !loading) {
          loading = true;
          log('Loading the binary…');
        } else if (/^ANALYZING all memory and code/.test(l)) {
          analyzing = true;
          started = Date.now();
          clearInterval(heartbeat);
          heartbeat = setInterval(() => analyzing && log(`Analyzing machine code… ${fmtElapsed(Date.now() - started)}`), 15000);
          log('Analyzing machine code — the slow part (big binaries can take several minutes)…');
        } else if (/^REPORT: Analysis succeeded/.test(l)) {
          analyzing = false;
          log(`Analysis finished after ${fmtElapsed(Date.now() - started)}`);
        } else if (/^\s*(ERROR|SEVERE)\b/.test(raw) || /^REPORT: .*fail/i.test(l)) {
          errors.push(l);
          log(l, { warn: true, quiet: true });
        } else {
          log(l, { quiet: true });
        }
      },
    });
    clearInterval(heartbeat);

    if ((await countFiles(outTmp)) === 0) {
      const loadFailed = errors.some((e) => /Import failed|No load spec|No memory blocks/i.test(e));
      const details = (errors.slice(-4).join('\n') || tail).replace(/file:\/\/\/\S*?\/in\//g, '');
      throw new Error(
        (loadFailed
          ? 'Ghidra could not load this file — it may be damaged, encrypted, or not a complete program.'
          : 'Ghidra could not decompile this file.') + '\n' + details
      );
    }
    await moveInto(outTmp, outDir);
    if (code !== 0) log('Ghidra exited with an error — the output may be incomplete.', { warn: true });
  } finally {
    clearInterval(heartbeat);
    await rmrf(work).catch(() => {});
  }
}

const ENGINES = {
  java: { name: 'Vineflower', fn: decompileJava },
  android: { name: 'JADX', fn: decompileAndroid },
  dotnet: { name: 'ILSpy', fn: decompileDotNet },
  'dotnet-archive': { name: 'ILSpy', fn: decompileDotNetArchive },
  'dotnet-bundle': { name: 'ILSpy', fn: decompileDotNetBundle },
  native: { name: 'Ghidra', fn: decompileNative },
  lua: { name: 'Lua decompiler', fn: decompileLua },
  manifest: { name: 'Manifest reader', fn: decompileManifest },
  generic: { name: 'File analyser', fn: decompileGeneric },
  website: { name: 'Website downloader', fn: decompileWebsite },
  ios: {
    name: 'iOS app decompiler',
    fn: (tools, file, outDir, log, opts) => ios.decompileIpa(tools, file, outDir, log, {
      ...opts,
      native: (bin, dir, names) => fsp.mkdir(dir, { recursive: true }).then(() => decompileNative(tools, bin, dir, log, { ...opts, names })),
      dotnet: (dll, dir) => tools.ilspy(log).then((exe) => ilspyOne(exe, dll, dir, log, opts.signal, path.dirname(dll))),
    }),
  },
};

/**
 * Decompile `file` into a new folder under `outputRoot`.
 * `log(message, { progress?, warn?, quiet? })` receives status updates.
 * `opts.signal` (AbortSignal) cancels the job; `opts.ghidraTimeout` is the per-function limit in seconds.
 */
async function decompile(tools, file, outputRoot, log = () => {}, opts = {}) {
  checkCancel(opts.signal);
  // A web address instead of a file: download the website.
  const web = isUrl(file);
  const info = web ? { engine: 'website', label: 'WEB' } : await detect(file);
  const engine = ENGINES[info.engine];
  log(`Detected ${info.label} → using ${engine.name}`, { detected: info });
  const base = web ? new URL(file).hostname.replace(/^www\./, '') : path.basename(file).replace(/\.[^.]+$/, '');
  const outDir = await uniqueDir(path.join(outputRoot, `${base}_${info.label.toLowerCase()}_src`));
  const started = Date.now();
  let build = null;
  try {
    await engine.fn(tools, file, outDir, log, opts);
    checkCancel(opts.signal);
    build = await makeRebuildable(info.engine, file, outDir, log, { ...opts, tools });
  } catch (err) {
    await rmrf(outDir).catch(() => {});
    throw err;
  }
  const files = await countFiles(outDir);
  if (!files) throw new Error('The decompiler produced no output.');
  const ms = Date.now() - started;
  log(`Done — ${files} files in ${fmtElapsed(ms)}`, { progress: 100 });
  return { outDir, files, ms, engineName: engine.name, build, ...info };
}

function androidReport(name) {
  return [
    `# Rebuilding ${name}`, '',
    'This folder is an Android Studio (Gradle) project made by JADX: the Java source, the decoded resources',
    '(layouts, strings, images) and AndroidManifest.xml.', '',
    '## How to build', '',
    '1. Open this folder in Android Studio (File > Open) and let it sync. It installs the Android SDK it needs.',
    '2. Build > Make Project. Fix what it reports, then Run.', '',
    '## What to expect', '',
    '- JADX output usually needs some fixes before it compiles: methods it could not decompile are marked with',
    '  "Code decompiled incorrectly" comments, and some generated R/BuildConfig references need adjusting.',
    '- Apps built with Kotlin, R8/ProGuard or obfuscation come back as Java with shortened names.',
    '- To rebuild the app exactly as it was (for example to change one resource), use apktool, which works on',
    '  smali (Dalvik assembly) instead of Java and always rebuilds.',
    '- A rebuilt APK must be signed with your own key; it cannot reuse the original signature.', '',
  ].join('\n');
}

// Turns the output into something that builds again (see rebuild.js). Problems here never fail the
// job: the decompiled source is still useful, and BUILD.md / the log say what's left.
async function makeRebuildable(engine, file, outDir, log, opts) {
  try {
    if (engine.startsWith('dotnet')) {
      return await rebuild.rebuildDotNet(outDir, {
        inputFile: file, name: path.basename(file), log, signal: opts.signal, build: opts.verifyBuild !== false,
      });
    }
    if (engine === 'java' && /\.(jar|zip|war|ear)$/i.test(file) && opts.verifyBuild !== false) {
      const javaExe = await opts.tools.anyJdk(log);
      return await require('./javabuild').rebuildJava(outDir, { inputFile: file, name: path.basename(file), javaExe, log, signal: opts.signal });
    }
    if (engine === 'android' && (await exists(path.join(outDir, 'settings.gradle')) || await exists(path.join(outDir, 'settings.gradle.kts')))) {
      await fsp.writeFile(path.join(outDir, 'BUILD.md'), androidReport(path.basename(file)));
      log('Saved as an Android Studio (Gradle) project — open the folder in Android Studio to build it');
      return { kind: 'android', checked: false };
    }
    if (engine === 'native') {
      const readme = path.join(outDir, 'README.md');
      if (!(await exists(path.join(outDir, 'functions.txt')))) return null; // a wrapped program: nothing native to rebuild
      const sum = await rebuild.nativeResources(file, outDir, { log, signal: opts.signal });
      const toolchain = await fsp.readFile(path.join(outDir, 'TOOLCHAIN.md'), 'utf8').catch(() => '');
      if (await exists(readme)) await fsp.appendFile(readme, (toolchain ? '\n' + toolchain.replace(/^# How this program was built\n/, '') : '') + rebuild.nativeReadmeSection(sum));
      return sum;
    }
  } catch (err) {
    if (err.cancelled) throw new CancelledError();
    log('Could not prepare the rebuild project: ' + err.message, { warn: true });
  }
  return null;
}

module.exports = { Tools, detect, decompile, countFiles, isDotNetPE, isUrl, SUPPORTED_EXTS, CancelledError, rebuildFolder: rebuild.rebuildFolder };
