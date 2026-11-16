// Programs that are not really native code: the EXE is a launcher or runtime and the real program is inside
// (or next to it). Extracting it gives the original language back instead of decompiled runtime code.
//   electron      resources/app.asar  -> the app's JavaScript / HTML / CSS
//   node-sea      NODE_SEA_BLOB       -> the main JavaScript
//   bun / deno    embedded modules    -> JavaScript / TypeScript
//   java-overlay  JAR appended to EXE -> Java (decompiled by Vineflower)
//   pyinstaller   CArchive + PYZ      -> .pyc modules -> Python (decompiled by pycdc)
//   delphi-forms  TPF0 resources      -> .dfm form files (exact UI definitions)
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const zlib = require('zlib');

const safeRel = (p) => p.replace(/\\/g, '/').split('/').filter((s) => s && s !== '.' && s !== '..')
  .map((s) => s.replace(/[<>:"|?*\x00-\x1f]/g, '_').replace(/[. ]+$/, '_')).join('/');

async function writeOut(root, rel, data) {
  const r = safeRel(rel);
  if (!r) return null;
  const dest = path.join(root, ...r.split('/'));
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  await fsp.writeFile(dest, data);
  return dest;
}

function beautify(code) {
  try { return require('js-beautify').js(code, { indent_size: 2, max_preserve_newlines: 2 }); } catch { return code; }
}
const minified = (t) => t.length > 3000 && t.length / Math.max(1, t.split('\n').length) > 250;

// ---------------------------------------------------------------- Electron (asar)

/** Files of an asar archive: [{ path, data }] (unpacked files are read from <archive>.unpacked). */
function readAsar(file) {
  const buf = fs.readFileSync(file);
  // Two Chromium pickles: the first holds the header size, the second the JSON header.
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  const header = JSON.parse(buf.toString('utf8', 16, 16 + jsonLen));
  const base = 8 + headerSize;
  const out = [];
  const walk = (node, prefix) => {
    for (const [name, entry] of Object.entries(node.files || {})) {
      const p = prefix ? `${prefix}/${name}` : name;
      if (entry.files) walk(entry, p);
      else if (entry.link) continue;
      else if (entry.unpacked) {
        const u = path.join(`${file}.unpacked`, ...p.split('/'));
        if (fs.existsSync(u)) out.push({ path: p, file: u });
      } else {
        const off = base + Number(entry.offset);
        out.push({ path: p, data: buf.subarray(off, off + entry.size) });
      }
    }
  };
  walk(header, '');
  return out;
}

async function extractElectron(file, outDir, log) {
  const res = path.join(path.dirname(file), 'resources');
  const asar = path.join(res, 'app.asar');
  const folder = path.join(res, 'app');
  const dest = path.join(outDir, 'original-source', 'app');
  let n = 0;
  let pretty = 0;
  const put = async (rel, data) => {
    if (/\.(js|mjs|cjs)$/i.test(rel) && data.length < 8e6) {
      const t = data.toString('utf8');
      if (minified(t)) { await writeOut(path.join(outDir, 'beautified'), rel, beautify(t)); pretty++; }
    }
    await writeOut(dest, rel, data);
    n++;
  };
  if (fs.existsSync(asar)) {
    for (const f of readAsar(asar)) await put(f.path, f.data || await fsp.readFile(f.file));
  } else if (fs.existsSync(folder)) {
    const walk = async (dir, rel) => {
      for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) await walk(path.join(dir, e.name), r);
        else await put(r, await fsp.readFile(path.join(dir, e.name)));
      }
    };
    await walk(folder, '');
  } else {
    return { ok: false, note: 'Electron app, but resources/app.asar was not found next to the EXE: drop the EXE from its installation folder (or drop app.asar).' };
  }
  const pkg = await fsp.readFile(path.join(dest, 'package.json'), 'utf8').then(JSON.parse).catch(() => null);
  log(`Electron app: ${n} source files extracted from ${fs.existsSync(asar) ? 'app.asar' : 'resources/app'}`);
  return {
    ok: n > 0, files: n,
    note: `**Electron app${pkg?.name ? ` “${pkg.productName || pkg.name}” ${pkg.version || ''}` : ''}**: its JavaScript, HTML and CSS (the program itself, ${n} files) are in \`original-source/app/\`${pretty ? `; ${pretty} minified files re-indented in \`beautified/\`` : ''}. Look for \`.map\` files there: they contain the original TypeScript. The EXE itself is Electron (Chromium + Node.js) and needs no decompiling.`,
  };
}

// ---------------------------------------------------------------- Node.js single executable app

async function extractNodeSea(resources, outDir, log) {
  const r = resources.find((x) => x.name === 'NODE_SEA_BLOB');
  if (!r) return { ok: false, note: 'Node.js single executable: the NODE_SEA_BLOB resource was not found.' };
  const b = r.data;
  let main = null;
  let codePath = null;
  try {
    // SeaResource: uint32 magic (0x143DA20), uint32 flags, then size-prefixed strings: code path, main script…
    if (b.readUInt32LE(0) === 0x143da20) {
      let p = 8;
      const str = () => { const n = Number(b.readBigUInt64LE(p)); p += 8; const s = b.subarray(p, p + n); p += n; return s; };
      codePath = str().toString('utf8');
      main = str();
    }
  } catch { /* other layout */ }
  await writeOut(outDir, 'original-source/NODE_SEA_BLOB.bin', b);
  if (main && main.length && !main.subarray(0, 4096).includes(0)) {
    const name = path.basename(codePath || 'main.js') || 'main.js';
    await writeOut(outDir, `original-source/${name}`, main);
    if (minified(main.toString('utf8'))) await writeOut(outDir, `beautified/${name}`, beautify(main.toString('utf8')));
    log(`Node.js single executable: main script ${name} extracted`);
    return { ok: true, note: `**Node.js single executable app**: the embedded main script is \`original-source/${name}\` (the exact source that was bundled).` };
  }
  return { ok: false, note: 'Node.js single executable app: the main script is stored as a V8 snapshot or code cache, not as source; the raw blob is in `original-source/NODE_SEA_BLOB.bin`.' };
}

// ---------------------------------------------------------------- Bun / Deno (embedded module sources)

async function extractEmbeddedJs(buf, pe, kind, outDir, log) {
  let region = buf;
  if (kind === 'bun') {
    const s = pe.sections.find((x) => x.name === '.bun');
    if (s) region = buf.subarray(s.raw, s.raw + s.rawSize);
    else if (pe.overlay) region = buf.subarray(pe.overlay.offset);
  } else if (pe.overlay) region = buf.subarray(pe.overlay.offset);
  // Module sources are stored as plain text: keep long text runs that look like code.
  const chunks = [];
  let start = -1;
  for (let i = 0; i <= region.length; i++) {
    const c = region[i];
    const text = c === 9 || c === 10 || c === 13 || (c >= 0x20 && c < 0x7f) || c >= 0x80;
    if (text && start < 0) start = i;
    else if (!text && start >= 0) {
      if (i - start > 400) {
        const t = region.toString('utf8', start, i);
        if (/\b(function|const|let|var|import|export|class|=>|require\()/.test(t)) chunks.push(t);
      }
      start = -1;
    }
  }
  const names = [...new Set((region.toString('latin1').match(/(\/\$bunfs\/[\w./-]+|file:\/\/\/[\w./:-]+|https?:\/\/[\w./-]+\.(?:ts|js|tsx|jsx|mjs))/g) || []))].slice(0, 2000);
  const dir = path.join(outDir, 'original-source');
  let k = 0;
  for (const c of chunks) await writeOut(dir, `module_${String(++k).padStart(3, '0')}.js`, minified(c) ? beautify(c) : c);
  if (names.length) await writeOut(dir, 'MODULES.txt', names.join('\n') + '\n');
  log(`${kind === 'bun' ? 'Bun' : 'Deno'} executable: ${k} embedded source blocks extracted`);
  return { ok: k > 0, note: `**${kind === 'bun' ? 'Bun' : 'Deno'} compiled executable**: ${k} embedded source blocks are in \`original-source/\`${names.length ? ` (module names in \`MODULES.txt\`)` : ''}. They are the bundled JavaScript/TypeScript of the app.` };
}

// ---------------------------------------------------------------- Java wrapped in an EXE

async function extractJavaOverlay(buf, pe, outDir, log, decompileJar) {
  const ov = buf.subarray(pe.overlay.offset);
  const start = ov.indexOf(Buffer.from('PK\x03\x04', 'latin1'));
  if (start < 0) return { ok: false, note: 'No JAR was found inside the EXE.' };
  const jar = ov.subarray(start);
  const jarPath = await writeOut(outDir, 'original-source/embedded.jar', jar);
  log(`Embedded JAR found (${Math.round(jar.length / 1024)} KB): decompiling it as Java…`);
  if (decompileJar) {
    try { await decompileJar(jarPath, path.join(outDir, 'java')); } catch (e) { return { ok: true, note: `**Java program in an EXE**: the JAR is \`original-source/embedded.jar\` (decompiling it failed: ${e.message.split('\n')[0]}).` }; }
  }
  return { ok: true, note: '**Java program wrapped in an EXE**: the embedded JAR is `original-source/embedded.jar`, decompiled to Java in `java/`.' };
}

// ---------------------------------------------------------------- PyInstaller

const PYI_MAGIC = Buffer.from('MEI\x0c\x0b\x0a\x0b\x0e', 'latin1');

/** Minimal reader for Python's marshal format (enough for PYZ tables of contents). */
function unmarshal(buf, pos = 0) {
  const refs = [];
  let p = pos;
  const r = () => {
    const code = buf[p++];
    const flag = code & 0x80;
    const t = String.fromCharCode(code & 0x7f);
    let idx = -1;
    if (flag) { idx = refs.length; refs.push(null); }
    const keep = (v) => { if (idx >= 0) refs[idx] = v; return v; };
    switch (t) {
      case '0': return null; case 'N': return null; case 'F': return false; case 'T': return true;
      case 'i': { const v = buf.readInt32LE(p); p += 4; return keep(v); }
      case 'l': { const n = buf.readInt32LE(p); p += 4; let v = 0; for (let k = 0; k < Math.abs(n); k++) { v += buf.readUInt16LE(p) * 2 ** (15 * k); p += 2; } return keep(n < 0 ? -v : v); }
      case 's': case 'u': case 't': case 'a': case 'A': { const n = buf.readInt32LE(p); p += 4; const s = buf.toString(t === 's' ? 'latin1' : 'utf8', p, p + n); p += n; return keep(s); }
      case 'z': case 'Z': { const n = buf[p++]; const s = buf.toString('latin1', p, p + n); p += n; return keep(s); }
      case ')': { const n = buf[p++]; const a = []; keep(a); for (let k = 0; k < n; k++) a.push(r()); return a; }
      case '(': case '[': case '<': case '>': { const n = buf.readInt32LE(p); p += 4; const a = []; keep(a); for (let k = 0; k < n; k++) a.push(r()); return a; }
      case 'r': { const n = buf.readUInt32LE(p); p += 4; return refs[n]; }
      default: throw new Error(`marshal type ${t} not supported`);
    }
  };
  return r();
}

/** Magic number of .pyc files for a Python version (3.7+). */
const PYC_MAGIC = {
  307: 3394, 308: 3413, 309: 3425, 310: 3439, 311: 3495, 312: 3531, 313: 3571, 314: 3627, 315: 3651,
};

function pycHeader(magicBytes) {
  const h = Buffer.alloc(16);
  magicBytes.copy(h, 0, 0, 4);
  return h;
}

/** Entries of a PyInstaller CArchive: { pyver, entries: [{ name, type, data }] }. */
function readCArchive(buf) {
  const cookie = buf.lastIndexOf(PYI_MAGIC);
  if (cookie < 0) throw new Error('PyInstaller archive not found');
  const pkgLen = buf.readUInt32BE(cookie + 8);
  const tocOff = buf.readUInt32BE(cookie + 12);
  const tocLen = buf.readUInt32BE(cookie + 16);
  const pyver = buf.readUInt32BE(cookie + 20);
  const hasLibName = buf.length - cookie >= 88;
  const start = cookie + (hasLibName ? 88 : 24) - pkgLen;
  const entries = [];
  let p = start + tocOff;
  const end = p + tocLen;
  while (p < end) {
    const size = buf.readUInt32BE(p);
    if (size < 18) break;
    const pos = buf.readUInt32BE(p + 4);
    const clen = buf.readUInt32BE(p + 8);
    const compressed = buf[p + 16];
    const type = String.fromCharCode(buf[p + 17]);
    const name = buf.toString('utf8', p + 18, p + size).replace(/\0+$/, '');
    let data = buf.subarray(start + pos, start + pos + clen);
    if (compressed) { try { data = zlib.inflateSync(data); } catch { /* keep raw */ } }
    entries.push({ name, type, data });
    p += size;
  }
  return { pyver: pyver >= 100 ? pyver : pyver * 10 > 300 ? pyver : pyver, entries };
}

async function extractPyInstaller(buf, outDir, log, pyDecompile) {
  const { pyver, entries } = readCArchive(buf);
  const ver = pyver >= 100 ? `${Math.floor(pyver / 100)}.${pyver % 100}` : `${Math.floor(pyver / 10)}.${pyver % 10}`;
  const verKey = pyver >= 100 ? pyver : Math.floor(pyver / 10) * 100 + (pyver % 10);
  let magic = null;
  const pycs = [];
  const root = path.join(outDir, 'original-source');
  const other = path.join(outDir, 'bundled-files');
  let bundled = 0;
  for (const e of entries) {
    if (e.type === 'z' || e.type === 'Z') {
      // PYZ: "PYZ\0", pyc magic, offset of a marshalled table of contents; entries are zlib-compressed code objects.
      const z = e.data;
      if (z.toString('latin1', 0, 4) !== 'PYZ\0') continue;
      magic = z.subarray(4, 8);
      const toc = unmarshal(z, z.readUInt32BE(8));
      const list = Array.isArray(toc) ? toc : [];
      for (const item of list) {
        const [name, info] = item || [];
        if (!Array.isArray(info)) continue;
        const [ispkg, pos, len] = info.length === 3 ? info : [0, info[1], info[2]];
        let code = z.subarray(pos, pos + len);
        try { code = zlib.inflateSync(code); } catch { /* encrypted (older PyInstaller --key) */ }
        const rel = `${String(name).replace(/\./g, '/')}${ispkg ? '/__init__' : ''}.pyc`;
        pycs.push({ rel, code, module: true });
      }
    }
  }
  for (const e of entries) {
    if (e.type === 's') pycs.push({ rel: `${e.name}.pyc`, code: e.data, script: true });
    else if (e.type === 'm' || e.type === 'M') pycs.push({ rel: `${e.name.replace(/\./g, '/')}.pyc`, code: e.data, module: true });
    else if (e.type !== 'z' && e.type !== 'Z' && e.type !== 'o') { await writeOut(other, e.name, e.data); bundled++; }
  }
  if (!magic && PYC_MAGIC[verKey]) { magic = Buffer.alloc(4); magic.writeUInt16LE(PYC_MAGIC[verKey], 0); magic[2] = 0x0d; magic[3] = 0x0a; }
  const pycDir = path.join(outDir, 'pyc');
  const written = [];
  for (const f of pycs) {
    // Code objects have no .pyc header: add one (magic of this Python version, then zero flags/date/size).
    const data = f.code.subarray(0, 4).equals(magic || Buffer.alloc(4)) ? f.code : Buffer.concat([pycHeader(magic || Buffer.alloc(4)), f.code]);
    const dest = await writeOut(pycDir, f.rel, data);
    if (dest) written.push({ ...f, dest });
  }
  const scripts = written.filter((f) => f.script && !/^pyi_|^pyiboot|^_pyi/i.test(path.basename(f.rel)));
  log(`PyInstaller (Python ${ver}): ${written.length} .pyc modules, ${scripts.length} main script${scripts.length === 1 ? '' : 's'}: ${scripts.map((s) => s.rel).join(', ')}`);

  // Decompile: the app's own code first (main scripts and modules outside the standard library / site-packages).
  let decompiled = 0;
  let failed = 0;
  if (pyDecompile) {
    // The app's own code: everything that isn't the standard library, PyInstaller itself or a common package.
    const STDLIB = new Set(require('./data/python-stdlib.json'));
    const PACKAGES = /^(pkg_resources|setuptools|pip|_distutils_hack|PIL|numpy|pandas|scipy|matplotlib|requests|urllib3|certifi|charset_normalizer|idna|six|typing_extensions|attr|attrs|yaml|cryptography|cffi|pycparser|google|grpc|win32|win32com|pywintypes|pythoncom|pythonwin|psutil|packaging|dateutil|pytz|jinja2|markupsafe|click|colorama|tqdm|rich|pygments|websocket|websockets|aiohttp|multidict|yarl|frozenlist|aiosignal|async_timeout|PyQt5|PyQt6|PySide2|PySide6|shiboken2|shiboken6|wx|kivy|pygame|tkinterdnd2|customtkinter|pystray|keyboard|pynput|pyautogui|pyperclip|selenium|bs4|lxml|soupsieve|socks|httpx|httpcore|anyio|sniffio|h11|certifi|pydantic|pydantic_core|annotated_types)$/;
    const top = (rel) => rel.split('/')[0].replace(/\.pyc$/, '');
    const own = written.filter((f) => (f.script && !/^pyi/.test(top(f.rel))) || (!f.script && !STDLIB.has(top(f.rel)) && !PACKAGES.test(top(f.rel)) && !top(f.rel).startsWith('_'))).slice(0, 400);
    for (const f of own) {
      const r = await pyDecompile(f.dest).catch((e) => ({ error: e.message }));
      if (r && r.source) { await writeOut(root, f.rel.replace(/\.pyc$/, '.py'), r.source); decompiled++; }
      else failed++;
    }
    log(`Python decompiled: ${decompiled} files${failed ? `, ${failed} failed (their bytecode is in pyc/)` : ''}`);
  }
  return {
    ok: written.length > 0,
    note: `**PyInstaller (Python ${ver})**: the program is Python. ${written.length} compiled modules are in \`pyc/\` (with valid .pyc headers)` +
      (pyDecompile ? `; ${decompiled} of the app's own modules were decompiled back to Python in \`original-source/\`${failed ? ` (${failed} could not be: newer Python versions are only partly supported by decompilers)` : ''}` : '; no Python decompiler is available (it needs Visual Studio\'s C++ tools and CMake to build pycdc), so only the bytecode is extracted') +
      `. Main script${scripts.length === 1 ? '' : 's'}: ${scripts.map((s) => `\`${s.rel.replace(/\.pyc$/, '.py')}\``).join(', ') || 'none found'}. ${bundled} bundled files (DLLs, data) are in \`bundled-files/\`. The EXE itself is PyInstaller's bootloader.`,
  };
}

// ---------------------------------------------------------------- Delphi forms (TPF0 -> .dfm text)

/** Converts a binary Delphi form (TPF0) to the text .dfm format. */
function dfmText(data) {
  if (data.toString('latin1', 0, 4) !== 'TPF0') return null;
  let p = 4;
  const u8 = () => data[p++];
  const short = () => { const n = u8(); const s = data.toString('latin1', p, p + n); p += n; return s; };
  const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
  const value = (ind) => {
    const t = u8();
    switch (t) {
      case 0: return '';
      case 1: { const items = []; while (data[p] !== 0) items.push(value(ind + 2)); p++; return `(\n${items.map((v) => ' '.repeat(ind + 2) + v).join('\n')})`; }
      case 2: { const v = data.readInt8(p); p += 1; return String(v); }
      case 3: { const v = data.readInt16LE(p); p += 2; return String(v); }
      case 4: { const v = data.readInt32LE(p); p += 4; return String(v); }
      case 5: { // 80-bit extended
        const mant = data.readBigUInt64LE(p); const se = data.readUInt16LE(p + 8); p += 10;
        if (!mant) return '0.0';
        const v = Number(mant) / 2 ** 63 * 2 ** ((se & 0x7fff) - 16383) * (se & 0x8000 ? -1 : 1);
        return String(Number(v.toPrecision(15)));
      }
      case 6: return q(short());
      case 7: return short();
      case 8: return 'False';
      case 9: return 'True';
      case 10: { const n = data.readUInt32LE(p); p += 4; const hex = data.toString('hex', p, p + n).toUpperCase(); p += n; return `{\n${(hex.match(/.{1,64}/g) || []).map((l) => ' '.repeat(ind + 2) + l).join('\n')}}`; }
      case 11: { const items = []; for (let s = short(); s; s = short()) items.push(s); return `[${items.join(', ')}]`; }
      case 12: { const n = data.readUInt32LE(p); p += 4; const s = data.toString('latin1', p, p + n); p += n; return q(s); }
      case 13: return 'nil';
      case 14: { // collection
        const items = [];
        while (data[p] !== 0) {
          if (data[p] >= 2 && data[p] <= 4) value(ind); // optional index
          const props = [];
          while (data[p] !== 0) { const name = short(); props.push(`${' '.repeat(ind + 4)}${name} = ${value(ind + 4)}`); }
          p++;
          items.push(`${' '.repeat(ind + 2)}item\n${props.join('\n')}\n${' '.repeat(ind + 2)}end`);
        }
        p++;
        return `<\n${items.join('\n')}>`;
      }
      case 15: { const v = data.readFloatLE(p); p += 4; return String(v); }
      case 16: { const v = Number(data.readBigInt64LE(p)) / 10000; p += 8; return String(v); }
      case 17: { const v = data.readDoubleLE(p); p += 8; return String(v); }
      case 18: { const n = data.readUInt32LE(p); p += 4; const s = data.toString('utf16le', p, p + n * 2); p += n * 2; return q(s); }
      case 19: { const v = data.readBigInt64LE(p); p += 8; return String(v); }
      case 20: { const n = data.readUInt32LE(p); p += 4; const s = data.toString('utf8', p, p + n); p += n; return q(s); }
      case 21: { const v = data.readDoubleLE(p); p += 8; return String(v); }
      default: throw new Error(`unknown DFM value type ${t}`);
    }
  };
  const object = (ind) => {
    let kw = 'object';
    if ((data[p] & 0xf0) === 0xf0) {
      const flags = u8() & 0x0f;
      if (flags & 1) kw = 'inherited';
      if (flags & 4) kw = 'inline';
      if (flags & 2) value(ind); // child position
    }
    const cls = short();
    const name = short();
    const lines = [`${' '.repeat(ind)}${kw} ${name ? `${name}: ` : ''}${cls}`];
    while (data[p] !== 0) { const prop = short(); lines.push(`${' '.repeat(ind + 2)}${prop} = ${value(ind + 2)}`); }
    p++;
    while (data[p] !== 0) lines.push(object(ind + 2));
    p++;
    lines.push(`${' '.repeat(ind)}end`);
    return lines.join('\n');
  };
  return object(0) + '\n';
}

async function extractDelphiForms(resources, outDir, log) {
  let n = 0;
  const names = [];
  for (const r of resources) {
    if (r.data.toString('latin1', 0, 4) !== 'TPF0') continue;
    try {
      const text = dfmText(r.data);
      if (!text) continue;
      const name = typeof r.name === 'string' ? r.name : `form_${r.name}`;
      await writeOut(outDir, `forms/${name}.dfm`, text);
      names.push(name);
      n++;
    } catch { /* damaged form */ }
  }
  log(`Delphi: ${n} forms decoded to .dfm`);
  return { ok: n > 0, note: `**Delphi / C++Builder forms**: ${n} form${n === 1 ? '' : 's'} decoded back to their \`.dfm\` text in \`forms/\` (${names.slice(0, 12).join(', ')}${names.length > 12 ? '…' : ''}). These are the exact UI definitions from the original project: components, properties and the names of their event handlers (e.g. \`OnClick = Button1Click\`), which match the method names in the code.` };
}

module.exports = {
  readAsar, extractElectron, extractNodeSea, extractEmbeddedJs, extractJavaOverlay, extractPyInstaller, readCArchive, unmarshal, dfmText, extractDelphiForms,
};
