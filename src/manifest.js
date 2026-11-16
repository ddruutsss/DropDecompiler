// .manifest files:
//  - Windows application / assembly manifests (XML, often UTF-16): pretty-printed, with a plain-language summary
//    (execution level, DPI awareness, supported Windows versions, dependencies…).
//  - Steam depot manifests (binary protobuf, sometimes zipped): the list of files, sizes and hashes.
//  - Anything else that is text (Unity, ClickOnce, YAML/JSON manifests…): copied as readable text.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

// ---------------------------------------------------------------- text / XML

function decodeText(buf) {
  if (buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le');
  if (buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return swapped.toString('utf16le');
  }
  // UTF-16LE without BOM: every other byte is zero.
  if (buf.length > 8 && buf[1] === 0 && buf[3] === 0 && buf[0] !== 0) return buf.toString('utf16le');
  return buf.toString('utf8').replace(/^﻿/, '');
}

function isTextual(buf) {
  const text = decodeText(buf.subarray(0, 16000));
  if (!text.length) return true;
  let bad = 0;
  for (const ch of text) {
    const c = ch.charCodeAt(0);
    if (c === 0 || (c < 0x20 && c !== 9 && c !== 10 && c !== 13) || c === 0xfffd) bad++;
  }
  return bad / text.length < 0.02;
}

/** Re-indents XML (keeps text, comments and CDATA as they are). */
function prettyXml(xml) {
  const tokens = xml.replace(/>\s+</g, '><').trim().match(/<!\[CDATA\[[\s\S]*?\]\]>|<!--[\s\S]*?-->|<[^>]+>|[^<]+/g) || [];
  const out = [];
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const pad = '  '.repeat(depth);
    if (/^<\//.test(t)) {
      depth = Math.max(0, depth - 1);
      out.push('  '.repeat(depth) + t);
    } else if (/^<[?!]/.test(t) || /\/>$/.test(t)) {
      out.push(pad + t);
    } else if (/^</.test(t)) {
      // <tag>text</tag> stays on one line
      if (tokens[i + 1] && !/^</.test(tokens[i + 1]) && tokens[i + 2] && /^<\//.test(tokens[i + 2])) {
        out.push(pad + t + tokens[i + 1].trim() + tokens[i + 2]);
        i += 2;
      } else {
        out.push(pad + t);
        depth++;
      }
    } else if (t.trim()) {
      out.push(pad + t.trim());
    }
  }
  return out.join('\n') + '\n';
}

const OS_GUIDS = {
  '{e2011457-1546-43c5-a5fe-008deee3d3f0}': 'Windows Vista',
  '{35138b9a-5d96-4fbd-8e2d-a2440225f93a}': 'Windows 7',
  '{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}': 'Windows 8',
  '{1f676c76-80e1-4239-95bb-83d0f6d0da78}': 'Windows 8.1',
  '{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}': 'Windows 10 / 11',
};

function attrs(tag) {
  const o = {};
  for (const m of tag.matchAll(/([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)')/g)) o[m[1]] = m[3] ?? m[4];
  return o;
}

function windowsManifestSummary(xml) {
  const lines = [];
  const tagsOf = (name) => [...xml.matchAll(new RegExp(`<(?:\\w+:)?${name}\\b[^>]*>`, 'gi'))].map((m) => attrs(m[0]));
  const textOf = (name) => (xml.match(new RegExp(`<(?:\\w+:)?${name}\\b[^>]*>([^<]*)<`, 'i')) || [])[1]?.trim();

  const ids = tagsOf('assemblyIdentity');
  if (ids[0]) {
    const a = ids[0];
    lines.push(`- **Identity:** ${a.name || '?'}${a.version ? ` version ${a.version}` : ''}${a.processorArchitecture ? ` (${a.processorArchitecture})` : ''}${a.type ? `, type ${a.type}` : ''}`);
  }
  const desc = textOf('description');
  if (desc) lines.push(`- **Description:** ${desc}`);
  const level = tagsOf('requestedExecutionLevel')[0];
  if (level) {
    const meaning = { asInvoker: 'runs with the rights of the user who starts it', highestAvailable: 'asks for the highest rights the user has', requireAdministrator: 'always asks for administrator rights (UAC prompt)' };
    lines.push(`- **Execution level:** \`${level.level}\` — ${meaning[level.level] || 'custom'}${level.uiAccess === 'true' ? '; uiAccess (can drive other apps\' UI)' : ''}`);
  }
  const dpi = textOf('dpiAwareness') || textOf('dpiAware');
  if (dpi) lines.push(`- **DPI awareness:** ${dpi}`);
  const lpa = textOf('longPathAware');
  if (lpa) lines.push(`- **Long paths (>260 chars):** ${lpa}`);
  const heap = textOf('heapType');
  if (heap) lines.push(`- **Heap type:** ${heap}`);
  const cp = textOf('activeCodePage');
  if (cp) lines.push(`- **Active code page:** ${cp}`);
  const os = tagsOf('supportedOS').map((a) => OS_GUIDS[(a.Id || a.id || '').toLowerCase()] || a.Id).filter(Boolean);
  if (os.length) lines.push(`- **Supported Windows versions declared:** ${os.join(', ')}`);
  const deps = ids.slice(1).map((a) => `${a.name}${a.version ? ` ${a.version}` : ''}`);
  if (deps.length) lines.push(`- **Depends on:** ${deps.join('; ')}${deps.some((d) => /Common-Controls/i.test(d)) ? ' (Common-Controls 6 = modern visual styles)' : ''}`);
  const files = tagsOf('file').map((a) => a.name).filter(Boolean);
  if (files.length) lines.push(`- **Files:** ${files.slice(0, 50).join(', ')}${files.length > 50 ? ` … ${files.length - 50} more` : ''}`);
  const com = tagsOf('comClass').length;
  if (com) lines.push(`- **COM classes registered (registration-free COM):** ${com}`);
  return lines;
}

// ---------------------------------------------------------------- Steam depot manifest (protobuf)

const STEAM = { payload: 0x71f617d0, metadata: 0x1f4812be, signature: 0x1b81b817, end: 0x32c415ab };
const FILE_FLAGS = { 1: 'user config', 2: 'versioned config', 4: 'encrypted', 8: 'read-only', 16: 'hidden', 32: 'executable', 64: 'directory', 128: 'custom executable', 256: 'install script', 512: 'symlink' };

/** Minimal protobuf reader: returns [{ field, wire, value }] (value is a BigInt for varints, a Buffer for bytes). */
function protoFields(buf) {
  const out = [];
  let p = 0;
  const varint = () => {
    let v = 0n;
    let shift = 0n;
    for (;;) {
      if (p >= buf.length) throw new Error('truncated varint');
      const b = buf[p++];
      v |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) return v;
      shift += 7n;
    }
  };
  while (p < buf.length) {
    const key = Number(varint());
    const field = key >> 3;
    const wire = key & 7;
    let value;
    if (wire === 0) value = varint();
    else if (wire === 1) { value = buf.readBigUInt64LE(p); p += 8; }
    else if (wire === 2) { const len = Number(varint()); value = buf.subarray(p, p + len); p += len; }
    else if (wire === 5) { value = BigInt(buf.readUInt32LE(p)); p += 4; }
    else throw new Error('unsupported wire type ' + wire);
    out.push({ field, wire, value });
  }
  return out;
}

function parseSteamManifest(buf) {
  let p = 0;
  let payload = null;
  let metadata = null;
  let signed = false;
  while (p + 4 <= buf.length) {
    const magic = buf.readUInt32LE(p);
    p += 4;
    if (magic === STEAM.end) break;
    if (![STEAM.payload, STEAM.metadata, STEAM.signature].includes(magic)) throw new Error('unknown section');
    const len = buf.readUInt32LE(p);
    p += 4;
    const body = buf.subarray(p, p + len);
    p += len;
    if (magic === STEAM.payload) payload = body;
    else if (magic === STEAM.metadata) metadata = body;
    else signed = true;
  }
  if (!payload) throw new Error('no file list');

  const meta = {};
  if (metadata) {
    for (const f of protoFields(metadata)) {
      if (f.field === 1) meta.depotId = Number(f.value);
      else if (f.field === 2) meta.manifestId = f.value.toString();
      else if (f.field === 3) meta.created = new Date(Number(f.value) * 1000);
      else if (f.field === 4) meta.encryptedNames = f.value !== 0n;
      else if (f.field === 5) meta.sizeOriginal = Number(f.value);
      else if (f.field === 6) meta.sizeCompressed = Number(f.value);
      else if (f.field === 7) meta.uniqueChunks = Number(f.value);
    }
  }
  const files = [];
  for (const m of protoFields(payload)) {
    if (m.field !== 1 || m.wire !== 2) continue;
    const f = { name: '', size: 0, flags: 0, sha: '', chunks: 0, link: '' };
    for (const x of protoFields(m.value)) {
      if (x.field === 1) f.name = x.value.toString('utf8');
      else if (x.field === 2) f.size = Number(x.value);
      else if (x.field === 3) f.flags = Number(x.value);
      else if (x.field === 5) f.sha = x.value.toString('hex');
      else if (x.field === 6) f.chunks++;
      else if (x.field === 7) f.link = x.value.toString('utf8');
    }
    files.push(f);
  }
  return { meta, files, signed };
}

function fmtBytes(n) {
  if (n >= 2 ** 30) return (n / 2 ** 30).toFixed(2) + ' GB';
  if (n >= 2 ** 20) return (n / 2 ** 20).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}

// ---- depot keys: file names in a depot manifest can be encrypted with the depot's AES-256 key.

/** Decrypts one encrypted file name (Steam: Base64 of [IV encrypted with AES-ECB][name in AES-CBC, PKCS7]). */
function decryptSteamName(b64, key) {
  const data = Buffer.from(b64.replace(/\s+/g, ''), 'base64');
  if (data.length < 32 || data.length % 16) throw new Error('not an encrypted name');
  const ecb = crypto.createDecipheriv('aes-256-ecb', key, null);
  ecb.setAutoPadding(false);
  const iv = Buffer.concat([ecb.update(data.subarray(0, 16)), ecb.final()]);
  const cbc = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cbc.update(data.subarray(16)), cbc.final()]).toString('utf8').replace(/\0+$/, '');
}

const KEY_FILE = /\.(lua|vdf|txt|key|json|cfg|ini|st)$/i;
const KEY_PATTERNS = [
  /addappid\s*\(\s*(\d+)\s*,\s*\d+\s*,\s*["']([0-9a-f]{64})["']/gi, // Lua: addappid(depot, flag, "key")
  /"(\d+)"\s*\{\s*"DecryptionKey"\s*"([0-9a-f]{64})"/gi, // Steam config.vdf
  /^\s*(\d+)\s*[;:=,\s]\s*"?([0-9a-f]{64})"?\s*$/gim, // depot;key per line
];

/** Depot keys found in text files next to the manifest: Map depotId -> { key, source }. */
async function findDepotKeys(dir) {
  const keys = new Map();
  let names = [];
  try { names = (await fsp.readdir(dir)).filter((n) => KEY_FILE.test(n)).slice(0, 300); } catch { return keys; }
  for (const name of names) {
    const full = path.join(dir, name);
    const st = await fsp.stat(full).catch(() => null);
    if (!st || !st.isFile() || st.size > 4 * 1024 * 1024) continue;
    const text = await fsp.readFile(full, 'utf8').catch(() => '');
    for (const re of KEY_PATTERNS) {
      for (const m of text.matchAll(re)) if (!keys.has(Number(m[1]))) keys.set(Number(m[1]), { key: Buffer.from(m[2], 'hex'), source: name });
    }
    // A file holding only a key, named after the depot (e.g. 1234561.key)
    const only = /^\s*([0-9a-f]{64})\s*$/i.exec(text);
    const id = /(\d{3,})/.exec(name);
    if (only && id && !keys.has(Number(id[1]))) keys.set(Number(id[1]), { key: Buffer.from(only[1], 'hex'), source: name });
  }
  return keys;
}

/** Decrypts every name in place. Returns false (and changes nothing) if the key is wrong. */
function decryptNames(files, key) {
  const out = [];
  for (const f of files) {
    try {
      const name = decryptSteamName(f.name, key);
      if (/[\x00-\x08\x0e-\x1f]/.test(name)) return false;
      let link = f.link;
      if (link) { try { link = decryptSteamName(link, key); } catch { /* stored in clear */ } }
      out.push({ name, link });
    } catch { return false; }
  }
  files.forEach((f, i) => { f.name = out[i].name; f.link = out[i].link; });
  return true;
}

function isSteamManifest(buf) {
  return buf.length >= 8 && buf.readUInt32LE(0) === STEAM.payload;
}

/** The raw Steam manifest from a file that may be zipped (as downloaded from Steam's CDN). */
function unwrapSteam(buf) {
  if (isSteamManifest(buf)) return buf;
  if (buf.subarray(0, 2).toString('latin1') === 'PK') {
    try {
      for (const e of new AdmZip(buf).getEntries()) {
        const data = e.getData();
        if (isSteamManifest(data)) return data;
      }
    } catch { /* not a zip */ }
  }
  return null;
}

async function writeSteam(file, steam, outDir, log) {
  const { meta, files, signed } = steam;
  // Encrypted names: use the depot key if one sits next to the manifest (Steam's config.vdf, a .lua with
  // addappid(depot, 1, "key"), or a text file with "depot;key").
  let keyNote = null;
  if (meta.encryptedNames) {
    const keys = await findDepotKeys(path.dirname(file));
    const found = keys.get(meta.depotId);
    if (found && decryptNames(files, found.key)) {
      meta.encryptedNames = false;
      keyNote = `- **File names decrypted** with the depot key from \`${found.source}\`.`;
      log(`File names decrypted with the depot key from ${found.source}`);
    } else if (found) {
      keyNote = `- **The depot key in \`${found.source}\` does not decrypt these names** (wrong key for depot ${meta.depotId}). They are shown as stored.`;
      log(`The depot key in ${found.source} does not match this manifest`, { warn: true });
    } else {
      keyNote = `- **File names are encrypted** with the depot key. To read them, put the key for depot ${meta.depotId} next to the manifest (Steam's \`config.vdf\`, a \`.lua\` with \`addappid(${meta.depotId}, 1, "<key>")\`, or a \`.txt\` with \`${meta.depotId};<64 hex characters>\`) and drop the manifest again.`;
      log('File names are encrypted: no depot key found next to the manifest', { warn: true });
    }
  }
  const dirs = files.filter((f) => f.flags & 64);
  const real = files.filter((f) => !(f.flags & 64));
  const total = real.reduce((s, f) => s + f.size, 0);
  const sorted = [...files].sort((a, b) => a.name.localeCompare(b.name));
  const flagText = (fl) => Object.entries(FILE_FLAGS).filter(([b]) => fl & Number(b)).map(([, n]) => n).join(', ');

  const listing = sorted.map((f) => (f.flags & 64 ? `${f.name.replace(/\\/g, '/')}/` : `${f.name.replace(/\\/g, '/')}    ${fmtBytes(f.size)}${f.link ? ` -> ${f.link}` : ''}`));
  await fsp.writeFile(path.join(outDir, 'files.txt'), listing.join('\n') + '\n');
  const csv = ['path,size,flags,sha1,chunks', ...sorted.map((f) => `"${f.name.replace(/"/g, '""')}",${f.size},"${flagText(f.flags)}",${f.sha},${f.chunks}`)];
  await fsp.writeFile(path.join(outDir, 'files.csv'), csv.join('\n') + '\n');

  const biggest = [...real].sort((a, b) => b.size - a.size).slice(0, 15);
  const exes = real.filter((f) => (f.flags & 32) || /\.(exe|dll|so|dylib)$/i.test(f.name)).map((f) => f.name);
  const md = [
    `# ${path.basename(file)}`, '',
    'Steam depot manifest: the list of files of one depot (one part of a game or app) at one version.', '',
    meta.depotId ? `- **Depot:** ${meta.depotId}` : null,
    meta.manifestId ? `- **Manifest ID:** ${meta.manifestId}` : null,
    meta.created ? `- **Created:** ${meta.created.toISOString().replace('T', ' ').slice(0, 19)} UTC` : null,
    `- **Files:** ${real.length.toLocaleString('en')} in ${dirs.length.toLocaleString('en')} folders, ${fmtBytes(total)}`,
    meta.sizeCompressed ? `- **Download size:** ${fmtBytes(meta.sizeCompressed)} (${(meta.uniqueChunks || 0).toLocaleString('en')} chunks)` : null,
    `- **Signed:** ${signed ? 'yes' : 'no'}`,
    keyNote,
    '', '## Biggest files', '', ...biggest.map((f) => `- ${f.name} — ${fmtBytes(f.size)}`),
    exes.length ? ['', '## Programs and libraries', '', ...exes.slice(0, 100).map((n) => `- ${n}`)] : [],
    '', 'Full list: `files.txt` (tree with sizes) and `files.csv` (sizes, flags, SHA-1, chunk counts).',
    'A manifest only describes the files; it does not contain them.', '',
  ].flat().filter((l) => l !== null);
  await fsp.writeFile(path.join(outDir, 'README.md'), md.join('\n'));
  log(`Steam depot manifest: ${real.length.toLocaleString('en')} files, ${fmtBytes(total)}`);
}

// ---------------------------------------------------------------- entry points

/** True when `file` is something the manifest engine handles. */
function isManifest(file, head) {
  if (path.extname(file).toLowerCase() === '.manifest') return true;
  return isSteamManifest(head);
}

async function decompileManifest(_tools, file, outDir, log) {
  const buf = await fsp.readFile(file);
  const steamBuf = unwrapSteam(buf);
  if (steamBuf) {
    try {
      return await writeSteam(file, parseSteamManifest(steamBuf), outDir, log);
    } catch (e) {
      log('Steam manifest could not be fully read: ' + e.message, { warn: true });
    }
  }

  if (!isTextual(buf)) {
    // Unknown binary manifest: hand over to the generic analyser.
    const generic = require('./generic');
    log('Binary manifest of an unknown format: analysing it as a generic file.');
    return generic.decompileGeneric(_tools, file, outDir, log);
  }

  const text = decodeText(buf);
  const base = path.basename(file);
  const isXml = /^\s*<(\?xml|assembly|\w+:assembly|asmv\d|Project|manifest)/i.test(text) || /^\s*</.test(text);
  // The copy is saved as UTF-8, so its XML declaration must say so.
  const pretty = isXml ? prettyXml(text).replace(/^(<\?xml[^>]*encoding=["'])[^"']+/i, '$1UTF-8') : text;
  const outName = isXml && !/\.xml$/i.test(base) ? base + '.xml' : base;
  await fsp.writeFile(path.join(outDir, outName), pretty);

  const md = [`# ${base}`, ''];
  if (/<(\w+:)?assembly\b/i.test(text)) {
    md.push('Windows application / assembly manifest (side-by-side manifest). Windows reads it when the program starts.', '', ...windowsManifestSummary(text));
  } else if (/ManifestFileVersion|AssetBundleManifest|CRC:\s*\d+/.test(text)) {
    md.push('Unity AssetBundle manifest: lists the assets in a bundle and the bundles it depends on.');
  } else if (/<manifest\b[^>]*android/i.test(text)) {
    md.push('Android manifest (text form).');
  } else {
    md.push('Text manifest.');
  }
  md.push('', `Readable copy: \`${outName}\`${isXml ? ' (re-indented XML, converted to UTF-8)' : ''}.`, '');
  await fsp.writeFile(path.join(outDir, 'README.md'), md.join('\n'));
  log(isXml ? 'Manifest decoded and re-indented' : 'Manifest copied as text');
}

module.exports = { decompileManifest, isManifest, prettyXml, decodeText, isTextual, parseSteamManifest, decryptSteamName, findDepotKeys };
