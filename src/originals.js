// Getting back to the *original* source and names, where the program still points to them:
//  - PE debug directory: which PDB a program was built with (CodeView), or a PDB embedded in it
//  - symbol servers: download that PDB (Microsoft for Windows / Microsoft binaries, NuGet for .NET libraries)
//  - portable PDBs (.NET): the exact source files embedded in them, or their Source Link URLs (GitHub, GitLab,
//    Azure DevOps…) from which the exact source is downloaded
//  - Maven Central: the published -sources.jar of a Java library, found through its pom.properties
// Everything here is best effort: a failure just means the decompiled code is all there is.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const zlib = require('zlib');
const AdmZip = require('adm-zip');

const UA = { 'User-Agent': 'DropDecompiler' };
const SYMBOL_SERVERS = {
  microsoft: 'https://msdl.microsoft.com/download/symbols',
  nuget: 'https://symbols.nuget.org/download/symbols',
};
const MAX_SOURCE_FILES = 4000;

async function get(url, signal, timeout = 60000, headers = {}) {
  const res = await fetch(url, { headers: { ...UA, ...headers }, redirect: 'follow', signal: AbortSignal.any([signal || new AbortController().signal, AbortSignal.timeout(timeout)]) });
  if (!res.ok) { res.body?.cancel(); return null; }
  return Buffer.from(await res.arrayBuffer());
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; await fn(items[k], k); }
  }));
}

function safeRel(p) {
  const segs = [];
  for (const s of p.replace(/\\/g, '/').split('/')) {
    if (!s || s === '.') continue;
    if (s === '..') { segs.pop(); continue; }
    segs.push(s.replace(/[<>:"|?*\x00-\x1f]/g, '_').replace(/[. ]+$/, '_').slice(0, 150));
  }
  return segs.join('/');
}

// ---------------------------------------------------------------- PE debug directory

/** { codeView: { guid, age, pdbPath, portable } | null, embeddedPdb: Buffer | null } or null if not a PE file. */
async function readPeDebug(file) {
  const fh = await fsp.open(file, 'r');
  try {
    const at = async (off, len) => {
      const b = Buffer.alloc(len);
      const { bytesRead } = await fh.read(b, 0, len, off);
      return b.subarray(0, bytesRead);
    };
    const dos = await at(0, 64);
    if (dos.length < 64 || dos.readUInt16LE(0) !== 0x5a4d) return null;
    const pe = dos.readUInt32LE(0x3c);
    const hdr = await at(pe, 24 + 240);
    if (hdr.length < 24 + 96 || hdr.readUInt32LE(0) !== 0x4550) return null;
    const nSections = hdr.readUInt16LE(6);
    const optSize = hdr.readUInt16LE(20);
    const magic = hdr.readUInt16LE(24);
    const dd = 24 + (magic === 0x20b ? 112 : 96);
    if (hdr.readUInt32LE(dd - 4) < 7 || hdr.length < dd + 7 * 8) return { codeView: null, embeddedPdb: null };
    const dbgRva = hdr.readUInt32LE(dd + 6 * 8);
    const dbgSize = hdr.readUInt32LE(dd + 6 * 8 + 4);
    if (!dbgRva || !dbgSize) return { codeView: null, embeddedPdb: null };
    const secs = await at(pe + 24 + optSize, nSections * 40);
    const rvaToOff = (rva) => {
      for (let i = 0; i < nSections; i++) {
        const s = i * 40;
        const va = secs.readUInt32LE(s + 12);
        const vs = Math.max(secs.readUInt32LE(s + 8), secs.readUInt32LE(s + 16));
        if (rva >= va && rva < va + vs) return rva - va + secs.readUInt32LE(s + 20);
      }
      return null;
    };
    const off = rvaToOff(dbgRva);
    if (off === null) return { codeView: null, embeddedPdb: null };
    const dir = await at(off, Math.min(dbgSize, 28 * 64));
    let codeView = null;
    let embeddedPdb = null;
    const checksums = [];
    for (let e = 0; e + 28 <= dir.length; e += 28) {
      const minor = dir.readUInt16LE(e + 10);
      const type = dir.readUInt32LE(e + 12);
      const size = dir.readUInt32LE(e + 16);
      const ptr = dir.readUInt32LE(e + 24);
      if (!size || !ptr || size > 64 * 1024 * 1024) continue;
      if (type === 2 && !codeView) {
        const d = await at(ptr, Math.min(size, 4096));
        if (d.subarray(0, 4).toString('latin1') !== 'RSDS') continue;
        const end = d.indexOf(0, 24);
        codeView = { guid: Buffer.from(d.subarray(4, 20)), age: d.readUInt32LE(20), pdbPath: d.toString('utf8', 24, end < 0 ? d.length : end), portable: minor === 0x504d };
      } else if (type === 17 && !embeddedPdb) {
        const d = await at(ptr, size);
        if (d.subarray(0, 4).toString('latin1') === 'MPDB') {
          try { embeddedPdb = zlib.inflateRawSync(d.subarray(8)); } catch { /* damaged */ }
        }
      } else if (type === 19) {
        // PdbChecksum: algorithm name (e.g. "SHA256"), NUL, checksum bytes. NuGet's symbol server requires it.
        const d = await at(ptr, Math.min(size, 256));
        const end = d.indexOf(0);
        if (end > 0) checksums.push(`${d.toString('utf8', 0, end)}:${d.subarray(end + 1).toString('hex').toUpperCase()}`);
      }
    }
    if (codeView) codeView.checksums = checksums;
    return { codeView, embeddedPdb };
  } finally {
    await fh.close();
  }
}

function guidString(g) {
  const h = (n, w) => n.toString(16).toUpperCase().padStart(w, '0');
  return h(g.readUInt32LE(0), 8) + h(g.readUInt16LE(4), 4) + h(g.readUInt16LE(6), 4) + g.subarray(8).toString('hex').toUpperCase();
}

/**
 * Downloads the PDB a program was built with from public symbol servers into `destDir`.
 * Returns the PDB path, or null. Microsoft's server has PDBs for Windows and Microsoft products; NuGet's has
 * portable PDBs of NuGet packages that publish symbols.
 */
async function fetchPdb(codeView, destDir, { signal, log = () => {} } = {}) {
  if (!codeView) return null;
  const name = path.win32.basename(codeView.pdbPath || '');
  if (!/\.pdb$/i.test(name)) return null;
  const key = guidString(codeView.guid) + (codeView.portable ? 'FFFFFFFF' : codeView.age.toString(16).toUpperCase());
  const servers = codeView.portable ? [SYMBOL_SERVERS.nuget, SYMBOL_SERVERS.microsoft] : [SYMBOL_SERVERS.microsoft];
  for (const server of servers) {
    const url = `${server}/${encodeURIComponent(name)}/${key}/${encodeURIComponent(name)}`;
    const headers = codeView.checksums?.length ? { SymbolChecksum: codeView.checksums.join(';') } : {};
    const body = await get(url, signal, 120000, headers).catch(() => null);
    if (!body) continue;
    const head = body.subarray(0, 32).toString('latin1');
    if (!head.startsWith('Microsoft C/C++ MSF 7.00') && !head.startsWith('BSJB')) continue; // e.g. a compressed .pd_
    await fsp.mkdir(destDir, { recursive: true });
    const dest = path.join(destDir, name);
    await fsp.writeFile(dest, body);
    log(`Debug symbols downloaded from ${new URL(server).host}: ${name}`);
    return dest;
  }
  return null;
}

// ---------------------------------------------------------------- portable PDB

const KIND_EMBEDDED_SOURCE = '0E8A571B-6926-466E-B4AD-8AB04611F5FE';
const KIND_SOURCE_LINK = 'CC110556-A091-4D38-9FEC-25AB9A351A6A';
// HasCustomDebugInformation coded index: table of each tag (ECMA-335 + portable PDB spec).
const HCDI_TABLES = [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b, 0x30, 0x32, 0x33, 0x34, 0x35];

function guidText(b) {
  const h = (n, w) => n.toString(16).toUpperCase().padStart(w, '0');
  const tail = b.subarray(8).toString('hex').toUpperCase();
  return `${h(b.readUInt32LE(0), 8)}-${h(b.readUInt16LE(4), 4)}-${h(b.readUInt16LE(6), 4)}-${tail.slice(0, 4)}-${tail.slice(4)}`;
}

/**
 * Reads the documents of a portable PDB, the source text embedded for each (if any) and the Source Link map.
 * Returns { documents: [{ name, text? }], sourceLink } or null if `buf` is not a portable PDB.
 */
function parsePortablePdb(buf) {
  if (buf.length < 32 || buf.readUInt32LE(0) !== 0x424a5342) return null;
  const verLen = buf.readUInt32LE(12);
  let p = 16 + verLen + 2;
  const nStreams = buf.readUInt16LE(p);
  p += 2;
  const streams = {};
  for (let i = 0; i < nStreams; i++) {
    const offset = buf.readUInt32LE(p);
    const size = buf.readUInt32LE(p + 4);
    p += 8;
    const end = buf.indexOf(0, p);
    const name = buf.toString('latin1', p, end);
    p = (end + 4) & ~3;
    streams[name] = buf.subarray(offset, offset + size);
  }
  const tables = streams['#~'];
  const pdb = streams['#Pdb'];
  if (!tables || !pdb) return null;
  const blobs = streams['#Blob'] || Buffer.alloc(0);
  const guids = streams['#GUID'] || Buffer.alloc(0);

  // Row counts: type-system tables come from #Pdb (they live in the assembly), debug tables from #~.
  const rows = new Array(64).fill(0);
  const tsMask = pdb.readBigUInt64LE(24);
  let q = 32;
  for (let t = 0; t < 64; t++) if (tsMask & (1n << BigInt(t))) { rows[t] = pdb.readUInt32LE(q); q += 4; }
  const heapSizes = tables[6];
  const valid = tables.readBigUInt64LE(8);
  q = 24;
  const present = [];
  for (let t = 0; t < 64; t++) if (valid & (1n << BigInt(t))) { rows[t] = tables.readUInt32LE(q); q += 4; present.push(t); }
  const strIdx = heapSizes & 1 ? 4 : 2;
  const guidIdx = heapSizes & 2 ? 4 : 2;
  const blobIdx = heapSizes & 4 ? 4 : 2;
  const idx = (t) => (rows[t] < 65536 ? 2 : 4);
  const hcdi = Math.max(...HCDI_TABLES.map((t) => rows[t])) < (1 << 11) ? 2 : 4;
  const rowSize = {
    0x30: blobIdx + guidIdx + blobIdx + guidIdx, // Document
    0x31: idx(0x30) + blobIdx, // MethodDebugInformation
    0x32: idx(0x06) + idx(0x35) + idx(0x33) + idx(0x34) + 8, // LocalScope
    0x33: 4 + strIdx, // LocalVariable
    0x34: strIdx + blobIdx, // LocalConstant
    0x35: idx(0x35) + blobIdx, // ImportScope
    0x36: idx(0x06) * 2, // StateMachineMethod
    0x37: hcdi + guidIdx + blobIdx, // CustomDebugInformation
  };
  const tableAt = {};
  for (const t of present) {
    if (rowSize[t] === undefined) return null; // unexpected table: not a standalone portable PDB
    tableAt[t] = q;
    q += rows[t] * rowSize[t];
  }
  const rd = (off, size) => (size === 2 ? tables.readUInt16LE(off) : tables.readUInt32LE(off));
  const blob = (i) => {
    if (!i || i >= blobs.length) return Buffer.alloc(0);
    const b0 = blobs[i];
    let len;
    let start;
    if ((b0 & 0x80) === 0) { len = b0; start = i + 1; }
    else if ((b0 & 0xc0) === 0x80) { len = ((b0 & 0x3f) << 8) | blobs[i + 1]; start = i + 2; }
    else { len = ((b0 & 0x1f) << 24) | (blobs[i + 1] << 16) | (blobs[i + 2] << 8) | blobs[i + 3]; start = i + 4; }
    return blobs.subarray(start, start + len);
  };
  const guid = (i) => (i ? guidText(guids.subarray((i - 1) * 16, i * 16)) : '');
  const compressed = (b, o) => {
    const v = b[o];
    if ((v & 0x80) === 0) return [v, 1];
    if ((v & 0xc0) === 0x80) return [((v & 0x3f) << 8) | b[o + 1], 2];
    return [((v & 0x1f) << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3], 4];
  };

  const documents = [];
  for (let r = 0; r < rows[0x30]; r++) {
    const off = tableAt[0x30] + r * rowSize[0x30];
    const nameBlob = blob(rd(off, blobIdx));
    let name = '';
    if (nameBlob.length) {
      const sep = nameBlob[0] ? String.fromCharCode(nameBlob[0]) : '';
      const parts = [];
      for (let o = 1; o < nameBlob.length;) {
        const [partIdx, n] = compressed(nameBlob, o);
        o += n;
        parts.push(blob(partIdx).toString('utf8'));
      }
      name = parts.join(sep);
    }
    documents.push({ name });
  }

  let sourceLink = null;
  for (let r = 0; r < (rows[0x37] || 0); r++) {
    const off = tableAt[0x37] + r * rowSize[0x37];
    const parent = rd(off, hcdi);
    const kind = guid(rd(off + hcdi, guidIdx));
    const value = blob(rd(off + hcdi + guidIdx, blobIdx));
    if (kind === KIND_SOURCE_LINK) {
      try { sourceLink = JSON.parse(value.toString('utf8')); } catch { /* invalid */ }
    } else if (kind === KIND_EMBEDDED_SOURCE && value.length >= 4) {
      const tag = parent & (hcdi === 2 ? 0x1f : 0x1f);
      const row = parent >>> 5;
      if (HCDI_TABLES[tag] !== 0x30 || !documents[row - 1]) continue;
      const format = value.readInt32LE(0);
      try {
        const data = format === 0 ? value.subarray(4) : zlib.inflateRawSync(value.subarray(4));
        documents[row - 1].text = data.toString('utf8').replace(/^﻿/, '');
      } catch { /* damaged */ }
    }
  }
  return { documents, sourceLink };
}

function sourceLinkUrl(map, doc) {
  const docs = map?.documents || {};
  let best = null;
  for (const [key, url] of Object.entries(docs)) {
    if (key.endsWith('*')) {
      const prefix = key.slice(0, -1);
      if (doc.toLowerCase().startsWith(prefix.toLowerCase()) && (!best || prefix.length > best.len)) {
        best = { len: prefix.length, url: url.replace('*', doc.slice(prefix.length).replace(/\\/g, '/')) };
      }
    } else if (key.toLowerCase() === doc.toLowerCase()) return url;
  }
  return best?.url || null;
}

/** Shortest common directory of document paths, to make them relative. */
function commonDir(names) {
  const split = names.map((n) => n.replace(/\\/g, '/').split('/').slice(0, -1));
  if (!split.length) return 0;
  let n = 0;
  while (split.every((s) => s.length > n && s[n].toLowerCase() === split[0][n].toLowerCase())) n++;
  return n;
}

/**
 * Writes the original source files of a .NET assembly into `destDir` (null: only find the PDB): embedded in
 * its PDB, or downloaded through Source Link. Returns { pdb (path or null), embeddedPdb, files, embedded,
 * downloaded, total } — the PDB gives ILSpy the original local variable names.
 */
async function dotnetOriginalSources(dll, destDir, { symbols = true, download = true, workDir, signal, log = () => {} } = {}) {
  const result = { pdb: null, embeddedPdb: false, files: 0, embedded: 0, downloaded: 0, total: 0, sourceLink: false };
  const info = await readPeDebug(dll).catch(() => null);
  if (!info) return result;
  let pdbBuf = info.embeddedPdb;
  result.embeddedPdb = !!pdbBuf;
  if (!pdbBuf) {
    const nextTo = dll.replace(/\.(dll|exe|winmd)$/i, '.pdb');
    const local = await fsp.readFile(nextTo).catch(() => null);
    if (local) { pdbBuf = local; result.pdb = nextTo; }
    else if (symbols && info.codeView && workDir) {
      const got = await fetchPdb(info.codeView, workDir, { signal, log });
      if (got) { result.pdb = got; pdbBuf = await fsp.readFile(got); }
    }
  }
  if (!destDir) return result; // only the PDB was wanted
  const parsed = pdbBuf && parsePortablePdb(pdbBuf);
  if (!parsed) return result;
  const docs = parsed.documents.filter((d) => d.name && /\.(cs|vb|fs|fsi|xaml|resx|razor|cshtml|cpp|c|h)$/i.test(d.name));
  result.total = docs.length;
  result.sourceLink = !!parsed.sourceLink;
  if (!docs.length) return result;
  const depth = commonDir(docs.map((d) => d.name));
  const relOf = (name) => safeRel(name.replace(/\\/g, '/').split('/').slice(depth).join('/').replace(/^[a-z]:/i, ''));
  const write = async (name, text) => {
    const dest = path.join(destDir, ...relOf(name).split('/'));
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await fsp.writeFile(dest, text);
    result.files++;
  };
  for (const d of docs) if (d.text !== undefined) { await write(d.name, d.text); result.embedded++; }
  if (download && parsed.sourceLink) {
    const todo = docs.filter((d) => d.text === undefined).slice(0, MAX_SOURCE_FILES)
      .map((d) => ({ d, url: sourceLinkUrl(parsed.sourceLink, d.name) })).filter((x) => x.url && /^https:\/\//i.test(x.url));
    if (todo.length) log(`Downloading ${todo.length} original source files through Source Link…`);
    await pool(todo, 8, async ({ d, url }) => {
      if (signal?.aborted) return;
      const body = await get(url, signal, 30000).catch(() => null);
      if (body && !body.subarray(0, 200).toString('latin1').includes('<!DOCTYPE html')) { await write(d.name, body); result.downloaded++; }
    });
  }
  return result;
}

// ---------------------------------------------------------------- Java: Maven Central sources

/** The Maven coordinates a jar declares (META-INF/maven/<group>/<artifact>/pom.properties). */
function mavenCoordinates(jarFile) {
  let zip;
  try { zip = new AdmZip(jarFile); } catch { return []; }
  const out = [];
  for (const e of zip.getEntries()) {
    if (!/^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/.test(e.entryName)) continue;
    const props = Object.fromEntries(e.getData().toString('utf8').split(/\r?\n/).filter((l) => l.includes('=') && !l.startsWith('#'))
      .map((l) => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()]));
    if (props.groupId && props.artifactId && props.version) out.push(props);
  }
  return out;
}

/**
 * Extracts the published source jar of a Java library into `destDir`: a <name>-sources.jar next to the input,
 * or the -sources.jar on Maven Central for the coordinates inside the jar.
 * Returns { files, from: [labels] }.
 */
async function javaOriginalSources(jarFile, destDir, { download = true, signal, log = () => {} } = {}) {
  const result = { files: 0, from: [] };
  const extract = async (buf, sub, label) => {
    let zip;
    try { zip = new AdmZip(buf); } catch { return; }
    let n = 0;
    for (const e of zip.getEntries()) {
      if (e.isDirectory || !/\.(java|kt|kts|groovy|scala|clj)$/i.test(e.entryName)) continue;
      const rel = safeRel(e.entryName);
      if (!rel) continue;
      const dest = path.join(destDir, sub, ...rel.split('/'));
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      await fsp.writeFile(dest, e.getData());
      n++;
    }
    if (n) { result.files += n; result.from.push(label); }
  };

  const local = jarFile.replace(/\.jar$/i, '-sources.jar');
  const localBuf = local !== jarFile ? await fsp.readFile(local).catch(() => null) : null;
  if (localBuf) {
    await extract(localBuf, '', path.basename(local));
    log(`Original sources taken from ${path.basename(local)}`);
    return result;
  }
  if (!download) return result;
  const base = path.basename(jarFile).replace(/\.jar$/i, '').toLowerCase();
  const coords = mavenCoordinates(jarFile)
    .sort((a, b) => (base.startsWith(b.artifactId.toLowerCase()) ? 1 : 0) - (base.startsWith(a.artifactId.toLowerCase()) ? 1 : 0))
    .slice(0, 40);
  if (!coords.length) return result;
  log(`Looking for published sources on Maven Central (${coords.length} artifact${coords.length === 1 ? '' : 's'})…`);
  await pool(coords, 4, async (c) => {
    if (signal?.aborted) return;
    const url = `https://repo1.maven.org/maven2/${c.groupId.replace(/\./g, '/')}/${c.artifactId}/${c.version}/${c.artifactId}-${c.version}-sources.jar`;
    const buf = await get(url, signal).catch(() => null);
    if (buf) await extract(buf, coords.length > 1 ? `${c.artifactId}-${c.version}` : '', `${c.groupId}:${c.artifactId}:${c.version}`);
  });
  if (result.files) log(`Original sources downloaded from Maven Central: ${result.files.toLocaleString('en')} files`);
  return result;
}

module.exports = { readPeDebug, fetchPdb, parsePortablePdb, sourceLinkUrl, dotnetOriginalSources, mavenCoordinates, javaOriginalSources, guidString };
