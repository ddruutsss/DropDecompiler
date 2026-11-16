// Matching decompilation: proves that rewritten C/C++ is the original source of a function by compiling it
// with Microsoft's compiler and comparing the generated machine code with the original, instruction by
// instruction. Both sides are disassembled by the same tool (dumpbin) and normalized: jumps inside the
// function become offsets from its start, references to other functions and data become "ref". Everything
// else (instructions, registers, immediates, stack offsets) must be identical for an exact match.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const msvc = require('./msvc');
const { parsePE } = require('./peinfo');

const LINE = /^\s+([0-9A-F]{6,16}):\s+(.+?)\s*$/i;
const PREFIXES = new Set(['rep', 'repe', 'repz', 'repne', 'repnz', 'lock', 'notrack', 'bnd', 'xacquire', 'xrelease']);
const BRANCH = /^(j[a-z]+|call|loop[a-z]*|jmp|jrcxz|jecxz)$/;

/** Parses dumpbin /disasm output: { instrs: [{ addr, mnem, ops }], labels: [{ name, index }] }. */
function parseListing(text) {
  const instrs = [];
  const labels = [];
  for (const raw of text.split(/\r?\n/)) {
    const m = LINE.exec(raw);
    if (m) {
      const parts = m[2].split(/\s+/);
      let mnem = parts.shift().toLowerCase();
      while (PREFIXES.has(mnem) && parts.length) mnem += ' ' + parts.shift().toLowerCase();
      instrs.push({ addr: parseInt(m[1], 16), mnem, ops: parts.join(' ') });
      continue;
    }
    const l = /^([^\s].*?):\s*$/.exec(raw);
    if (l && !/^(Dump of file|File Type|Summary)/.test(l[1])) labels.push({ name: l[1], index: instrs.length });
  }
  return { instrs, labels };
}

const ADDR = /^(?:0x)?([0-9A-F]{6,16})h?$/i;

/** Canonical text of each instruction (see the header comment). */
const isPadding = (i) => i.mnem === 'nop' || (i.mnem === 'int' && i.ops.trim() === '3') || i.mnem === 'int3';

function normalize(instrs, start, end, image = null, localLabels = new Map()) {
  // Alignment padding (multi-byte nops, int 3 between functions) depends on where the linker put the
  // function, not on the source: it is left out, and jump targets are counted in instructions, not bytes.
  const kept = instrs.filter((i) => !isPadding(i));
  const indexOf = (t) => { const k = kept.findIndex((i) => i.addr >= t); return k < 0 ? kept.length : k; };
  return kept.map(({ mnem, ops }) => {
    let o = ops.replace(/\bds:/g, '').replace(/\s+/g, ' ').trim();
    if (BRANCH.test(mnem.split(' ').pop())) {
      const target = o.replace(/^(short|near ptr|far ptr)\s+/i, '');
      const a = ADDR.exec(target);
      if (a) {
        const t = parseInt(a[1], 16);
        o = t >= start && t < end ? `@${indexOf(t)}` : '<ext>';
      } else if (localLabels.has(target)) {
        o = `@${indexOf(localLabels.get(target))}`;
      } else if (!/\[|^(r|e)?[a-z]{1,3}\d*[dwb]?$/i.test(target)) {
        o = '<ext>'; // a symbol: another function
      }
    }
    // Memory operands that name data by address or by symbol -> [ref] (offsets inside globals are dropped).
    o = o.replace(/\[([^\]]+)\]/g, (m, inner) => {
      const t = inner.trim();
      if (ADDR.test(t)) return '[ref]';
      if (/^[A-Za-z_$?@.][\w$?@.<>:-]*(\s*[+-]\s*[0-9A-F]+h?)?$/i.test(t) && !/^(r|e)?([abcd]x|[sd]i|[sb]p|ip|\d+[dwb]?)$/i.test(t.split(/\s*[+-]/)[0])) return '[ref]';
      return m;
    });
    // "offset sym" and immediate addresses inside the image (32-bit code) -> ref
    o = o.replace(/\boffset\s+\S+/gi, 'ref');
    if (image) {
      o = o.replace(/\b([0-9A-F]{6,8})h\b/gi, (m, h) => {
        const v = parseInt(h, 16);
        return v >= image.base && v < image.base + image.size ? 'ref' : m;
      });
    }
    return `${mnem} ${o}`.trim().toLowerCase();
  });
}

/** Myers diff of two string arrays: [{ op: '=' | '-' | '+', a, b }]. */
function diff(a, b) {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  const v = new Map([[1, 0]]);
  const trace = [];
  outer: for (let d = 0; d <= max; d++) {
    trace.push(new Map(v));
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && (v.get(k - 1) ?? -1) < (v.get(k + 1) ?? -1)) ? v.get(k + 1) ?? 0 : (v.get(k - 1) ?? 0) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v.set(k, x);
      if (x >= n && y >= m) break outer;
    }
    if (d > 4000) break; // very different: stop early (score stays low)
  }
  // Backtrack
  const ops = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0 && (x > 0 || y > 0); d--) {
    const vv = trace[d];
    const k = x - y;
    const prevK = k === -d || (k !== d && (vv.get(k - 1) ?? -1) < (vv.get(k + 1) ?? -1)) ? k + 1 : k - 1;
    const prevX = vv.get(prevK) ?? 0;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) { ops.push({ op: '=', a: a[x - 1], b: b[y - 1] }); x--; y--; }
    if (d > 0) {
      if (x === prevX) { ops.push({ op: '+', b: b[y - 1] }); y--; } else { ops.push({ op: '-', a: a[x - 1] }); x--; }
    }
  }
  while (x > 0 && y > 0) { ops.push({ op: '=', a: a[x - 1], b: b[y - 1] }); x--; y--; }
  while (x > 0) { ops.push({ op: '-', a: a[--x] }); }
  while (y > 0) { ops.push({ op: '+', b: b[--y] }); }
  return ops.reverse();
}

function score(ops, n, m) {
  const same = ops.filter((o) => o.op === '=').length;
  return n + m ? (2 * same) / (n + m) : 1;
}

/** Readable diff: the differing parts with a little context. */
function diffText(ops, context = 2, maxLines = 80) {
  const keep = new Set();
  ops.forEach((o, i) => { if (o.op !== '=') for (let k = i - context; k <= i + context; k++) keep.add(k); });
  const lines = [];
  let last = -1;
  for (let i = 0; i < ops.length && lines.length < maxLines; i++) {
    if (!keep.has(i)) continue;
    if (last >= 0 && i > last + 1) lines.push('   …');
    const o = ops[i];
    lines.push(o.op === '=' ? `   ${o.a}` : o.op === '-' ? `-  ${o.a}      (original)` : `+  ${o.b}      (yours)`);
    last = i;
  }
  if (lines.length >= maxLines) lines.push('   … more differences');
  return lines.join('\n');
}

// ---------------------------------------------------------------- original and candidate code

const originalCache = new Map();

/** The original function's normalized instructions (va = virtual address, size in bytes). */
async function originalFunction(binary, va, size) {
  const key = `${binary}|${va}|${size}`;
  if (originalCache.has(key)) return originalCache.get(key);
  const head = Buffer.alloc(4096);
  const fh = await fsp.open(binary, 'r');
  await fh.read(head, 0, 4096, 0);
  await fh.close();
  const pe = parsePE(head);
  if (!pe) throw new Error('Matching works on Windows EXE/DLL files (built with Microsoft C/C++).');
  const arch = pe.machine === 'x86' ? 'x86' : pe.machine === 'ARM64' ? 'arm64' : 'x64';
  const r = await msvc.tool('dumpbin', ['/nologo', '/disasm:nobytes', `/range:0x${va.toString(16)},0x${(va + size - 1).toString(16)}`, binary], { arch });
  const { instrs } = parseListing(r.out);
  const lastSection = pe.sections[pe.sections.length - 1];
  const image = { base: pe.imageBase, size: lastSection ? lastSection.rva + lastSection.vsize : 0x10000000 };
  const res = { arch, image, instrs, norm: normalize(instrs.filter((i) => i.addr >= va && i.addr < va + size), va, va + size, image) };
  if (!res.norm.length) throw new Error(`No instructions at 0x${va.toString(16)} in ${path.basename(binary)}`);
  originalCache.set(key, res);
  return res;
}

/** Compiles code and returns the normalized instructions of `name` (or of the biggest function). */
async function compileFunction(code, { arch = 'x64', flags = '/O2', lang = 'c', name = null, image = null } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-match-'));
  try {
    const src = path.join(dir, `candidate.${lang === 'cpp' ? 'cpp' : 'c'}`);
    await fsp.writeFile(src, code);
    const c = await msvc.tool('cl', ['/nologo', '/c', ...flags.split(/\s+/).filter(Boolean), '/Gy', '/w', src, `/Fo${path.join(dir, 'candidate.obj')}`], { arch, cwd: dir });
    if (c.code !== 0) return { errors: c.out.split(/\r?\n/).filter((l) => /error|fatal/i.test(l)).slice(0, 25).join('\n').replace(new RegExp(dir.replace(/\\/g, '\\\\'), 'gi'), '') || c.out.slice(0, 2000) };
    const d = await msvc.tool('dumpbin', ['/nologo', '/disasm:nobytes', path.join(dir, 'candidate.obj')], { arch, cwd: dir });
    const { instrs, labels } = parseListing(d.out);
    const funcs = labels.filter((l) => !l.name.startsWith('$')).map((l, i, all) => {
      const next = all[i + 1] ? all[i + 1].index : instrs.length;
      return { name: l.name, body: instrs.slice(l.index, next) };
    }).filter((f) => f.body.length);
    if (!funcs.length) return { errors: 'The code compiled but contains no function.' };
    const pick = (name && funcs.find((f) => f.name === name || f.name.includes(`?${name}@`) || f.name.replace(/^_/, '').replace(/@\d+$/, '') === name))
      || funcs.sort((x, y) => y.body.length - x.body.length)[0];
    const start = pick.body[0].addr;
    const end = pick.body[pick.body.length - 1].addr + 16;
    // $LN labels inside the function (jump targets written as names)
    const local = new Map();
    for (const l of labels.filter((x) => x.name.startsWith('$'))) if (instrs[l.index]) local.set(l.name, instrs[l.index].addr);
    return { function: pick.name, norm: normalize(pick.body, start, end, image, local), others: funcs.map((f) => f.name) };
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

const FLAG_SETS = ['/O2', '/O2 /GS-', '/O1', '/O1 /GS-', '/Ox /GS-', '/Od', '/Od /GS-'];

/**
 * Compiles `code` and compares the function with the original at `va` (size bytes) in `binary`.
 * Tries the usual optimization settings unless `flags` is given. Returns
 * { exact, score, flags, function, originalCount, yoursCount, diff, errors }.
 */
async function compare({ binary, va, size, code, lang, flags, name }) {
  const orig = await originalFunction(binary, va, size);
  const sets = flags ? [flags] : FLAG_SETS;
  let best = null;
  let lastErrors = null;
  for (const f of sets) {
    const c = await compileFunction(code, { arch: orig.arch, flags: f, lang, name, image: orig.image });
    if (c.errors) { lastErrors = c.errors; if (flags || !best) continue; else continue; }
    const ops = diff(orig.norm, c.norm);
    const s = score(ops, orig.norm.length, c.norm.length);
    if (!best || s > best.score) best = { score: s, flags: f, ops, c };
    if (s === 1) break;
  }
  if (!best) return { exact: false, score: 0, errors: lastErrors || 'compilation failed' };
  const exact = best.score === 1 && orig.norm.length === best.c.norm.length;
  return {
    exact, score: best.score, flags: best.flags, function: best.c.function,
    originalCount: orig.norm.length, yoursCount: best.c.norm.length,
    diff: exact ? '' : diffText(best.ops),
  };
}

/** Finds a function in a Ghidra output folder's functions.txt by address, name or file. */
async function findFunction(root, query) {
  for (const list of ['functions.txt', path.join('code', 'functions.txt')]) {
    let text;
    try { text = await fsp.readFile(path.join(root, list), 'utf8'); } catch { continue; }
    const base = path.dirname(list) === '.' ? '' : path.dirname(list).replace(/\\/g, '/') + '/';
    const q = String(query).trim().replace(/^0x/i, '').toLowerCase();
    for (const line of text.split(/\r?\n/)) {
      const m = /^([0-9a-f]+)\s+(\d+)\s+(.+?)\s+->\s+(\S+)$/i.exec(line.trim());
      if (!m) continue;
      const [, addr, size, name, file] = m;
      const cleanName = name.replace(/\s+\*$/, '');
      if (addr.toLowerCase() === q.padStart(addr.length, '0') || cleanName.toLowerCase() === q || (base + file).toLowerCase() === q.replace(/\\/g, '/') || file.toLowerCase() === q.replace(/\\/g, '/')) {
        return { va: parseInt(addr, 16), size: Number(size), name: cleanName, file: base + file };
      }
    }
  }
  return null;
}

module.exports = { compare, compileFunction, originalFunction, findFunction, parseListing, normalize, diff, score, diffText, FLAG_SETS };
