// Lua: plain scripts, compiled Lua 5.0-5.4 bytecode (unluac) and LuaJIT bytecode (luajit-decompiler-v2).
// Works on one file or on an archive / folder of them; every file gets a .lua in src/ and a line in README.md.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const AdmZip = require('adm-zip');

const IS_WIN = process.platform === 'win32';
const LUA_EXTS = ['.lua', '.luac', '.luajit', '.ljbc', '.lub', '.lu'];

/** What a Lua file is, from its first bytes: { kind: 'luajit'|'lua'|'source'|'unknown', version } */
function luaKind(head) {
  if (head.length >= 4 && head[0] === 0x1b && head[1] === 0x4c && head[2] === 0x4a) {
    return { kind: 'luajit', version: `LuaJIT bytecode v${head[3]}` };
  }
  if (head.length >= 5 && head[0] === 0x1b && head.subarray(1, 4).toString('latin1') === 'Lua') {
    const v = head[4];
    return { kind: 'lua', version: `Lua ${v >> 4}.${v & 0xf} bytecode`, raw: v };
  }
  if (looksLikeText(head)) return { kind: 'source', version: 'Lua source' };
  return { kind: 'unknown', version: 'unknown / encrypted' };
}

function looksLikeText(buf) {
  const sample = buf.subarray(0, 8000);
  if (!sample.length) return true;
  if (sample.includes(0)) return false;
  let bad = 0;
  for (const b of sample) if (b < 0x09 || (b > 0x0d && b < 0x20 && b !== 0x1b)) bad++;
  return bad / sample.length < 0.02;
}

/** True when a file should go to the Lua engine. */
function isLua(file, head) {
  const k = luaKind(head);
  if (k.kind === 'lua' || k.kind === 'luajit') return true;
  return LUA_EXTS.includes(path.extname(file).toLowerCase());
}

// Common "encryptions" games put on Lua files: worth naming so the user knows why it can't be read.
function encryptionHint(head) {
  const s = head.subarray(0, 64).toString('latin1');
  if (/^XXTEA|^xxtea|^SIGN|^signature/.test(s)) return 'This looks like XXTEA-encrypted Lua (Cocos2d-x): it needs the game\'s key to decrypt before it can be decompiled.';
  if (s.startsWith('LuaQ') || s.startsWith('LuaR') || s.startsWith('LuaS') || s.startsWith('LuaT')) return 'Lua bytecode with its first byte removed or changed (a common protection). Restoring the leading 0x1B byte may make it decompilable.';
  if (/^\x1bLua/.test(s)) return null;
  return 'Not a Lua script and not standard Lua bytecode: it is probably encrypted or compressed by the program that uses it.';
}

function obfuscationHint(text) {
  const lines = text.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  if (/\\27LuaQ|\\27LuaR|\\27LuaS|\\27LuaT|\\x1bLua/i.test(text)) return 'contains embedded Lua bytecode in a string';
  if (/loadstring\s*\(|load\s*\(\s*["'(]/.test(text) && longest > 2000) return 'looks obfuscated (packed code passed to load/loadstring)';
  if (longest > 5000 && lines.length < 20) return 'minified or obfuscated (very long lines)';
  return null;
}

function spawnQuiet(cmd, args, { signal, timeoutMs = 120000, verbatim = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { windowsHide: true, windowsVerbatimArguments: verbatim });
    let out = '';
    const add = (c) => { out = (out + c.toString()).slice(-8000); };
    child.stdout.on('data', add);
    child.stderr.on('data', add);
    const kill = () => {
      if (IS_WIN) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true }).on('error', () => {});
      else child.kill('SIGKILL');
    };
    const timer = setTimeout(kill, timeoutMs);
    signal?.addEventListener('abort', kill, { once: true });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', kill);
      resolve({ code, out });
    });
  });
}

async function readHead(file, n = 8192) {
  const fh = await fsp.open(file, 'r');
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fh.read(buf, 0, n, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

async function listInputs(file, tmp, log) {
  const head = await readHead(file);
  if (head.subarray(0, 2).toString('latin1') !== 'PK') return [{ src: file, rel: path.basename(file) }];
  log('Archive: unpacking the Lua files…');
  const out = [];
  for (const e of new AdmZip(file).getEntries()) {
    if (e.isDirectory) continue;
    const rel = e.entryName.replace(/\\/g, '/');
    const dest = path.resolve(tmp, 'in', rel);
    if (!dest.startsWith(path.resolve(tmp, 'in') + path.sep)) continue;
    const data = e.getData();
    if (!isLua(rel, data.subarray(0, 64))) continue;
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await fsp.writeFile(dest, data);
    out.push({ src: dest, rel });
  }
  if (!out.length) throw new Error('This archive contains no Lua files.');
  return out;
}

/**
 * Decompiles `file` into outDir/src. `tools` provides unluac(log) → { java, classpath }
 * and luajitDecompiler(log) → exe path, downloaded the first time they're needed.
 */
async function decompileLua(tools, file, outDir, log, { signal } = {}) {
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-lua-'));
  const rows = [];
  try {
    const inputs = await listInputs(file, tmp, log);
    const srcDir = path.join(outDir, 'src');
    let i = 0;
    for (const input of inputs) {
      if (signal?.aborted) throw Object.assign(new Error('Cancelled'), { cancelled: true });
      i++;
      const head = await readHead(input.src);
      const kind = luaKind(head);
      const relLua = input.rel.replace(/\.(luac|luajit|ljbc|lub|lu|bytes|txt|out)$/i, '').replace(/(\.lua)?$/i, '.lua');
      const dest = path.join(srcDir, ...relLua.split('/'));
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      if (inputs.length > 1) log(`(${i}/${inputs.length}) ${input.rel}`, { progress: Math.floor((i * 100) / inputs.length), quiet: true });
      const row = { file: input.rel, format: kind.version, result: '', out: path.relative(outDir, dest).split(path.sep).join('/') };

      if (kind.kind === 'source') {
        const text = (await fsp.readFile(input.src, 'utf8')).replace(/^﻿/, '');
        await fsp.writeFile(dest, text);
        const hint = obfuscationHint(text);
        row.result = hint ? `already source; ${hint}` : 'already source (copied)';
      } else if (kind.kind === 'lua') {
        row.result = await runUnluac(tools, input.src, dest, log, signal);
      } else if (kind.kind === 'luajit') {
        row.result = await runLuajit(tools, input.src, dest, tmp, log, signal);
      } else {
        const hint = encryptionHint(head);
        await fsp.writeFile(dest.replace(/\.lua$/, '.txt'), `-- ${input.rel}: ${hint}\n`);
        row.out = row.out.replace(/\.lua$/, '.txt');
        row.result = hint;
      }
      if (inputs.length === 1) log(`${kind.version}: ${row.result}`);
      rows.push(row);
    }
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
  }

  const ok = rows.filter((r) => /decompiled|source/.test(r.result)).length;
  const md = [
    `# ${path.basename(file)}`, '',
    `${rows.length} Lua file${rows.length === 1 ? '' : 's'}, ${ok} readable.`, '',
    '| File | Format | Result | Output |', '|---|---|---|---|',
    ...rows.map((r) => `| ${r.file} | ${r.format} | ${r.result.replace(/\|/g, '\\|')} | ${r.out} |`), '',
    '## Notes', '',
    '- Lua 5.0 to 5.4 bytecode is decompiled with unluac, LuaJIT bytecode with luajit-decompiler-v2.',
    '- Local variable names survive only when the bytecode kept its debug info; otherwise they come back as L0_1, slot1….',
    '- Files that fail usually use a modified Lua VM (custom opcodes or header) or are encrypted. A `.luadis` disassembly is written instead when possible.',
    '- Open the AI assistant to rename variables, explain the script or deobfuscate it.', '',
  ];
  await fsp.writeFile(path.join(outDir, 'README.md'), md.join('\n'));
  if (!ok && rows.every((r) => !/disassembly/.test(r.result))) log('No file could be decompiled — see README.md.', { warn: true });
}

async function runUnluac(tools, src, dest, log, signal) {
  const { java, classpath } = await tools.unluac(log);
  const r = await spawnQuiet(java, ['-cp', classpath, 'unluac.Main', '--output', dest, src], { signal });
  if (r.code === 0 && (await fsp.stat(dest).then((s) => s.size > 0, () => false))) return 'decompiled (unluac)';
  await fsp.rm(dest, { force: true });
  // Still give the user something to read: the bytecode disassembly.
  const dis = dest.replace(/\.lua$/, '.luadis');
  const d = await spawnQuiet(java, ['-cp', classpath, 'unluac.Main', '--disassemble', '--output', dis, src], { signal });
  const why = (r.out.trim().split(/\r?\n/).filter(Boolean).pop() || 'unknown error').slice(0, 200);
  if (d.code === 0) return `could not decompile (${why}); disassembly written`;
  await fsp.rm(dis, { force: true });
  return `could not decompile (${why})`;
}

async function runLuajit(tools, src, dest, tmp, log, signal) {
  const exe = await tools.luajitDecompiler(log);
  // The tool prints to its console window (not stdout) and waits for a key unless it was started from a
  // console, so it runs under cmd.exe. ASCII-only working paths: it uses the ANSI Windows API.
  const work = path.join(tmp, 'lj', String(Date.now()));
  const inDir = path.join(work, 'in');
  const outTmp = path.join(work, 'out');
  await fsp.mkdir(inDir, { recursive: true });
  await fsp.mkdir(outTmp, { recursive: true });
  const input = path.join(inDir, 'input.luac');
  await fsp.copyFile(src, input);
  const cmd = `""${exe}" "${input}" -s -f -o "${outTmp}""`;
  const r = await spawnQuiet(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', cmd], { signal, verbatim: true, timeoutMs: 180000 });
  const produced = path.join(outTmp, 'input.lua');
  if (await fsp.stat(produced).then((s) => s.size > 0, () => false)) {
    await fsp.copyFile(produced, dest);
    return 'decompiled (luajit-decompiler-v2)';
  }
  return `could not decompile${r.code ? ` (exit code ${r.code})` : ''}: the bytecode may be from a modified LuaJIT build`;
}

module.exports = { decompileLua, isLua, luaKind, LUA_EXTS };
