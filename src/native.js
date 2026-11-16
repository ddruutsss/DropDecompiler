// First step for Windows EXE/DLL files: find out what the program really is (toolchain, language, wrapped
// runtime) and extract its real code when it isn't native (Python, JavaScript, Java, Delphi forms).
// Writes TOOLCHAIN.md and tells core.js whether Ghidra is still needed.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const pi = require('./peinfo');
const { readResources } = require('./peres');
const wrapped = require('./wrapped');
const originals = require('./originals');

function run(cmd, args, { input, timeout = 120000, cwd } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { windowsHide: true, cwd });
    let out = '';
    let err = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    const timer = setTimeout(() => child.kill(), timeout);
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, out, err: e.message }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); });
    if (input !== undefined) child.stdin.end(input);
  });
}

/** A Python interpreter of exactly this version (e.g. "3.13"), or null. */
async function findPython(version) {
  const [maj, min] = version.split('.');
  const tag = `${maj}${min}`;
  const candidates = [
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', `Python${tag}`, 'python.exe'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', `Python${tag}`, 'python.exe'),
    `C:\\Python${tag}\\python.exe`,
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  const launcher = path.join(process.env.SystemRoot || 'C:\\Windows', 'py.exe');
  if (fs.existsSync(launcher)) {
    const r = await run(launcher, [`-${version}`, '-c', 'import sys;print(sys.executable)'], { timeout: 20000 });
    const exe = r.out.trim();
    if (r.code === 0 && exe && fs.existsSync(exe)) return exe;
  }
  return null;
}

/**
 * Python decompiler for one .pyc: pycdc (built on demand when Visual Studio + CMake are installed), and
 * otherwise / for what it can't do, the exact structure rebuilt by the Python version that made the bytecode.
 */
function pythonDecompiler(tools, pyver, log) {
  let pycdc;
  let python;
  let warned = false;
  return async (pycPath) => {
    if (pycdc === undefined) pycdc = tools.pycdc ? await tools.pycdc(log).catch((e) => { log(`pycdc is not available: ${e.message.split('\n')[0]}`, { quiet: true }); return null; }) : null;
    if (pycdc) {
      const r = await run(pycdc, [pycPath], { timeout: 60000 });
      if (r.code === 0 && r.out.trim() && !/^\s*$/.test(r.out)) {
        const incomplete = /Unsupported opcode|Decompyle incomplete|WARNING/i.test(r.out + r.err);
        if (!incomplete) return { source: r.out };
      }
    }
    if (python === undefined) {
      python = pyver ? await findPython(pyver) : null;
      if (!python && !warned) { warned = true; log(`Python ${pyver} is not installed: function bodies stay as bytecode in pyc/.`, { quiet: true }); }
    }
    if (!python) return null;
    const out = pycPath.replace(/\.pyc$/, '.structure.py');
    // In the packaged app the script is inside app.asar, which only Electron can read: give Python a copy.
    const script = path.join(os.tmpdir(), 'dropdecompiler-pyc_structure.py');
    const code = await fsp.readFile(path.join(__dirname, 'python', 'pyc_structure.py'));
    if (!(await fsp.readFile(script).catch(() => Buffer.alloc(0))).equals(code)) await fsp.writeFile(script, code);
    const r = await run(python, ['-I', script], { input: JSON.stringify([{ pyc: pycPath, out }]), timeout: 60000 });
    if (r.code === 0 && fs.existsSync(out)) {
      const text = await fsp.readFile(out, 'utf8');
      await fsp.rm(out, { force: true });
      return { source: text, structure: true };
    }
    return null;
  };
}

/**
 * Analyses a PE file before decompiling it.
 * Returns { skipGhidra, cpp, toolchain, findings, lines } and writes TOOLCHAIN.md.
 */
async function analyzeNative(tools, file, outDir, log, opts = {}) {
  const buf = await fsp.readFile(file);
  const pe = pi.parsePE(buf);
  if (!pe) return { skipGhidra: false, cpp: false, lines: [] };
  const dbg = await originals.readPeDebug(file).catch(() => null);
  const text = pi.ascii(buf);
  const tc = pi.toolchain(buf, pe, dbg?.codeView?.pdbPath, text);
  const imp = pi.imports(buf, pe);
  const resources = readResources(buf);
  const findings = pi.runtimes(buf, pe, imp, resources, file, fs);
  const cppClasses = pi.cppClasses(text);

  const lines = ['## Toolchain', ''];
  const row = (k, v) => v && lines.push(`- **${k}:** ${v}`);
  row('Language', tc.language && `${tc.language}${tc.languageVersion ? ` (${tc.languageVersion})` : ''}`);
  row('Compiler', [tc.compiler, tc.version].filter(Boolean).join(', '));
  row('Linker', tc.linker);
  if (tc.objects) row('Object files', `${tc.objects} (${Object.entries(tc.languages).map(([k, v]) => `${v} ${k}`).join(', ')}): about the number of source files compiled into it, the runtime's included`);
  row('Original PDB path', tc.pdbPath && `\`${tc.pdbPath}\``);
  if (tc.project?.name || tc.project?.configuration) row('Original project', [tc.project.name && `**${tc.project.name}**`, tc.project.configuration, tc.project.platform, tc.project.folder && `in \`${tc.project.folder}\``].filter(Boolean).join(', '));
  row('Target', `${pe.machine}, ${pe.subsystem}${pe.dll ? ', DLL' : ''}, built ${pe.timestamp > 0x30000000 && pe.timestamp < 0x7fffffff ? new Date(pe.timestamp * 1000).toISOString().slice(0, 10) : '(reproducible build, no date)'}`);
  if (cppClasses) row('C++ classes with RTTI', cppClasses.toLocaleString('en'));
  for (const n of tc.notes) lines.push(`- ${n}`);
  if (/Visual C\+\+/.test(tc.compiler || '')) {
    const vs = await require('./msvc').findVs().catch(() => null);
    lines.push(`- Matching decompilation: ${vs ? `available (${vs.name || 'Visual Studio'} ${vs.version}). The AI assistant can verify rewritten functions against the original machine code; exact matches are most likely with the same compiler generation as above.` : 'install Visual Studio with the "Desktop development with C++" workload to let the AI assistant verify rewritten functions against the original machine code.'}`);
  }
  lines.push('');

  // Wrapped programs: extract the real code.
  let skipGhidra = false;
  const notes = [];
  for (const f of findings) {
    if (!f.extract) continue;
    let r = null;
    try {
      if (f.extract === 'electron') r = await wrapped.extractElectron(file, outDir, log);
      else if (f.extract === 'node-sea') r = await wrapped.extractNodeSea(resources, outDir, log);
      else if (f.extract === 'bun' || f.extract === 'deno') r = await wrapped.extractEmbeddedJs(buf, pe, f.extract, outDir, log);
      else if (f.extract === 'java-overlay') r = await wrapped.extractJavaOverlay(buf, pe, outDir, log, opts.decompileJar);
      else if (f.extract === 'delphi-forms') r = await wrapped.extractDelphiForms(resources, outDir, log);
      else if (f.extract === 'pyinstaller') {
        const archive = wrapped.readCArchive(buf);
        const v = archive.pyver >= 100 ? `${Math.floor(archive.pyver / 100)}.${archive.pyver % 100}` : `${Math.floor(archive.pyver / 10)}.${archive.pyver % 10}`;
        r = await wrapped.extractPyInstaller(buf, outDir, log, pythonDecompiler(tools, v, log));
      }
    } catch (e) {
      r = { ok: false, note: `${f.name}: extraction failed (${e.message.split('\n')[0]}).` };
    }
    if (r?.note) notes.push(`- ${r.note}`);
    // The EXE is only a launcher for code in another language: decompiling the launcher adds nothing.
    if (r?.ok && ['python', 'javascript', 'java'].includes(f.kind)) skipGhidra = true;
  }
  const other = findings.filter((f) => !f.extract || !notes.length);
  if (findings.length) {
    lines.push('## What this program contains', '');
    lines.push(...notes);
    for (const f of findings.filter((x) => !x.extract)) lines.push(`- **${f.name}**: ${f.detail}`);
    lines.push('');
  }
  if (skipGhidra) lines.push(`The EXE is a launcher (${findings.filter((f) => f.extract).map((f) => f.name).join(', ')}), so its machine code was not decompiled: the program's real code is listed above.`, '');
  await fsp.writeFile(path.join(outDir, 'TOOLCHAIN.md'), ['# How this program was built', '', ...lines].join('\n'));
  if (tc.compiler || tc.language) log(`Built with ${[tc.language, tc.compiler, tc.version].filter(Boolean).join(', ')}${tc.project?.name ? `; original project “${tc.project.name}”` : ''}`);
  for (const f of findings) if (!f.extract) log(`${f.name}: ${f.detail}`, { warn: f.kind === 'packer' });
  return { skipGhidra, cpp: cppClasses > 0 && /Visual C\+\+/.test(tc.compiler || ''), toolchain: tc, findings, lines, other };
}

module.exports = { analyzeNative, findPython, pythonDecompiler };
