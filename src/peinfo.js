// What a Windows EXE/DLL really is, before decompiling it:
//  - toolchain: the "Rich" header records every compiler/linker build that produced the object files
//    (exact Visual Studio version, how many C / C++ / assembler objects), the PDB path reveals the original
//    project folder and configuration, and signatures identify other compilers (GCC/MinGW, Clang, Delphi, Go…)
//  - runtime: many EXEs are not native code at all (PyInstaller, Electron, Node single-executable apps,
//    Java wrapped in an EXE, AutoIt, installers, packers). Their real code can be extracted instead.
const path = require('path');
const RICH = require('./data/richids.json');

// ---------------------------------------------------------------- PE headers

function parsePE(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return null;
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 24 > buf.length || buf.readUInt32LE(pe) !== 0x4550) return null;
  const machine = buf.readUInt16LE(pe + 4);
  const nSections = buf.readUInt16LE(pe + 6);
  const timestamp = buf.readUInt32LE(pe + 8);
  const optSize = buf.readUInt16LE(pe + 20);
  const characteristics = buf.readUInt16LE(pe + 22);
  const opt = pe + 24;
  const magic = buf.readUInt16LE(opt);
  const is64 = magic === 0x20b;
  const imageBase = is64 ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
  const dd = opt + (is64 ? 112 : 96);
  const dir = (i) => ({ rva: buf.readUInt32LE(dd + i * 8), size: buf.readUInt32LE(dd + i * 8 + 4) });
  const sections = [];
  for (let i = 0; i < nSections; i++) {
    const s = opt + optSize + i * 40;
    if (s + 40 > buf.length) break;
    sections.push({
      name: buf.toString('latin1', s, s + 8).replace(/\0.*$/, ''),
      vsize: buf.readUInt32LE(s + 8), rva: buf.readUInt32LE(s + 12), rawSize: buf.readUInt32LE(s + 16),
      raw: buf.readUInt32LE(s + 20), flags: buf.readUInt32LE(s + 36),
    });
  }
  const end = sections.reduce((m, s) => Math.max(m, s.raw + s.rawSize), 0);
  const rvaToOff = (rva) => {
    for (const s of sections) if (rva >= s.rva && rva < s.rva + Math.max(s.vsize, s.rawSize)) return rva - s.rva + s.raw;
    return -1;
  };
  return {
    machine: { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'ARM64', 0x1c4: 'ARM' }[machine] || `0x${machine.toString(16)}`,
    is64, imageBase, timestamp, dll: (characteristics & 0x2000) !== 0,
    subsystem: { 1: 'native', 2: 'Windows GUI', 3: 'console', 9: 'Windows CE', 10: 'EFI', 16: 'boot' }[buf.readUInt16LE(opt + 68)] || 'other',
    linker: `${buf[opt + 2]}.${buf[opt + 3]}`, sections, overlay: end > 0 && end < buf.length ? { offset: end, size: buf.length - end } : null,
    dir, rvaToOff, peOffset: pe,
  };
}

/** Names of the DLLs a PE imports (lower case), and a sample of imported function names. */
function imports(buf, pe) {
  const out = { dlls: [], functions: new Set() };
  const { rva } = pe.dir(1);
  let p = rva ? pe.rvaToOff(rva) : -1;
  if (p < 0) return out;
  for (let n = 0; n < 512 && p + 20 <= buf.length; n++, p += 20) {
    const nameRva = buf.readUInt32LE(p + 12);
    if (!nameRva) break;
    const o = pe.rvaToOff(nameRva);
    if (o < 0) continue;
    out.dlls.push(buf.toString('latin1', o, buf.indexOf(0, o)).toLowerCase());
    const thunkRva = buf.readUInt32LE(p) || buf.readUInt32LE(p + 16);
    let t = thunkRva ? pe.rvaToOff(thunkRva) : -1;
    for (let k = 0; t >= 0 && k < 4000; k++, t += pe.is64 ? 8 : 4) {
      const v = pe.is64 ? Number(buf.readBigUInt64LE(t)) : buf.readUInt32LE(t);
      if (!v) break;
      if (pe.is64 ? v >= 2 ** 63 : v & 0x80000000) continue; // by ordinal
      const h = pe.rvaToOff(v & 0x7fffffff);
      if (h >= 0 && out.functions.size < 20000) out.functions.add(buf.toString('latin1', h + 2, buf.indexOf(0, h + 2)));
    }
  }
  return out;
}

// ---------------------------------------------------------------- Rich header

/** Entries of the Rich header: [{ prodId, build, count, kind, version }]. */
function richHeader(buf, pe) {
  const limit = Math.min(pe ? pe.peOffset : 0x400, buf.length);
  let rich = -1;
  for (let i = 0x80; i + 8 <= limit; i += 4) if (buf.readUInt32LE(i) === 0x68636952) { rich = i; break; } // "Rich"
  if (rich < 0) return null;
  const key = buf.readUInt32LE(rich + 4);
  let dans = -1;
  for (let i = rich - 8; i >= 0x40; i -= 4) if ((buf.readUInt32LE(i) ^ key) === 0x536e6144) { dans = i; break; } // "DanS"
  if (dans < 0) return null;
  const entries = [];
  for (let i = dans + 16; i + 8 <= rich; i += 8) {
    const id = (buf.readUInt32LE(i) ^ key) >>> 0;
    const count = (buf.readUInt32LE(i + 4) ^ key) >>> 0;
    const prodId = id >>> 16;
    const build = id & 0xffff;
    entries.push({ prodId, build, count, kind: RICH.kinds[prodId] || '???', version: vsVersion(build) });
  }
  return entries;
}

const KNOWN_BUILDS = Object.keys(RICH.builds).map(Number).sort((a, b) => a - b);

/** Visual Studio version of a compiler build number (exact, or the closest known one). */
function vsVersion(build) {
  if (!build) return null;
  if (RICH.builds[build]) return RICH.builds[build];
  let below = null;
  for (const b of KNOWN_BUILDS) if (b <= build) below = b; else break;
  if (below === null) return null;
  const v = /^(VS\d+)(?: v(\d+)\.(\d+))?/.exec(RICH.builds[below]);
  return v ? `${v[1]}${v[2] ? ` v${v[2]}.${v[3]}` : ''} (build ${build})` : null;
}

// ---------------------------------------------------------------- toolchain

// Object kinds of the Rich header. "CIL" is the intermediate format of link-time code generation (/GL),
// not .NET; "LTM" (MSIL) is C++/CLI.
const LANG_KIND = { 'C': 'C', 'C++': 'C++', 'LTC': 'C (LTCG)', 'LT+': 'C++ (LTCG)', 'PGO': 'C (PGO)', 'PG+': 'C++ (PGO)', 'POC': 'C (PGO)', 'PO+': 'C++ (PGO)', 'CIL': 'C (LTCG)', 'CI+': 'C++ (LTCG)', 'LTM': 'C++ (/clr)', 'ASM': 'assembler' };

function ascii(buf, max = 64 * 1024 * 1024) {
  return buf.subarray(0, Math.min(buf.length, max)).toString('latin1');
}

/**
 * Everything known about how the binary was built.
 * { compiler, version, languages: { C, 'C++', assembler }, objects, linker, pdbPath, project, rich, notes[] }
 */
function toolchain(buf, pe, pdbPath, text = ascii(buf)) {
  const out = { compiler: null, version: null, languages: {}, objects: 0, linker: null, pdbPath: pdbPath || null, project: null, notes: [] };
  const rich = richHeader(buf, pe);
  out.rich = rich;
  if (rich && rich.length) {
    out.compiler = 'Microsoft Visual C++';
    const compileUnits = rich.filter((e) => LANG_KIND[e.kind]);
    for (const e of compileUnits) {
      const lang = LANG_KIND[e.kind].replace(/ \(.*\)$/, '');
      out.languages[lang] = (out.languages[lang] || 0) + e.count;
      out.objects += e.count;
    }
    // The compiler that built most of the program's objects (the app's own code, not the runtime).
    const main = [...compileUnits].sort((a, b) => b.count - a.count)[0];
    if (main) out.version = main.version;
    const lnk = rich.find((e) => e.kind === 'LNK');
    if (lnk) out.linker = lnk.version;
    if (rich.some((e) => /^(LTC|LT\+|CIL|CI\+)$/.test(e.kind))) out.notes.push('Built with link-time code generation (/GL /LTCG): functions may be inlined across source files.');
    if (rich.some((e) => /^(PG|PO)/.test(e.kind))) out.notes.push('Built with profile-guided optimization: hot and cold parts of functions may be split.');
    if (rich.some((e) => e.kind === 'LTM')) out.notes.push('Contains C++/CLI (/clr) code: part of it is .NET IL.');
  }

  // The source language, independent of the linker (Rust and others also link with Microsoft's tools).
  out.language = null;
  if (/rust_panic|\/rustc\/[0-9a-f]{40}|\.cargo[\\/]registry|core::panicking/.test(text)) {
    out.language = 'Rust';
    const v = /rustc\/([0-9a-f]{9})/.exec(text);
    if (v) out.languageVersion = `rustc commit ${v[1]}`;
  } else if (/Go build ID: |runtime\.gopanic|go\.buildid/.test(text)) {
    out.language = 'Go';
    const v = /go1\.\d+(\.\d+)?/.exec(text);
    if (v) out.languageVersion = v[0];
  } else if (/@nimFrame|fatal\.nim|nimGC/.test(text)) out.language = 'Nim';
  else if (/zig[\\/]lib[\\/]std/.test(text)) out.language = 'Zig';
  else if (/Embarcadero|SOFTWARE\\Borland\\Delphi|FastMM|System\.SysUtils|@System@TObject/.test(text) || pe.sections.some((s) => /^(CODE|\.itext)$/.test(s.name))) {
    out.language = /C\+\+Builder|bcc(32|64)|__CPPdebugHook/.test(text) ? 'C++ (C++Builder)' : 'Delphi (Object Pascal)';
  } else if (out.languages['C++'] && out.languages.C) out.language = out.languages['C++'] >= out.languages.C ? 'C++ (and C)' : 'C (and C++)';
  else if (out.languages['C++']) out.language = 'C++';
  else if (out.languages.C) out.language = 'C';

  if (out.compiler) {
    // Microsoft linker / compiler (Rich header)
  } else if (/GCC: \(|Mingw-w64 runtime failure|__mingw_|libgcc_s_|_GLOBAL__sub_I_/.test(text)) {
    out.compiler = 'GCC (MinGW-w64)';
    const v = /GCC: \(([^)]*)\) ([\d.]+)/.exec(text);
    if (v) out.version = `GCC ${v[2]} (${v[1]})`;
    out.language ||= /_ZN|__cxa_|std::/.test(text) ? 'C++' : 'C';
  } else if (out.language === 'Go') out.compiler = 'Go toolchain';
  else if (/^Delphi|C\+\+Builder/.test(out.language || '')) out.compiler = 'Embarcadero / Borland';
  else if (/clang version [\d.]+/.test(text) || pdbPath) {
    // A PDB but no Rich header: Microsoft's linker always writes one, LLVM's lld-link does not.
    out.compiler = 'Clang / LLVM (lld-link)';
    const v = /clang version ([\d.]+)/.exec(text);
    if (v) out.version = `Clang ${v[1]}`;
    out.language ||= /\.\?AV|\?\?_7/.test(text) ? 'C++' : null;
  }

  if (pdbPath) {
    // C:\src\MyApp\x64\Release\MyApp.pdb -> project MyApp, x64, Release
    const parts = pdbPath.split(/[\\/]/).filter(Boolean);
    const conf = parts.find((p) => /^(Release|Debug|RelWithDebInfo|MinSizeRel|Retail|Shipping|Development)$/i.test(p));
    const plat = parts.find((p) => /^(x64|x86|Win32|ARM64|amd64|i386)$/i.test(p));
    const stop = parts.findIndex((p) => /^(x64|x86|Win32|ARM64|Release|Debug|bin|obj|out|build|Build|RelWithDebInfo|MinSizeRel|target)$/i.test(p));
    const project = stop > 0 ? parts[stop - 1] : null;
    out.project = { name: project, configuration: conf || null, platform: plat || null, folder: stop > 0 ? parts.slice(0, stop).join('\\') : null };
  }
  return out;
}

// ---------------------------------------------------------------- runtimes, installers, packers

/**
 * What else the EXE contains or is: [{ kind, name, detail, extract }]. `extract` names a handler in
 * wrapped.js that recovers the real code.
 */
function runtimes(buf, pe, imp, resources, file, fs) {
  const text = ascii(buf);
  const found = [];
  const add = (kind, name, detail, extract = null) => found.push({ kind, name, detail, extract });
  const sec = (re) => pe.sections.some((s) => re.test(s.name));
  const dll = (re) => imp.dlls.some((d) => re.test(d));
  const res = (pred) => resources.find(pred);
  const overlay = pe.overlay ? buf.subarray(pe.overlay.offset) : null;

  // Interpreted / bundled languages: the real program is inside.
  if (text.includes('MEI\x0c\x0b\x0a\x0b\x0e') || /_MEIPASS|pyi-runtime-tmpdir|PyInstaller/.test(text)) add('python', 'PyInstaller (Python)', 'The EXE is a Python program packed by PyInstaller: its .pyc modules are inside.', 'pyinstaller');
  else if (res((r) => r.name === 'PYTHONSCRIPT')) add('python', 'py2exe (Python)', 'The EXE is a Python program packed by py2exe.', null);
  else if (/nuitka|__compiled__|NUITKA_ONEFILE/i.test(text)) add('python', 'Nuitka (Python)', 'Python compiled to C by Nuitka: no bytecode to recover; the C was generated from the Python source, and module/function names survive in the strings.');
  if (res((r) => r.name === 'NODE_SEA_BLOB') || /NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:1/.test(text)) add('javascript', 'Node.js single executable app', 'The main JavaScript is embedded in the NODE_SEA_BLOB resource.', 'node-sea');
  else if (sec(/^\.bun$/) || text.includes('---- Bun! ----')) add('javascript', 'Bun compiled executable', 'Bun embeds the JavaScript/TypeScript of the app (bundled) in the executable.', 'bun');
  else if (text.includes('d3n0l4nd')) add('javascript', 'Deno compiled executable', 'Deno embeds the app\'s modules (an eszip archive) at the end of the executable.', 'deno');
  else if (/pkg\/prelude\/bootstrap\.js|PKG_DUMMY_ENTRYPOINT/.test(text)) add('javascript', 'pkg (Node.js)', 'Packed with vercel/pkg: the sources are in a virtual /snapshot file system, usually as V8 bytecode.');
  const besideApp = file && fs && ['app.asar', 'app'].some((n) => fs.existsSync(path.join(path.dirname(file), 'resources', n)));
  if (/electron\.asar|Electron Framework|electron\/js2c/i.test(text) || (pdbName(buf) || '').toLowerCase() === 'electron.exe.pdb' || besideApp) {
    add('javascript', 'Electron app', 'An Electron app: the program is JavaScript in resources/app.asar (or resources/app) next to the EXE.', 'electron');
  }
  if (overlay && overlay.indexOf(Buffer.from('PK\x03\x04', 'latin1')) >= 0 && /META-INF\/MANIFEST\.MF|launch4j|JSmooth|exe4j|jar2exe/i.test(ascii(overlay, 8 * 1024 * 1024) + text.slice(0, 2e6))) {
    add('java', /launch4j/i.test(text) ? 'Launch4j (Java)' : 'Java program wrapped in an EXE', 'The JAR is appended to the EXE: it is decompiled as Java.', 'java-overlay');
  } else if (/launch4j|JSmooth|exe4j/i.test(text)) add('java', 'Java launcher', 'A launcher for a Java program; the JAR is a separate file next to the EXE.');
  if (res((r) => r.name === 'SCRIPT' && r.data.subarray(0, 64).includes('AU3!EA0')) || />>>AUTOIT (SCRIPT|NO CMDEXECUTE)<<</.test(text)) {
    add('autoit', 'AutoIt script', 'A compiled AutoIt script (encrypted in the SCRIPT resource). Tools such as AutoIt-Ripper recover the .au3 source.');
  }
  if (dll(/^msvbvm[56]0\.dll$/)) add('vb6', 'Visual Basic 6', /\bmethcall|ProcCallEngine/.test(text) ? 'Compiled to P-Code: the interpreter runs bytecode (VB Decompiler can rebuild most of the source).' : 'Compiled to native code with the VB6 runtime.');
  if (resources.some((r) => r.data.subarray(0, 4).toString('latin1') === 'TPF0')) add('delphi', 'Delphi / C++Builder forms', 'The UI forms (.dfm) are stored as resources: they are decoded back to text.', 'delphi-forms');
  if (dll(/^qt[56]core/i) || /QObject::|qt_metacast/.test(text)) add('framework', 'Qt', `Qt ${/Qt6/i.test(imp.dlls.join()) ? '6' : /Qt5/i.test(imp.dlls.join()) ? '5' : ''} application: classes with Q_OBJECT keep their names in the meta-object data.`);
  if (dll(/^mfc\d+u?d?\.dll$/) || /\.\?AVCWinApp@@/.test(text)) add('framework', 'MFC', 'Microsoft Foundation Classes application.');
  if (dll(/^unityplayer\.dll$/)) add('framework', 'Unity', 'Unity game launcher: the game code is in GameAssembly.dll (IL2CPP) or Managed\\Assembly-CSharp.dll next to it.');
  if (/UnrealEngine|UE4Game|FEngineLoop/.test(text)) add('framework', 'Unreal Engine', 'Unreal Engine game.');

  // Installers and self-extracting archives: the real programs are inside.
  if (overlay && overlay.subarray(0, 64 * 1024).includes(Buffer.from('NullsoftInst', 'latin1'))) add('installer', 'NSIS installer', 'The files to install are in the NSIS data appended to the EXE (7-Zip can extract them).');
  if (/Inno Setup Setup Data|Inno Setup Messages/.test(text)) add('installer', 'Inno Setup installer', 'The files to install are compressed inside (innoextract can extract them).');
  if (sec(/^\.wixburn$/)) add('installer', 'WiX Burn bundle', 'A WiX bootstrapper: the MSI packages are attached.');
  if (/InstallShield/.test(text) && overlay) add('installer', 'InstallShield installer', 'InstallShield setup with attached data.');
  if (overlay && overlay.subarray(0, 32).includes(Buffer.from('377abcaf271c', 'hex'))) add('installer', '7-Zip self-extracting archive', 'A 7z archive is appended to the EXE.');
  if (overlay && overlay.subarray(0, 32).toString('latin1').startsWith('Rar!')) add('installer', 'WinRAR self-extracting archive', 'A RAR archive is appended to the EXE.');

  // Packers and protectors: the code on disk is not the real code.
  if (sec(/^UPX\d$/)) add('packer', 'UPX', 'Packed with UPX: unpack it with "upx -d" and decompile the result.');
  if (sec(/^\.themida$|^\.winlice/)) add('packer', 'Themida / WinLicense', 'Protected by Themida/WinLicense: code is encrypted and virtualized; static decompilation shows the protector.');
  if (sec(/^\.vmp\d$/)) add('packer', 'VMProtect', 'Protected by VMProtect: parts of the code run in a virtual machine.');
  if (sec(/^\.aspack$|^\.adata$/)) add('packer', 'ASPack', 'Packed with ASPack.');
  if (sec(/^\.enigma\d$/)) add('packer', 'Enigma Protector', 'Protected by Enigma.');
  if (sec(/^\.MPRESS\d$/)) add('packer', 'MPRESS', 'Packed with MPRESS.');
  if (sec(/^pec\d$|^PEC2/)) add('packer', 'PECompact', 'Packed with PECompact.');
  return found;
}

function pdbName(buf) {
  const i = buf.indexOf('RSDS', 0, 'latin1');
  if (i < 0) return null;
  const e = buf.indexOf(0, i + 24);
  return path.win32.basename(buf.toString('latin1', i + 24, e));
}

/** Number of C++ classes with RTTI (MSVC type descriptors ".?AV…@@"). */
function cppClasses(text) {
  const set = new Set();
  for (const m of text.matchAll(/\.\?A[VU]([\w@?$<>]{1,200}?)@@/g)) { set.add(m[1]); if (set.size > 50000) break; }
  return set.size;
}

module.exports = { parsePE, imports, richHeader, vsVersion, toolchain, runtimes, cppClasses, ascii };
