// Rebuilds a decompiled JAR into a complete, working JAR.
//
// Every decompiled class is recompiled with javac against the original program (and the libraries it ships).
// A class whose source doesn't compile, or whose recompiled version lost a field or method the rest of the
// program may use, is taken from the original JAR instead. The result always contains the whole program:
// as much as possible rebuilt from the editable source, the rest exactly as it was. Resources come from src/,
// so edited resources are picked up too.
//
// Output layout:  src/  (decompiled source + resources)   lib/original.jar   lib/nested/  (JARs the program
// carries inside it)   rebuilt/<name>.jar   build.bat   BUILD.md
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const AdmZip = require('adm-zip');
const { readClass } = require('./classfile');

const IS_WIN = process.platform === 'win32';
const EXE = IS_WIN ? '.exe' : '';
const MAX_ROUNDS = 10;
const SIGNATURE = /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i;
const OWN_FILES = new Set(['src', 'lib', 'build', 'rebuilt', 'build.bat', 'BUILD.md', '.dropdecompiler.json', 'original-source', 'ORIGINAL-SOURCE.md']);

const exists = (p) => fsp.access(p).then(() => true, () => false);
const isAnonymous = (name) => /\$\d/.test(name); // Foo$1, Foo$1Local: only used inside their own file

async function walk(dir, filter, rel = '', out = []) {
  let ents;
  try { ents = await fsp.readdir(path.join(dir, rel), { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) await walk(dir, filter, r, out);
    else if (filter(r)) out.push(r);
  }
  return out;
}

/** First run: move Vineflower's output into src/ and keep a copy of the input as lib/original.jar. */
async function layoutJava(outDir, inputFile) {
  const src = path.join(outDir, 'src');
  if (!(await exists(src))) {
    await fsp.mkdir(src);
    for (const name of await fsp.readdir(outDir)) {
      if (OWN_FILES.has(name)) continue;
      await fsp.rename(path.join(outDir, name), path.join(src, name));
    }
  }
  const original = path.join(outDir, 'lib', 'original.jar');
  if (inputFile && !(await exists(original))) {
    await fsp.mkdir(path.dirname(original), { recursive: true });
    await fsp.copyFile(inputFile, original);
  }
}

/** Reads the original archive: its classes (by internal name) and other entries, in order. */
function readArchive(jarPath) {
  const zip = new AdmZip(jarPath);
  const entries = [];
  const classes = new Map();
  for (const e of zip.getEntries()) {
    const ent = { name: e.entryName, dir: e.isDirectory, data: e.isDirectory ? null : e.getData() };
    entries.push(ent);
    if (ent.dir || !/\.class$/i.test(ent.name) || /^META-INF\/versions\//i.test(ent.name)) continue;
    const info = readClass(ent.data);
    if (!info || !ent.name.endsWith(info.name + '.class')) continue;
    ent.cls = info.name;
    classes.set(info.name, { ...info, entry: ent, prefix: ent.name.slice(0, ent.name.length - info.name.length - 6) });
  }
  return { entries, classes };
}

function parseJavacErrors(out, srcDir) {
  const errs = new Map();
  for (const line of out.split(/\r?\n/)) {
    const m = /^(.+?\.java):(\d+): error: (.*)$/.exec(line.trim());
    if (!m) continue;
    const file = path.resolve(srcDir, m[1]);
    const key = IS_WIN ? file.toLowerCase() : file;
    if (!errs.has(key)) errs.set(key, `line ${m[2]}: ${m[3]}`);
  }
  return errs;
}

async function javacVersion(javac) {
  const { exec } = require('./rebuild');
  try {
    const r = await exec(javac, ['-version']);
    return Number((r.out.match(/javac (\d+)/) || [])[1]) || 0;
  } catch { return 0; }
}

/**
 * Builds rebuilt/<name>.jar. `javaExe` is the java executable of a JDK (javac and jar sit next to it).
 * Returns a summary for the UI; never throws for compile problems (only for cancellation / missing JDK).
 */
async function rebuildJava(outDir, { inputFile, name, javaExe, log = () => {}, signal } = {}) {
  const { exec } = require('./rebuild');
  await layoutJava(outDir, inputFile);
  const srcDir = path.join(outDir, 'src');
  const libDir = path.join(outDir, 'lib');
  const buildDir = path.join(outDir, 'build');
  const classesDir = path.join(buildDir, 'classes');
  const originalJar = path.join(libDir, 'original.jar');
  if (!(await exists(originalJar))) throw new Error('lib/original.jar is missing, so there is nothing to rebuild against.');

  const stateFile = path.join(outDir, '.dropdecompiler.json');
  let state = {};
  try { state = JSON.parse(await fsp.readFile(stateFile, 'utf8')); } catch { /* first run */ }
  name = name || state.name || 'program.jar';
  const jarName = name.replace(/\.(war|ear|zip|jmod)$/i, '.jar').replace(/^(?!.*\.jar$)(.*)$/i, '$1.jar');

  const bin = path.dirname(javaExe);
  const javac = path.join(bin, 'javac' + EXE);
  const jdkMajor = await javacVersion(javac);
  if (!jdkMajor) throw new Error('No JDK with javac was found to recompile the Java source.');

  log('Rebuilding the JAR: recompiling the decompiled source with javac…');
  const { entries, classes } = readArchive(originalJar);

  // Libraries the program carries inside itself (fat JARs, Fabric/Forge mods, WAR files) go on the classpath.
  const nestedDir = path.join(libDir, 'nested');
  for (const e of entries) {
    if (e.dir || !/\.jar$/i.test(e.name)) continue;
    const dest = path.join(nestedDir, path.basename(e.name));
    if (!(await exists(dest))) {
      await fsp.mkdir(nestedDir, { recursive: true });
      await fsp.writeFile(dest, e.data);
    }
  }

  // Classes inside a sub-folder of the archive (WEB-INF/classes, BOOT-INF/classes) need a plain folder on the classpath.
  await fsp.rm(buildDir, { recursive: true, force: true });
  const cp = [path.join(libDir, '*'), path.join(nestedDir, '*')];
  const prefixed = [...classes.values()].filter((c) => c.prefix);
  if (prefixed.length) {
    const dir = path.join(buildDir, 'original-classes');
    for (const c of prefixed) {
      const dest = path.join(dir, ...c.name.split('/')) + '.class';
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      await fsp.writeFile(dest, c.entry.data);
    }
    cp.unshift(dir);
  }

  // Match each source file to the original classes it produces (Foo.java → Foo, Foo$Inner, Foo$1…).
  const sources = new Map(); // internal name of the top-level class → { file, rel }
  for (const rel of await walk(srcDir, (r) => r.endsWith('.java') && !r.endsWith('module-info.java'))) {
    const file = path.join(srcDir, ...rel.split('/'));
    const text = await fsp.readFile(file, 'utf8');
    const pkg = (text.match(/^\s*package\s+([\w.]+)\s*;/m) || [])[1];
    const internal = (pkg ? pkg.replace(/\./g, '/') + '/' : '') + path.basename(rel, '.java');
    if (classes.has(internal)) sources.set(internal, { file, rel, internal });
  }
  const ownerOf = (cls) => {
    for (let n = cls; ; ) {
      if (sources.has(n)) return n;
      const i = n.lastIndexOf('$');
      if (i <= 0) return null;
      n = n.slice(0, i);
    }
  };
  const owned = new Map(); // source → original classes it replaces
  for (const c of classes.values()) {
    const o = ownerOf(c.name);
    if (o) (owned.get(o) || owned.set(o, []).get(o)).push(c);
  }

  const maxMajor = Math.max(52, ...[...classes.values()].map((c) => c.major));
  const release = Math.min(jdkMajor, Math.max(8, maxMajor - 44));
  const kept = new Map(); // source internal name → reason it was kept from the original
  let active = [...sources.keys()];
  let javacFailure = null;
  const total = sources.size;

  for (let round = 1; round <= MAX_ROUNDS && active.length; round++) {
    await fsp.rm(classesDir, { recursive: true, force: true });
    await fsp.mkdir(classesDir, { recursive: true });
    const listFile = path.join(buildDir, 'sources.txt');
    await fsp.writeFile(listFile, active.map((s) => `"${sources.get(s).file.split(path.sep).join('/')}"`).join('\n'));
    log(round === 1 ? `Compiling ${active.length.toLocaleString()} classes (Java ${release})…` : `Recompiling ${active.length.toLocaleString()} classes without the ones that failed…`);
    const r = await exec(javac, [
      '-d', classesDir, '-cp', cp.join(path.delimiter), '--release', String(release), '-encoding', 'UTF-8',
      '-nowarn', '-proc:none', '-implicit:none', '-Xmaxerrs', '1000000', '-XDsuppressNotes', '@' + listFile,
    ], { cwd: srcDir, signal });

    if (r.code !== 0) {
      const errs = parseJavacErrors(r.out, srcDir);
      const failing = active.filter((s) => {
        const f = sources.get(s).file;
        return errs.has(IS_WIN ? f.toLowerCase() : f);
      });
      if (!failing.length) {
        javacFailure = r.out.trim().split(/\r?\n/).slice(-6).join('\n');
        for (const s of active) kept.set(s, 'javac failed: ' + javacFailure.split('\n')[0]);
        active = [];
        break;
      }
      for (const s of failing) {
        const f = sources.get(s).file;
        kept.set(s, errs.get(IS_WIN ? f.toLowerCase() : f));
      }
      active = active.filter((s) => !kept.has(s));
      continue;
    }

    // The rest of the program was compiled against the original classes: a recompiled class must still
    // provide every field and method they can use, and every named nested class.
    const changed = [];
    for (const s of active) {
      for (const orig of owned.get(s) || []) {
        if (isAnonymous(orig.name)) continue;
        const file = path.join(classesDir, ...orig.name.split('/')) + '.class';
        const now = (await exists(file)) ? readClass(await fsp.readFile(file)) : null;
        if (!now) { changed.push([s, `${orig.name.split('/').pop()} is missing after recompiling`]); break; }
        const lost = [...orig.members].filter((m) => !now.members.has(m));
        if (lost.length) { changed.push([s, `${orig.name.split('/').pop()} lost ${lost[0].slice(2)}${lost.length > 1 ? ` and ${lost.length - 1} more` : ''}`]); break; }
      }
    }
    if (!changed.length) break;
    for (const [s, why] of changed) kept.set(s, why);
    active = active.filter((s) => !kept.has(s));
  }
  if (!active.length) await fsp.rm(classesDir, { recursive: true, force: true });

  // Assemble: original order, recompiled classes in place of the ones they replace, resources from src/.
  const replaced = new Set();
  for (const s of active) for (const c of owned.get(s) || []) replaced.add(c.entry.name);
  const out = new AdmZip();
  let signatureDropped = false;
  let resourcesEdited = 0;
  for (const e of entries) {
    if (replaced.has(e.name)) continue;
    if (replaced.size && SIGNATURE.test(e.name)) { signatureDropped = true; continue; }
    if (e.dir) { out.addFile(e.name, Buffer.alloc(0)); continue; }
    let data = e.data;
    if (!e.cls && !/\.jar$/i.test(e.name)) {
      const edited = path.join(srcDir, ...e.name.split('/'));
      try {
        const d = await fsp.readFile(edited);
        if (!d.equals(data)) { data = d; resourcesEdited++; }
      } catch { /* not in src/: keep the original */ }
    }
    out.addFile(e.name, data);
  }
  let added = 0;
  for (const s of active) {
    const prefix = classes.get(s).prefix;
    const pkgDir = path.posix.dirname(s);
    const base = path.posix.basename(s);
    const dir = path.join(classesDir, ...pkgDir.split('/'));
    for (const f of await fsp.readdir(dir).catch(() => [])) {
      if (f === base + '.class' || (f.startsWith(base + '$') && f.endsWith('.class'))) {
        out.addFile(prefix + (pkgDir === '.' ? '' : pkgDir + '/') + f, await fsp.readFile(path.join(dir, f)));
        added++;
      }
    }
  }
  const rebuiltDir = path.join(outDir, 'rebuilt');
  await fsp.rm(rebuiltDir, { recursive: true, force: true });
  await fsp.mkdir(rebuiltDir, { recursive: true });
  const rebuiltJar = path.join(rebuiltDir, jarName);
  await out.writeZipPromise(rebuiltJar);

  // Check the result is the whole program: every named class and every other file of the original is there.
  const check = readArchive(rebuiltJar);
  const missing = [];
  for (const c of classes.values()) if (!isAnonymous(c.name) && !check.classes.has(c.name)) missing.push(c.name);
  const names = new Set(check.entries.map((e) => e.name));
  for (const e of entries) {
    if (!e.cls && !e.dir && !names.has(e.name) && !(signatureDropped && SIGNATURE.test(e.name))) missing.push(e.name);
  }

  await fsp.rm(classesDir, { recursive: true, force: true });
  await writeBuildBat(outDir, { jarName, release, cp: cp.map((p) => path.relative(outDir, p)), prefix: (classes.get(active[0] || '') || {}).prefix || '', bin });
  const fromSource = active.length;
  const summary = {
    kind: 'java', checked: true, ok: missing.length === 0, complete: missing.length === 0,
    fromSource, total, kept: kept.size, errors: kept.size, release,
    outputs: [path.relative(outDir, rebuiltJar).split(path.sep).join('/')],
  };
  await fsp.writeFile(stateFile, JSON.stringify({ ...state, name }, null, 2));
  await fsp.writeFile(path.join(outDir, 'BUILD.md'), javaReport({
    name, jarName, summary, kept, sources, javacFailure, missing, signatureDropped, resourcesEdited, release,
    nested: await fsp.readdir(nestedDir).catch(() => []),
  }));
  if (missing.length) log(`The rebuilt JAR is missing ${missing.length} file(s) — see BUILD.md`, { warn: true });
  else log(`✓ Rebuilt ${jarName}: ${fromSource.toLocaleString()} of ${total.toLocaleString()} classes recompiled from source, ${kept.size.toLocaleString()} kept from the original — complete program`);
  return summary;
}

async function writeBuildBat(outDir, { jarName, release, cp, prefix, bin }) {
  const cpWin = cp.map((p) => p.split('/').join('\\')).join(';');
  const lines = [
    '@echo off',
    'rem Recompiles the classes listed in build\\sources.txt (the ones that compiled last time) and puts them',
    'rem into a copy of the original JAR. Press "Rebuild" in DropDecompiler to retry every class and update the list.',
    'cd /d "%~dp0"',
    `set "JDK=${bin}"`,
    'if exist "%JDK%\\javac.exe" (set "JAVAC=%JDK%\\javac.exe" & set "JAR=%JDK%\\jar.exe") else (set "JAVAC=javac" & set "JAR=jar")',
    'if not exist build\\sources.txt (echo Press Rebuild in DropDecompiler first. & pause & exit /b 1)',
    'if exist build\\classes rmdir /s /q build\\classes',
    `"%JAVAC%" -d build\\classes -cp "${cpWin}" --release ${release} -encoding UTF-8 -nowarn -proc:none -implicit:none @build\\sources.txt || (pause & exit /b 1)`,
    'if not exist rebuilt mkdir rebuilt',
    `copy /y lib\\original.jar "rebuilt\\${jarName}" >nul`,
  ];
  if (prefix) {
    lines.push(`xcopy /e /i /y /q build\\classes "build\\stage\\${prefix.split('/').join('\\')}" >nul`,
      `"%JAR%" uf "rebuilt\\${jarName}" -C build\\stage . || (pause & exit /b 1)`, 'rmdir /s /q build\\stage');
  } else {
    lines.push(`"%JAR%" uf "rebuilt\\${jarName}" -C build\\classes . || (pause & exit /b 1)`);
  }
  lines.push('rmdir /s /q build\\classes', `echo Built rebuilt\\${jarName}`, 'pause', '');
  await fsp.writeFile(path.join(outDir, 'build.bat'), lines.join('\r\n'));
}

function javaReport({ name, jarName, summary, kept, sources, javacFailure, missing, signatureDropped, resourcesEdited, release, nested }) {
  const o = [`# Rebuilding ${name}`, ''];
  o.push(summary.complete
    ? `Status: ✓ COMPLETE — rebuilt/${jarName} contains the whole program.`
    : `Status: ✕ rebuilt/${jarName} is missing ${missing.length} file(s) of the original (see below).`, '');
  o.push(`- ${summary.fromSource.toLocaleString()} of ${summary.total.toLocaleString()} classes were recompiled from the decompiled source in src/`);
  if (kept.size) o.push(`- ${kept.size.toLocaleString()} were kept exactly as in the original, because their source doesn't compile yet (listed below)`);
  o.push(`- compiled for Java ${release}, the version the original was built for`);
  if (resourcesEdited) o.push(`- ${resourcesEdited} resource file(s) taken from your edited copies in src/`);
  if (signatureDropped) o.push('- the original was signed; the signature was removed because the classes changed');
  o.push('', 'So the rebuilt JAR always runs like the original. Each class you fix in src/ moves from "kept" to',
    '"recompiled" the next time you press Rebuild.', '',
    '## How to build', '',
    '- press "Rebuild" in DropDecompiler: tries every class again, keeps the original for the ones that fail',
    '- or double-click build.bat: recompiles the classes that compiled last time (build/sources.txt)',
    '- or open the folder in IntelliJ IDEA / Eclipse: mark src/ as the source root and add the JARs in lib/ and',
    '  lib/nested/ as libraries', '');
  if (nested.length) {
    o.push('## Libraries', '', `The program carries ${nested.length} JAR(s) inside it; they are in lib/nested/ and on the classpath.`,
      'If classes fail with "cannot find symbol" or "package … does not exist", the program needs a library it',
      "doesn't include (for a Minecraft mod: Minecraft and the mod loader). Put those JARs in lib/ and press Rebuild.", '');
  } else {
    o.push('## Libraries', '', 'If classes fail with "cannot find symbol" or "package … does not exist", the program needs a library',
      "it doesn't include. Put those JARs in lib/ and press Rebuild.", '');
  }
  if (javacFailure) o.push('## javac', '', '```', javacFailure, '```', '');
  if (kept.size) {
    o.push('## Kept from the original', '');
    const list = [...kept.entries()].sort(([a], [b]) => a.localeCompare(b));
    for (const [s, why] of list.slice(0, 300)) o.push(`- src/${sources.get(s).rel}  —  ${why}`);
    if (list.length > 300) o.push(`- … and ${list.length - 300} more`);
    o.push('');
  }
  if (missing.length) {
    o.push('## Missing from the rebuilt JAR', '');
    for (const m of missing.slice(0, 100)) o.push(`- ${m}`);
    o.push('');
  }
  o.push('## Notes', '',
    '- Names of classes, methods and fields are the original ones; local variable names are guessed and comments are gone.',
    '- Kotlin and Scala classes come back as Java and often need fixes before they compile; the originals are kept until then.',
    '- Obfuscated programs keep their scrambled names.', '');
  return o.join('\n');
}

module.exports = { rebuildJava, layoutJava };
