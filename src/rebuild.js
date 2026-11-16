// Turns decompiler output into projects that build again.
//  .NET:   fixes the ILSpy projects (target framework, references between the app's own assemblies,
//          third-party DLLs copied into lib/), writes a .sln and build.bat, then really builds it with
//          `dotnet build`, applying automatic fixes for known decompiler mistakes, and writes BUILD.md.
//  Native: extracts the Windows resources (dialogs, menus, icons, strings, version info, manifest) into
//          resources/app.rc and checks with rc.exe that they compile back to the same bytes.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { readResources, readRes, writeRcProject, compareResources, findRc, keyOf } = require('./peres');

const IS_WIN = process.platform === 'win32';
const DOTNET_ENV = { DOTNET_NOLOGO: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_GENERATE_ASPNET_CERTIFICATE: 'false', MSBUILDDISABLENODEREUSE: '1' };
const SKIP_DIRS = new Set(['bin', 'obj', '_bundle', 'rebuilt', 'lib', 'resources', 'functions', 'node_modules', '.vs', 'original-source']);
const MAX_ATTEMPTS = 4;

const exists = (p) => fsp.access(p).then(() => true, () => false);

function exec(cmd, args, { cwd, env, signal, onLine } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, windowsHide: true });
    let out = '';
    let partial = '';
    const onData = (c) => {
      const text = c.toString();
      out += text;
      if (out.length > 4e6) out = out.slice(-2e6);
      const lines = (partial + text).split(/\r?\n/);
      partial = lines.pop();
      for (const l of lines) if (l.trim()) onLine?.(l);
    };
    const kill = () => {
      if (IS_WIN) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true }).on('error', () => {});
      else child.kill('SIGKILL');
    };
    signal?.addEventListener('abort', kill, { once: true });
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', (e) => { signal?.removeEventListener('abort', kill); reject(e); });
    child.on('close', (code) => {
      signal?.removeEventListener('abort', kill);
      if (partial.trim()) onLine?.(partial);
      if (signal?.aborted) { const e = new Error('Cancelled'); e.cancelled = true; reject(e); }
      else resolve({ code, out });
    });
  });
}

async function findProjects(dir, depth = 3, out = []) {
  let ents;
  try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isFile() && /\.csproj$/i.test(e.name)) out.push(p);
    else if (e.isDirectory() && depth > 0 && !SKIP_DIRS.has(e.name.toLowerCase())) await findProjects(p, depth - 1, out);
  }
  return out;
}

async function findByName(dir, name, depth = 6) {
  if (depth < 0) return null;
  let ents;
  try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch { return null; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isFile() && e.name.toLowerCase() === name.toLowerCase()) return p;
  }
  for (const e of ents) {
    if (!e.isDirectory()) continue;
    const hit = await findByName(path.join(dir, e.name), name, depth - 1);
    if (hit) return hit;
  }
  return null;
}

const tag = (xml, name) => (xml.match(new RegExp(`<${name}>([^<]*)</${name}>`)) || [])[1];
const winPath = (p) => p.split('/').join('\\');
const guidFor = (s) => {
  const h = crypto.createHash('md5').update(s).digest('hex').toUpperCase();
  return `{${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}}`;
};

// .NET Framework 4.x versions are all in-place updates of 4.0, and the metadata of programs built
// without a TargetFrameworkAttribute says "v4.0" even when they use 4.5+ APIs, so ILSpy picks net40.
// 4.8 is a superset that every supported Windows ships, so it builds them all.
const OLD_NET4 = /^net4(0|03|5|51|52|6|61|62|7|71|72)$/;

// ---------------------------------------------------------------- .NET project preparation

async function readProject(file) {
  const xml = await fsp.readFile(file, 'utf8');
  return {
    file,
    dir: path.dirname(file),
    xml,
    name: path.basename(file, '.csproj'),
    assembly: tag(xml, 'AssemblyName') || path.basename(file, '.csproj'),
    outputType: tag(xml, 'OutputType') || 'Library',
    tf: tag(xml, 'TargetFramework') || tag(xml, 'TargetFrameworks') || '',
  };
}

/**
 * Makes the ILSpy projects in `outDir` self-contained and buildable (idempotent).
 * Returns { projects, sln, fixes, missing } — `fixes` are human-readable notes for BUILD.md.
 */
async function prepareDotNet(outDir, { inputFile, title } = {}) {
  const projects = await Promise.all((await findProjects(outDir)).map(readProject));
  if (!projects.length) return null;
  const fixes = [];
  const missing = [];
  const byAssembly = new Map(projects.map((p) => [p.assembly.toLowerCase(), p]));
  const libDir = path.join(outDir, 'lib');
  const searchDirs = [path.join(outDir, '_bundle'), inputFile && path.dirname(inputFile)].filter(Boolean);

  for (const p of projects) {
    let xml = p.xml;
    if (OLD_NET4.test(p.tf)) {
      xml = xml.replace(`<TargetFramework>${p.tf}</TargetFramework>`, '<TargetFramework>net48</TargetFramework>');
      fixes.push(`${p.name}: target framework ${p.tf} → net48 (the metadata only says "4.x"; 4.8 contains every 4.x API)`);
      p.tf = 'net48';
    }

    // References: the app's own assemblies become project references; third-party DLLs go to lib/.
    const refRe = /<Reference Include="([^"]+)"\s*(?:\/>|>([\s\S]*?)<\/Reference>)/g;
    const replacements = [];
    for (const m of xml.matchAll(refRe)) {
      const simple = m[1].split(',')[0].trim();
      const sibling = byAssembly.get(simple.toLowerCase());
      if (sibling && sibling !== p) {
        const rel = winPath(path.relative(p.dir, sibling.file));
        replacements.push([m[0], `<ProjectReference Include="${rel}" />`]);
        fixes.push(`${p.name}: references the decompiled ${sibling.name} project instead of its DLL`);
        continue;
      }
      const hint = m[2] && tag(m[2], 'HintPath');
      if (!hint) continue;
      const abs = path.resolve(p.dir, hint);
      if (abs.startsWith(libDir + path.sep) && (await exists(abs))) continue; // already prepared
      let src = (await exists(abs)) ? abs : null;
      for (const d of searchDirs) if (!src) src = await findByName(d, path.basename(hint));
      if (!src) { missing.push(`${p.name}: ${path.basename(hint)}`); continue; }
      await fsp.mkdir(libDir, { recursive: true });
      const dest = path.join(libDir, path.basename(src));
      if (path.resolve(src) !== dest) await fsp.copyFile(src, dest);
      const rel = winPath(path.relative(p.dir, dest));
      replacements.push([m[0], m[0].replace(`<HintPath>${hint}</HintPath>`, `<HintPath>${rel}</HintPath>`)]);
      fixes.push(`${p.name}: ${path.basename(src)} copied into lib\\ so the project builds anywhere`);
    }
    for (const [a, b] of replacements) xml = xml.replace(a, b);
    if (xml !== p.xml) {
      await fsp.writeFile(p.file, xml);
      p.xml = xml;
    }
  }

  // Solution file: one entry per project, the program (exe) first so Visual Studio starts it.
  projects.sort((a, b) => /exe/i.test(b.outputType) - /exe/i.test(a.outputType));
  // A later "Rebuild" reuses the solution written the first time.
  const existing = title ? [] : (await fsp.readdir(outDir)).filter((f) => /\.sln$/i.test(f));
  const slnName = existing.length === 1 ? existing[0] : (title || path.basename(outDir)).replace(/[<>:"/\\|?*]/g, '_') + '.sln';
  const sln = path.join(outDir, slnName);
  const typeGuid = '{9A19103F-16F7-4668-BE54-9A1E7A4F7556}';
  const lines = [
    '', 'Microsoft Visual Studio Solution File, Format Version 12.00', '# Visual Studio Version 17',
    'VisualStudioVersion = 17.0.31903.59', 'MinimumVisualStudioVersion = 10.0.40219.1',
  ];
  for (const p of projects) {
    lines.push(`Project("${typeGuid}") = "${p.name}", "${winPath(path.relative(outDir, p.file))}", "${guidFor(p.file)}"`, 'EndProject');
  }
  lines.push('Global', '\tGlobalSection(SolutionConfigurationPlatforms) = preSolution',
    '\t\tDebug|Any CPU = Debug|Any CPU', '\t\tRelease|Any CPU = Release|Any CPU', '\tEndGlobalSection',
    '\tGlobalSection(ProjectConfigurationPlatforms) = postSolution');
  for (const p of projects) {
    const g = guidFor(p.file);
    for (const c of ['Debug', 'Release']) {
      lines.push(`\t\t${g}.${c}|Any CPU.ActiveCfg = ${c}|Any CPU`, `\t\t${g}.${c}|Any CPU.Build.0 = ${c}|Any CPU`);
    }
  }
  lines.push('\tEndGlobalSection', 'EndGlobal', '');
  await fsp.writeFile(sln, '\ufeff' + lines.join('\r\n'));

  await fsp.writeFile(path.join(outDir, 'build.bat'), [
    '@echo off',
    'rem Builds the decompiled solution. Output: rebuilt\\  (open the .sln in Visual Studio to edit and debug)',
    'cd /d "%~dp0"',
    'where dotnet >nul 2>nul || (echo The .NET SDK is required: https://dotnet.microsoft.com/download & pause & exit /b 1)',
    `dotnet build "${slnName}" -c Release || (pause & exit /b 1)`,
    'echo.',
    "echo Build succeeded. The program is in each project's bin\\Release folder.",
    'pause',
    '',
  ].join('\r\n'));

  return { projects, sln, fixes, missing };
}

// ---------------------------------------------------------------- .NET build + automatic fixes

// "C:\x\Foo.cs(12,5): error CS0165: Use of unassigned local variable 'x' [C:\x\Foo.csproj]"
const DIAG = /^\s*(.*?)\((\d+),(\d+)(?:,\d+,\d+)?\): (error|warning) ([A-Z]+\d+): (.*?)(?: \[([^\]]+)\])?\s*$/;
const DIAG_NOPOS = /^\s*(.*?) : (error|warning) ([A-Z]+\d+): (.*?)(?: \[([^\]]+)\])?\s*$/;

function parseDiagnostics(out) {
  const seen = new Set();
  const list = [];
  for (const line of out.split(/\r?\n/)) {
    let d;
    const m = DIAG.exec(line);
    if (m) d = { file: m[1], line: +m[2], col: +m[3], severity: m[4], code: m[5], message: m[6], project: m[7] };
    else {
      const n = DIAG_NOPOS.exec(line);
      if (n) d = { file: n[1], line: 0, col: 0, severity: n[2], code: n[3], message: n[4], project: n[5] };
    }
    if (!d || d.severity !== 'error') continue;
    const key = `${d.file}|${d.line}|${d.col}|${d.code}|${d.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    list.push(d);
  }
  return list;
}

/** Applies fixes for known decompiler artefacts. Returns the notes of the fixes made (empty = nothing to do). */
async function applyFixes(errors, prep, done) {
  const notes = [];
  const edits = new Map(); // file -> lines
  const inserts = [];

  const lines = async (file) => {
    if (!edits.has(file)) edits.set(file, (await fsp.readFile(file, 'utf8')).split('\n'));
    return edits.get(file);
  };

  for (const e of errors) {
    const proj = prep.projects.find((p) => e.project && path.resolve(e.project) === path.resolve(p.file)) ||
      prep.projects.find((p) => e.file && path.resolve(e.file).startsWith(p.dir + path.sep));

    // CS0165: ILSpy sometimes can't untangle an async/iterator state machine and leaves a jump past a
    // variable's assignment. Initialising it makes the method compile; its logic still needs a look.
    if (e.code === 'CS0165' && /\.cs$/i.test(e.file)) {
      const name = (e.message.match(/'([^']+)'/) || [])[1];
      const key = `${e.file}|${name}|${e.line}`;
      if (!name || done.has(key) || !(await exists(e.file))) continue;
      const ls = await lines(e.file);
      const n = name.replace(/[$]/g, '\\$');
      const type = '((?!(?:return|goto|throw|else|case|await|yield|new|out|ref|in|using|var|const)\\b)[\\w.<>\\[\\], ?]+?)';
      const bare = new RegExp(`^(\\s*)${type}\\s+${n};\\s*\\r?$`);
      const init = new RegExp(`^(\\s*)${type}\\s+${n}\\s*=\\s*(.+);\\s*\\r?$`);
      // ILSpy puts each method signature on its own line: don't search past the start of this method.
      const signature = /^\s*(?:(?:public|private|protected|internal|static|async|override|virtual|sealed|extern|unsafe|new)\s+)+[^=;]*\)\s*\r?$/;
      for (let i = Math.min(e.line - 1, ls.length - 1); i >= 0 && !signature.test(ls[i]); i--) {
        let m = bare.exec(ls[i]);
        if (m) {
          ls[i] = `${m[1]}${m[2]} ${name} = default; // DropDecompiler: initialised so it compiles — review this method`;
          done.add(key);
          notes.push(`${path.basename(e.file)}:${i + 1} — initialised local '${name}' (ILSpy couldn't fully recover this method; check its logic)`);
          break;
        }
        m = init.exec(ls[i]);
        if (m) {
          // A goto jumps over "T x = value;": declare x at the top of the method, keep the assignment here.
          const outer = m[1].replace(/(\t|    )$/, '');
          let open = -1;
          for (let j = i - 1; j >= 0 && j > i - 5000; j--) {
            if (ls[j].replace(/\r$/, '') === outer + '{') { open = j; break; }
          }
          if (open < 0) break;
          ls[i] = `${m[1]}${name} = ${m[3]};`;
          inserts.push({ file: e.file, at: open + 1, text: `${m[1]}${m[2]} ${name} = default; // DropDecompiler: moved up so it compiles — review this method` });
          done.add(key);
          notes.push(`${path.basename(e.file)}:${i + 1} — moved the declaration of '${name}' to the top of its method (ILSpy couldn't fully recover this method; check its logic)`);
          break;
        }
      }
      continue;
    }

    if (!proj) continue;
    // LangVersion newer than the installed compiler.
    if ((e.code === 'CS1617' || e.code === 'CS8304' || /LangVersion/i.test(e.message)) && !done.has(proj.file + '|lang')) {
      done.add(proj.file + '|lang');
      proj.xml = proj.xml.replace(/<LangVersion>[^<]*<\/LangVersion>/, '<LangVersion>latest</LangVersion>');
      await fsp.writeFile(proj.file, proj.xml);
      notes.push(`${proj.name}: LangVersion set to "latest" (the installed compiler is older than the one ILSpy targets)`);
      continue;
    }
    // Missing APIs on a .NET Framework 2.0/3.5 or old 4.x target: move to 4.8.
    if (/^(CS0117|CS0234|CS0246|CS1061|CS0103|CS0315|CS0012)$/.test(e.code) && /^net(20|35|4\d*)$/.test(proj.tf) && proj.tf !== 'net48' && !done.has(proj.file + '|tf')) {
      done.add(proj.file + '|tf');
      proj.xml = proj.xml.replace(`<TargetFramework>${proj.tf}</TargetFramework>`, '<TargetFramework>net48</TargetFramework>');
      await fsp.writeFile(proj.file, proj.xml);
      notes.push(`${proj.name}: target framework ${proj.tf} → net48 (APIs it uses are missing from ${proj.tf})`);
      proj.tf = 'net48';
    }
  }
  // Inserted lines go in last (bottom-up) so the error line numbers above stay valid.
  inserts.sort((a, b) => b.at - a.at);
  for (const ins of inserts) edits.get(ins.file).splice(ins.at, 0, ins.text + (edits.get(ins.file)[0]?.endsWith('\r') ? '\r' : ''));
  for (const [file, ls] of edits) await fsp.writeFile(file, ls.join('\n'));
  return notes;
}

async function rmBuildDirs(prep) {
  for (const p of prep.projects) {
    for (const d of ['bin', 'obj']) await fsp.rm(path.join(p.dir, d), { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => {});
  }
}

/**
 * Builds the prepared solution, fixing known problems between attempts. The built program is copied to
 * rebuilt/<project>/ and bin/obj are removed so the source tree stays clean.
 */
async function buildDotNet(outDir, prep, { log = () => {}, signal } = {}) {
  const result = { ok: false, attempts: 0, fixes: [], errors: [], outputs: [], skipped: null };
  const done = new Set();
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    result.attempts = attempt;
    log(attempt === 1 ? 'Checking that the decompiled project builds (dotnet build)…' : `Rebuilding after ${result.fixes.length} automatic fix(es)…`);
    let r;
    try {
      r = await exec('dotnet', ['build', prep.sln, '-c', 'Release', '-nologo', '-v', 'q', '-clp:ErrorsOnly;NoSummary', '-p:TreatWarningsAsErrors=false'], {
        cwd: outDir, env: DOTNET_ENV, signal,
      });
    } catch (e) {
      if (e.cancelled) throw e;
      result.skipped = 'The .NET SDK (dotnet) was not found, so the build could not be checked.';
      return result;
    }
    result.errors = parseDiagnostics(r.out);
    if (r.code === 0) { result.ok = true; break; }
    if (!result.errors.length) {
      result.errors = [{ file: '', line: 0, code: 'BUILD', message: r.out.trim().split(/\r?\n/).slice(-6).join(' ') }];
      break;
    }
    const notes = await applyFixes(result.errors, prep, done);
    if (!notes.length) break;
    result.fixes.push(...notes);
  }

  if (result.ok) {
    const dest = path.join(outDir, 'rebuilt');
    await fsp.rm(dest, { recursive: true, force: true });
    for (const p of prep.projects) {
      const bin = path.join(p.dir, 'bin', 'Release');
      const tfDirs = (await fsp.readdir(bin).catch(() => [])).map((d) => path.join(bin, d));
      if (await exists(path.join(bin, p.assembly + '.dll')) || await exists(path.join(bin, p.assembly + '.exe'))) tfDirs.unshift(bin);
      for (const d of tfDirs) {
        const exe = path.join(d, p.assembly + '.exe');
        const dll = path.join(d, p.assembly + '.dll');
        const main = (await exists(exe)) ? exe : (await exists(dll)) ? dll : null;
        if (!main) continue;
        // Libraries end up next to the program anyway; only copy them on their own when there is no program.
        if (main === dll && prep.projects.some((q) => /exe/i.test(q.outputType))) break;
        const target = path.join(dest, p.name);
        await fsp.cp(d, target, { recursive: true });
        result.outputs.push(path.join(target, path.basename(main)));
        break;
      }
    }
  }
  await rmBuildDirs(prep);
  return result;
}

function dotnetReport(name, prep, build) {
  const rel = (p) => path.relative(path.dirname(prep.sln), p).split(path.sep).join('/');
  const o = [`# Rebuilding ${name}`, ''];
  if (build?.skipped) o.push(`Status: not checked. ${build.skipped}`);
  else if (build?.ok) o.push(`Status: ✓ BUILDS — ${prep.projects.length} project${prep.projects.length > 1 ? 's' : ''} compiled without errors${prep.fixes.length ? ` after ${prep.fixes.length} automatic fix(es)` : ''}.`);
  else if (build) o.push(`Status: ✕ ${build.errors.length} error(s) remain — see below. Everything else is set up; fix these and build again.`);
  o.push('', '## How to build', '',
    `- Open ${path.basename(prep.sln)} in Visual Studio 2022 or later (or Rider / VS Code with C# Dev Kit) and press F5`,
    '- or double-click build.bat',
    `- or run:  dotnet build "${path.basename(prep.sln)}" -c Release`,
    '- or press "Rebuild" in DropDecompiler after editing the code', '');
  if (build?.outputs?.length) {
    o.push('## Rebuilt program', '');
    for (const p of build.outputs) o.push(`- ${rel(p)}`);
    o.push('');
  }
  o.push('## Projects', '');
  for (const p of prep.projects) o.push(`- ${rel(p.file)}  (${p.outputType}, ${p.tf})`);
  o.push('');
  const fixes = [...prep.fixes, ...(build?.fixes || [])];
  if (fixes.length) {
    o.push('## Changes made so it builds', '');
    for (const f of fixes) o.push(`- ${f}`);
    o.push('');
  }
  if (prep.missing.length) {
    o.push('## Missing libraries', '', 'These referenced DLLs were not found next to the input file. Put them in lib\\ and build again:', '');
    for (const m of prep.missing) o.push(`- ${m}`);
    o.push('');
  }
  if (build && !build.ok && build.errors.length) {
    o.push('## Remaining errors', '');
    for (const e of build.errors.slice(0, 80)) {
      const where = e.file ? `${rel(e.file)}${e.line ? `(${e.line})` : ''}: ` : '';
      o.push(`- ${where}${e.code} ${e.message}`);
    }
    if (build.errors.length > 80) o.push(`- … and ${build.errors.length - 80} more`);
    o.push('');
  }
  o.push('## Notes', '',
    '- Forms, controls and their layout are recreated as C# code (InitializeComponent); WPF windows come back as',
    '  .xaml files and resources (.resx, images, icons, the manifest) are included in the project.',
    '- Names of local variables are guessed unless a .pdb was next to the file; comments are gone.',
    '- Obfuscated programs decompile, but their names stay scrambled and they may need manual fixes.', '');
  return o.join('\n');
}

/** Prepare + build + BUILD.md. Never throws for build problems (only for cancellation). */
async function rebuildDotNet(outDir, { inputFile, name, log = () => {}, signal, build = true } = {}) {
  const prep = await prepareDotNet(outDir, { inputFile, title: name ? name.replace(/\.[^.]+$/, '') : undefined });
  if (!prep) return null;
  for (const f of prep.fixes) log('Project fix: ' + f, { quiet: true });
  const result = build ? await buildDotNet(outDir, prep, { log, signal }) : null;
  // Fixes from earlier runs are remembered so BUILD.md keeps listing them after a later "Rebuild".
  const notesFile = path.join(outDir, '.dropdecompiler.json');
  let state = {};
  try { state = JSON.parse(await fsp.readFile(notesFile, 'utf8')); } catch { /* first run */ }
  name = name || state.name || path.basename(outDir);
  const all = [...new Set([...(state.fixes || []), ...prep.fixes, ...(result?.fixes || [])])];
  await fsp.writeFile(notesFile, JSON.stringify({ name, fixes: all }, null, 2));
  prep.fixes = all;
  if (result) result.fixes = [];
  await fsp.writeFile(path.join(outDir, 'BUILD.md'), dotnetReport(name, prep, result));
  const summary = {
    kind: 'dotnet',
    checked: !!result && !result.skipped,
    ok: !!result?.ok,
    errors: result?.errors?.length || 0,
    fixes: prep.fixes.length + (result?.fixes?.length || 0),
    outputs: (result?.outputs || []).map((p) => path.relative(outDir, p).split(path.sep).join('/')),
    sln: path.basename(prep.sln),
  };
  if (result?.skipped) log(result.skipped, { warn: true });
  else if (result?.ok) log(`✓ The decompiled project builds${summary.fixes ? ` (${summary.fixes} automatic fix(es))` : ''} — rebuilt program in rebuilt/`);
  else if (result) log(`The project has ${summary.errors} build error(s) left — see BUILD.md`, { warn: true });
  return summary;
}

// ---------------------------------------------------------------- native resources

async function nativeResources(file, outDir, { log = () => {}, signal } = {}) {
  let buf;
  try { buf = await fsp.readFile(file); } catch { return null; }
  const resources = readResources(buf);
  if (!resources.length) return null;
  const dir = path.join(outDir, 'resources');
  await fsp.mkdir(dir, { recursive: true });
  const shown = resources.filter((r) => r.type !== 1 && r.type !== 3).length; // icon/cursor images belong to their groups
  log(`Extracting ${shown} Windows resources (dialogs, menus, icons, strings…) into resources/app.rc…`);
  const rc = await findRc();
  let fallback = new Set();
  let st;
  let verify = null;
  for (let pass = 0; pass < 3; pass++) {
    st = await writeRcProject(resources, dir, fallback);
    if (!rc) break;
    const tmp = path.join(os.tmpdir(), `dropdecomp-${process.pid}-${Date.now()}.res`);
    const r = await exec(rc, ['/nologo', '/fo', tmp, 'app.rc'], { cwd: dir, signal });
    if (r.code !== 0) {
      await fsp.rm(tmp, { force: true });
      if (pass === 0) { fallback = new Set(resources.map(keyOf)); continue; } // keep everything byte-for-byte
      verify = { ok: false, error: r.out.trim().split(/\r?\n/).slice(-5).join('\n') };
      break;
    }
    const rebuilt = readRes(await fsp.readFile(tmp));
    await fsp.rm(tmp, { force: true });
    if (st.extraPath) rebuilt.push(...readRes(await fsp.readFile(st.extraPath)));
    const cmp = compareResources(resources, rebuilt);
    verify = { ok: !cmp.bad.length && cmp.imagesMatch, mismatched: cmp.bad.length, imagesMatch: cmp.imagesMatch };
    if (verify.ok || !cmp.bad.length) break;
    for (const k of cmp.bad) fallback.add(k);
  }

  await fsp.writeFile(path.join(dir, 'build.bat'), [
    '@echo off',
    'rem Compiles app.rc into app.res with the Windows SDK resource compiler (installed with Visual Studio C++).',
    'cd /d "%~dp0"',
    'set "RC=rc.exe"',
    'where rc >nul 2>nul || for /f "delims=" %%i in (\'dir /b /s "%ProgramFiles(x86)%\\Windows Kits\\10\\bin\\rc.exe" 2^>nul ^| findstr /i "\\\\x64\\\\rc.exe"\') do set "RC=%%i"',
    '"%RC%" /nologo /fo app.res app.rc || (pause & exit /b 1)',
    'echo Built app.res. Link it into your program (link.exe app.res' + (st.extraPath ? ' extra.res' : '') + ' ...).',
    'pause',
    '',
  ].join('\r\n'));

  const summary = {
    kind: 'native', resources: st.count, text: st.text, files: st.raw, extra: st.extra,
    checked: !!verify, ok: !!verify?.ok, rc: !!rc, error: verify?.error,
  };
  if (!rc) log('Resources extracted (rc.exe not found, so they were not test-compiled).');
  else if (verify?.ok) log(`✓ ${st.count} resources rebuild byte-identical with rc.exe (${st.text} as editable script)`);
  else log(`Resources extracted; ${verify?.mismatched ?? '?'} could not be reproduced exactly`, { warn: true });
  return summary;
}

function nativeReadmeSection(sum) {
  const o = ['', '## Rebuilding', ''];
  o.push('Machine code can\'t be turned back into a project that compiles to the same program: the compiler',
    'threw away names, types and structure, and the pseudo-C above calls placeholders like FUN_140001000.',
    'Use it to understand the program and rewrite the parts you need. What CAN be rebuilt exactly:', '');
  if (sum) {
    o.push(`- resources/app.rc   the program's GUI and assets: ${sum.resources} resources (${sum.text} as editable`,
      '                     script: dialogs, menus, string tables, version info, shortcuts; icons, bitmaps and the',
      '                     manifest as files). Compile with resources/build.bat or add app.rc to a Visual Studio project.');
    if (sum.extra) o.push(`- resources/extra.res ${sum.extra} resource(s) rc can't express, already compiled — link next to app.res`);
    if (sum.checked) {
      o.push('', sum.ok
        ? '  ✓ Verified: compiling app.rc gives back exactly the same resources as the original program.'
        : '  ✕ Some resources did not compile back identically; see resources/app.rc.');
    }
  } else o.push('- (this file has no Windows resources)');
  o.push('');
  return o.join('\n');
}

/** Re-checks an output folder after the user edited it ("Rebuild" button). */
async function rebuildFolder(outDir, { log = () => {}, signal, javaExe } = {}) {
  if (await exists(path.join(outDir, 'lib', 'original.jar'))) {
    if (!javaExe) throw new Error('No JDK available to recompile the Java source.');
    return require('./javabuild').rebuildJava(outDir, { javaExe: await javaExe(), log, signal });
  }
  if (await exists(path.join(outDir, 'BUILD.md')) && (await exists(path.join(outDir, 'settings.gradle')) || await exists(path.join(outDir, 'settings.gradle.kts')))) {
    throw new Error('Android projects are built in Android Studio: open this folder there (see BUILD.md).');
  }
  if ((await findProjects(outDir)).length) return rebuildDotNet(outDir, { log, signal });
  const rcDir = path.join(outDir, 'resources');
  if (await exists(path.join(rcDir, 'app.rc'))) {
    const rc = await findRc();
    if (!rc) throw new Error('rc.exe (Windows SDK) was not found. Install Visual Studio with the C++ workload.');
    log('Compiling resources/app.rc…');
    const r = await exec(rc, ['/nologo', '/fo', 'app.res', 'app.rc'], { cwd: rcDir, signal });
    const errors = r.out.split(/\r?\n/).filter((l) => /error/i.test(l));
    return { kind: 'native', checked: true, ok: r.code === 0, errors: errors.length, outputs: r.code === 0 ? ['resources/app.res'] : [], message: errors.slice(0, 5).join('\n') };
  }
  throw new Error('Nothing to rebuild here: no .csproj project or resources/app.rc in this folder.');
}

module.exports = { rebuildDotNet, nativeResources, nativeReadmeSection, rebuildFolder, prepareDotNet, buildDotNet, parseDiagnostics, exec };
