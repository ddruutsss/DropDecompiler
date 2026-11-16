// Microsoft C/C++ toolchain on this PC (Visual Studio or Build Tools): found with vswhere, used with the
// environment of vcvarsall.bat. Needed for matching decompilation and for building helper tools.
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const VSWHERE = path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
let vsCache;
const envCache = new Map();

function exec(cmd, args, { env, cwd, verbatim, timeout = 120000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env: env || process.env, cwd, windowsHide: true, windowsVerbatimArguments: !!verbatim });
    let out = '';
    const add = (c) => { out += c.toString(); if (out.length > 20e6) out = out.slice(-10e6); };
    child.stdout.on('data', add);
    child.stderr.on('data', add);
    const timer = setTimeout(() => child.kill(), timeout);
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, out: String(e.message) }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, out }); });
  });
}

/** The newest Visual Studio with the C++ tools: { path, version, vcvarsall } or null. */
async function findVs() {
  if (vsCache !== undefined) return vsCache;
  vsCache = null;
  if (process.platform !== 'win32' || !fs.existsSync(VSWHERE)) return null;
  const r = await exec(VSWHERE, ['-latest', '-products', '*', '-prerelease', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-format', 'json', '-utf8']);
  try {
    const list = JSON.parse(r.out);
    const vs = list[0];
    const vcvarsall = vs && path.join(vs.installationPath, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat');
    if (vcvarsall && fs.existsSync(vcvarsall)) {
      const toolsDir = path.join(vs.installationPath, 'VC', 'Tools', 'MSVC');
      const toolset = fs.existsSync(toolsDir) ? fs.readdirSync(toolsDir).sort().pop() : null;
      vsCache = { path: vs.installationPath, version: vs.installationVersion, name: vs.displayName, vcvarsall, toolset };
    }
  } catch { /* no VS */ }
  return vsCache;
}

/** Environment variables set by vcvarsall.bat for an architecture ("x64" or "x86"). */
async function vcEnv(arch = 'x64') {
  if (envCache.has(arch)) return envCache.get(arch);
  const vs = await findVs();
  if (!vs) return null;
  const comspec = process.env.ComSpec || 'C:\\Windows\\System32\\cmd.exe';
  const target = arch === 'x86' ? 'x64_x86' : arch === 'arm64' ? 'x64_arm64' : 'x64';
  const r = await exec(comspec, ['/d', '/s', '/c', `""${vs.vcvarsall}" ${target} >nul 2>&1 && set"`], { verbatim: true, timeout: 120000 });
  const env = {};
  for (const line of r.out.split(/\r?\n/)) {
    const i = line.indexOf('=');
    if (i > 0) env[line.slice(0, i)] = line.slice(i + 1);
  }
  if (!env.INCLUDE || !env.Path && !env.PATH) return null;
  envCache.set(arch, env);
  return env;
}

/** Runs a tool of the toolchain (cl, link, dumpbin…) for an architecture. */
async function tool(name, args, { arch = 'x64', cwd, timeout } = {}) {
  const env = await vcEnv(arch);
  if (!env) throw new Error('Visual Studio C++ tools were not found (install the "Desktop development with C++" workload).');
  const dirs = (env.Path || env.PATH || '').split(';');
  const exe = dirs.map((d) => path.join(d, `${name}.exe`)).find((p) => fs.existsSync(p));
  if (!exe) throw new Error(`${name}.exe was not found in the Visual Studio environment`);
  return exec(exe, args, { env, cwd, timeout });
}

/** CMake: on PATH, or the one Visual Studio installs. */
async function findCmake() {
  for (const d of (process.env.PATH || '').split(path.delimiter)) {
    const p = d && path.join(d, 'cmake.exe');
    if (p && fs.existsSync(p)) return p;
  }
  const vs = await findVs();
  const bundled = vs && path.join(vs.path, 'Common7', 'IDE', 'CommonExtensions', 'Microsoft', 'CMake', 'CMake', 'bin', 'cmake.exe');
  return bundled && fs.existsSync(bundled) ? bundled : null;
}

module.exports = { findVs, vcEnv, tool, findCmake, exec };
