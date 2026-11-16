// Cross-platform app frameworks inside iOS (.ipa) and Android (.apk) packages. Native decompilers only see
// the host app; the real code of these apps is elsewhere:
//  - React Native: a JavaScript bundle (split back into its modules and re-indented), or Hermes bytecode
//  - Cordova / Capacitor / Ionic: the web app itself (HTML, JS, CSS: the actual source)
//  - Xamarin / .NET MAUI: .NET assemblies (decompiled to C# with ILSpy)
//  - Flutter: Dart compiled ahead of time (libapp.so / App.framework), assets
//  - Unity: IL2CPP (global-metadata.dat + the native game binary)
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const HERMES_MAGIC = Buffer.from('c61fbc03c103191f', 'hex');
const DOTNET_SYSTEM = /^(System|Microsoft|mscorlib|netstandard|Xamarin|Mono|Java\.Interop|Microsoft\.Maui|_Microsoft|WindowsBase|FSharp\.Core)\b/i;

function isHermes(buf) {
  return buf.length > 16 && buf.subarray(0, 8).equals(HERMES_MAGIC);
}

function printableStrings(buf, min = 6, limit = 100000) {
  const out = new Set();
  let cur = '';
  for (let i = 0; i < buf.length && out.size < limit; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
    else { if (cur.length >= min) out.add(cur); cur = ''; }
  }
  if (cur.length >= min) out.add(cur);
  return [...out];
}

/** Splits a React Native (Metro) bundle into its modules: [{ id, name, code }]. */
function splitMetroBundle(js) {
  const starts = [];
  const re = /__d\(\s*function\s*\(/g;
  let m;
  while ((m = re.exec(js))) starts.push(m.index);
  const modules = [];
  for (let k = 0; k < starts.length; k++) {
    let chunk = js.slice(starts[k], k + 1 < starts.length ? starts[k + 1] : js.length);
    // The last module is followed by the start-up code (__r(...)).
    if (k + 1 === starts.length) { const r = chunk.search(/;?\s*__r\(\d+\)/); if (r > 0) chunk = chunk.slice(0, r); }
    const tail = /\}\s*,\s*(\d+)\s*,\s*(\[[\d,\s]*\]|null)?\s*(?:,\s*"([^"]+)")?\s*\)\s*;?\s*$/.exec(chunk);
    modules.push({ id: tail ? Number(tail[1]) : k, name: tail?.[3] || null, code: chunk.replace(/;?\s*$/, ';') });
  }
  return modules;
}

function beautifyJs(code) {
  try { return require('js-beautify').js(code, { indent_size: 2, max_preserve_newlines: 2 }); } catch { return code; }
}

const safe = (s) => s.replace(/[<>:"|?*\x00-\x1f]/g, '_').replace(/\.\.+/g, '.').slice(0, 150);

/**
 * Looks at the files of an app package and extracts what the native decompilers can't see.
 * `files` = [{ rel, abs }] (rel uses "/"), `outDir` = output folder.
 * `dotnet(dllPath, outSubDir)` decompiles a .NET assembly (provided by core.js).
 * Returns { detected: [names], notes: [markdown lines] }.
 */
async function analyzeFrameworks(files, outDir, { log = () => {}, signal, dotnet } = {}) {
  const detected = [];
  const notes = [];
  const has = (re) => files.some((f) => re.test(f.rel));

  // ---- React Native
  const bundles = files.filter((f) => /(^|\/)(main\.jsbundle|index\.(android|ios)\.bundle|[^/]+\.jsbundle)$/i.test(f.rel));
  for (const b of bundles.slice(0, 4)) {
    const buf = await fsp.readFile(b.abs);
    const dir = path.join(outDir, 'react-native', safe(path.basename(b.rel)));
    await fsp.mkdir(dir, { recursive: true });
    if (isHermes(buf)) {
      const version = buf.readUInt32LE(8);
      const strings = printableStrings(buf);
      await fsp.writeFile(path.join(dir, 'strings.txt'), strings.join('\n') + '\n');
      detected.push('React Native (Hermes)');
      notes.push(`- **React Native, Hermes bytecode v${version}** (\`${b.rel}\`): the JavaScript was compiled to Hermes bytecode, which has no exact way back to JS. Its ${strings.length.toLocaleString('en')} strings (API URLs, keys, messages, component names) are in \`react-native/${path.basename(b.rel)}/strings.txt\`. A Hermes disassembler (hermes-dec, hbctool) can turn the bytecode into pseudo-code.`);
      log(`React Native app with Hermes bytecode v${version}: strings extracted`);
    } else {
      const js = buf.toString('utf8');
      const mods = splitMetroBundle(js);
      if (mods.length > 1) {
        const mdir = path.join(dir, 'modules');
        await fsp.mkdir(mdir, { recursive: true });
        for (const mod of mods) {
          if (signal?.aborted) break;
          const name = mod.name ? safe(mod.name.replace(/^\/+/, '').replace(/\.(jsx?|tsx?|mjs)$/i, '')).replace(/\//g, '__') : `${mod.id}`;
          await fsp.writeFile(path.join(mdir, `${name}.js`), beautifyJs(mod.code));
        }
        notes.push(`- **React Native** (\`${b.rel}\`): the JavaScript bundle was split back into its **${mods.length.toLocaleString('en')} modules** (\`react-native/${path.basename(b.rel)}/modules/\`, re-indented). This is the app's real JavaScript, minified: names of local variables are shortened, but logic, strings and component structure are intact.`);
      } else {
        await fsp.writeFile(path.join(dir, 'bundle.js'), js.length < 40e6 ? beautifyJs(js) : js);
        notes.push(`- **JavaScript bundle** (\`${b.rel}\`): re-indented into \`react-native/${path.basename(b.rel)}/bundle.js\`.`);
      }
      detected.push('React Native');
      log(`React Native app: ${mods.length > 1 ? `${mods.length} JavaScript modules extracted` : 'JavaScript bundle re-indented'}`);
    }
  }

  // ---- Cordova / Capacitor / Ionic: the web app is the source
  const webIndex = files.find((f) => /(^|\/)(www|public)\/index\.html$/i.test(f.rel));
  if (webIndex) {
    const root = webIndex.rel.slice(0, webIndex.rel.length - 'index.html'.length);
    const kind = has(/capacitor\.config\.json$|native-bridge\.js$/i) ? 'Capacitor' : has(/(^|\/)cordova\.js$/i) ? 'Cordova' : 'Web view app';
    const web = files.filter((f) => f.rel.startsWith(root));
    let pretty = 0;
    for (const f of web) {
      const dest = path.join(outDir, 'web-app', ...f.rel.slice(root.length).split('/'));
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      if (/\.(js|mjs)$/i.test(f.rel)) {
        const text = await fsp.readFile(f.abs, 'utf8');
        const lines = text.split('\n').length;
        if (text.length > 3000 && text.length / lines > 250 && text.length < 8e6) { await fsp.writeFile(dest, beautifyJs(text)); pretty++; continue; }
      }
      await fsp.copyFile(f.abs, dest);
    }
    detected.push(kind);
    notes.push(`- **${kind}**: the app is a web app in a native shell. Its HTML, JavaScript and CSS (the actual source of the app, ${web.length.toLocaleString('en')} files) are in \`web-app/\`${pretty ? `; ${pretty} minified scripts were re-indented` : ''}. Look for \`.map\` files there: they contain the original TypeScript.`);
    log(`${kind}: ${web.length} web files extracted`);
  }

  // ---- Xamarin / .NET MAUI
  const dlls = [];
  let packed = 0;
  for (const f of files.filter((x) => /\.dll$/i.test(x.rel) && x.abs)) {
    const fh = await fsp.open(f.abs, 'r');
    const b = Buffer.alloc(4);
    await fh.read(b, 0, 4, 0);
    await fh.close();
    if (b.toString('latin1', 0, 2) === 'MZ') dlls.push(f);
    else if (b.toString('latin1') === 'XALZ') packed++;
  }
  if (packed) {
    detected.push('.NET (Xamarin / MAUI)');
    notes.push(`- **.NET for Android**: ${packed} assemblies are LZ4-compressed ("XALZ"). Decompress them (for example with \`pyxamstore\` or an XALZ unpacker) and drop the DLLs into DropDecompiler to get C#.`);
  }
  if (dlls.length) {
    const app = dlls.filter((f) => !DOTNET_SYSTEM.test(path.basename(f.rel)));
    detected.push('.NET (Xamarin / MAUI)');
    let done = 0;
    if (dotnet) {
      for (const f of app.slice(0, 40)) {
        if (signal?.aborted) break;
        const name = path.basename(f.rel).replace(/\.dll$/i, '');
        log(`Decompiling .NET assembly ${name}…`);
        try { await dotnet(f.abs, path.join(outDir, 'dotnet', safe(name))); done++; } catch (e) { log(`${name}: ${e.message.split('\n')[0]}`, { warn: true }); }
      }
    }
    notes.push(`- **.NET (Xamarin / MAUI)**: ${dlls.length} assemblies, ${app.length} of them the app's own. ${done ? `${done} were decompiled to C# in \`dotnet/\`.` : ''} Release builds for iOS are compiled ahead of time and often have their IL removed: then the C# shows types and signatures with empty method bodies, and the logic is in the native binary.`);
  }
  if (has(/(^|\/)assemblies\/assemblies.*\.blob$/i)) {
    detected.push('.NET (Xamarin / MAUI)');
    notes.push('- **.NET for Android**: assemblies are packed in `assemblies.blob` (LZ4-compressed "XALZ" entries). Unpack them (for example with `pyxamstore`) and drop the DLLs here to decompile them to C#.');
  }

  // ---- Flutter
  if (has(/(^|\/)(App|Flutter)\.framework\/|libflutter\.so$|libapp\.so$|flutter_assets\//i)) {
    const debugKernel = files.find((f) => /flutter_assets\/kernel_blob\.bin$/i.test(f.rel));
    detected.push('Flutter');
    notes.push(`- **Flutter**: the app's Dart code is compiled ahead of time into ${has(/lib(app|flutter)\.so$/i) ? '`libapp.so`' : '`App.framework`'}, which is machine code without Dart symbols, so it can't be turned back into Dart source. Tools such as **blutter** recover the Dart class and function names from it. Assets (images, fonts, JSON) are in \`flutter_assets\`.${debugKernel ? ' **This is a debug build**: `kernel_blob.bin` contains the Dart program as kernel bytecode, including source text.' : ''}`);
  }

  // ---- Unity (IL2CPP)
  if (has(/global-metadata\.dat$|UnityFramework\.framework\/|libil2cpp\.so$|libunity\.so$/i)) {
    detected.push('Unity');
    const mono = files.some((f) => /(^|\/)Managed\/Assembly-CSharp\.dll$/i.test(f.rel));
    notes.push(mono
      ? '- **Unity (Mono)**: the game scripts are in `Assembly-CSharp.dll`, decompiled to C# in `dotnet/`.'
      : '- **Unity (IL2CPP)**: the C# game code was converted to C++ and compiled into the native binary. `global-metadata.dat` still holds every class, method and field name: **Il2CppDumper** combines it with the binary to recover the C# declarations and method addresses.');
  }
  return { detected: [...new Set(detected)], notes };
}

module.exports = { analyzeFrameworks, splitMetroBundle, isHermes };
