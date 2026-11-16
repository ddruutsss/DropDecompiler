# Architecture

DropDecompiler is an Electron app. The decompilation engine (`src/`) is plain Node.js with no Electron dependency
(except `src/capture.js`), so it can be used and tested from a script:

```js
const { Tools, decompile } = require('./src/core');
const tools = new Tools(process.env.APPDATA + '\\drop-decompiler\\tools');
const result = await decompile(tools, 'C:\\path\\to\\program.exe', 'C:\\output', console.log);
```

## Flow

1. **Detection** (`core.detect`): magic bytes and archive contents pick an engine (`dotnet`, `java`, `android`,
   `native`, `ios`, `lua`, `manifest`, `website`, `generic`…).
2. **Tools** (`core.Tools`): decompilers and runtimes are downloaded (or built) the first time they are needed and
   cached in `%APPDATA%\drop-decompiler\tools`.
3. **Engine**: writes the output folder.
4. **Rebuild** (`rebuild.js`, `javabuild.js`): makes .NET and Java output build again; native GUI resources.
5. **AI assistant** (`ai.js`): a Claude agent whose tools only see that output folder.

## Files

| File | Role |
|---|---|
| `main.js` | Electron main process: window, job queue, settings, file access, AI sign-in |
| `preload.js` | Safe bridge between the UI and the main process |
| `renderer/` | UI: job list, source browser, AI panel, settings page |
| `launch.js`, `DropDecompiler.bat` | Start from source |
| `src/core.js` | Detection, tool downloads, decompiler runners, original-source recovery hooks |
| `src/native.js` | Windows EXE/DLL analysis: toolchain, wrapped programs, Python decompilation |
| `src/peinfo.js` | PE headers, Rich header, imports, compiler/language/runtime detection |
| `src/wrapped.js` | Electron (asar), Node SEA, Bun/Deno, PyInstaller (CArchive, PYZ, marshal), Java overlays, Delphi DFM forms |
| `src/python/pyc_structure.py` | Rebuilds Python module structure from bytecode with the matching Python version |
| `src/msvc.js` | Finds Visual Studio and runs `cl` / `dumpbin` in its environment |
| `src/matching.js` | Matching decompilation: compile, disassemble, normalize, diff |
| `src/originals.js` | PE debug directory, symbol servers, portable PDB reader (embedded sources, Source Link), Maven sources |
| `src/rebuild.js`, `src/javabuild.js`, `src/classfile.js` | Buildable .NET solutions; recompiled Java JARs; `.class` reader |
| `src/peres.js` | Windows resources to a `.rc` script |
| `src/ios.js` | iOS apps: unpacking, images, report |
| `src/macho.js` | Mach-O reader: load commands, chained fixups, binds, code signature |
| `src/objc.js` | Objective-C class-dump |
| `src/swift.js`, `src/swiftnames.js` | Swift reflection metadata and demangling |
| `src/plist.js`, `src/nib.js` | Binary/XML property lists; compiled Interface Builder files |
| `src/frameworks.js` | React Native, Cordova/Capacitor, Xamarin/MAUI, Flutter, Unity inside apps |
| `src/website.js`, `src/capture.js` | Website download, link rewriting, source maps; the hidden browser |
| `src/lua.js`, `src/manifest.js`, `src/generic.js` | Lua; manifests (Windows, Steam, Unity); any other file |
| `src/ghidra/*.java` | Ghidra scripts: per-function export, naming from metadata, thorough analysis |
| `src/data/` | Compiler ID table (Rich header), Python standard library module list |
| `scripts/check.js` | `npm run check`: syntax check of every file |
