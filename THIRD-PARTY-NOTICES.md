# Third-party software

DropDecompiler is MIT-licensed (see [LICENSE](LICENSE)). It builds on the work below.

## Included in DropDecompiler

| Component | License | Use |
|---|---|---|
| [Electron](https://www.electronjs.org/) | MIT | Application runtime |
| [Anthropic TypeScript SDK](https://github.com/anthropics/anthropic-sdk-typescript) | Apache-2.0 | AI assistant |
| [highlight.js](https://highlightjs.org/) | BSD-3-Clause | Syntax highlighting |
| [js-beautify](https://github.com/beautifier/js-beautify) | MIT | Re-indenting minified JavaScript / CSS / HTML |
| [adm-zip](https://github.com/cthackers/adm-zip) | MIT | Reading archives |
| [richprint](https://github.com/dishather/richprint) `comp_id.txt` | BSD-2-Clause, © Dmitry Shatrov and contributors | Compiler IDs of the PE "Rich" header (`src/data/richids.json` is derived from it) |

## Downloaded on first use (not included)

Each tool is fetched from its official release (or source) the first time a file needs it, and stored in
`%APPDATA%\drop-decompiler\tools`. Their licenses apply to them.

| Tool | License | Used for |
|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Apache-2.0 | Native code (EXE, DLL, SO, Mach-O) |
| [Eclipse Temurin](https://adoptium.net/) JDK / JRE | GPL-2.0 with Classpath Exception | Running Ghidra, Vineflower, JADX, unluac |
| [Vineflower](https://github.com/Vineflower/vineflower) | Apache-2.0 | Java |
| [JADX](https://github.com/skylot/jadx) | Apache-2.0 | Android |
| [ILSpy](https://github.com/icsharpcode/ILSpy) (`ilspycmd`) | MIT | .NET |
| [unluac](https://sourceforge.net/projects/unluac/) | MIT | Lua 5.x bytecode (compiled from source) |
| [LuaJIT Decompiler v2](https://github.com/marsinator358/luajit-decompiler-v2) | MIT | LuaJIT bytecode |
| [pycdc](https://github.com/zrax/pycdc) | GPL-3.0 | Python bytecode (built from source on your PC with Visual Studio, run as a separate program) |
| [Anthropic CLI](https://github.com/anthropics/anthropic-cli) | Apache-2.0 | "Sign in with Anthropic" |

Debug symbols come from the Microsoft and NuGet symbol servers, original sources from the locations the programs
point to (Source Link, Maven Central, source maps); they belong to their authors.
