# Formats

What DropDecompiler does with each kind of input, and what the output folder contains. Every output folder has a
`README.md` (or `BUILD.md`) that the viewer opens first.

- [.NET](#net) · [Java](#java) · [Android](#android) · [iOS](#ios-apps-ipa) · [Native code](#native-code-exe-dll-so-mach-o)
- [Python, Electron and other wrapped programs](#wrapped-programs) · [Websites](#websites) · [Lua](#lua)
- [Manifests](#manifests) · [Anything else](#anything-else) · [Cross-platform apps](#cross-platform-apps)

## .NET

`.dll` `.exe` `.winmd`, `.nupkg`, and .NET **single-file** apps (an `.exe` that looks native but carries assemblies).

[ILSpy](https://github.com/icsharpcode/ILSpy) writes a C# project: WinForms forms with their `InitializeComponent`
layout code, WPF windows as `.xaml`, `.resx` resources, the icon and the manifest. DropDecompiler then makes it build:

- a Visual Studio solution (`.sln`) and `build.bat`; single-file apps and NuGet packages get one project per assembly,
  wired together with project references
- third-party DLLs the program uses are copied to `lib\`, so the project builds on any machine
- the target framework is fixed (programs that only say ".NET 4.x" move from `net40` to `net48`)
- it is **test-built with `dotnet build`**, and known decompiler mistakes are fixed between attempts
- the rebuilt program goes to `rebuilt\`; `BUILD.md` lists what was changed and any errors left

The viewer shows **✓ Builds** or the number of errors left. Edit the code and press **Rebuild**.

When the assembly has a PDB (next to it, embedded, or on the NuGet / Microsoft symbol servers), ILSpy uses the
original local variable names, and the original source files are recovered into `original-source/` when they are
embedded or linked with Source Link. See [Accuracy](ACCURACY.md).

## Java

`.jar` `.war` `.ear` `.class` `.jmod`, or a `.zip` of classes, decompiled by
[Vineflower](https://github.com/Vineflower/vineflower) with the jar's bundled libraries as context.

**Archives come out as a rebuilt JAR that is always the complete program.** Every class is recompiled with `javac`
(for the Java version the original targets) against the original JAR and its libraries. A class that doesn't compile
yet, or that lost a member the rest of the program uses, is taken from the original JAR unchanged, so
`rebuilt\<name>.jar` always works. Each class you fix in `src\` and **Rebuild** moves from "kept" to "recompiled";
`BUILD.md` lists the kept classes with their first compiler error.

Libraries that publish sources (a `-sources.jar` next to the jar, or on Maven Central) get their exact original
source in `original-source/`.

## Android

`.apk` `.aab` `.aar` `.dex` `.xapk` `.apks` `.apkm`, decompiled by [JADX](https://github.com/skylot/jadx) into an
Android Studio (Gradle) project: Java source, decoded resources, `AndroidManifest.xml`.

- A ProGuard / R8 **`mapping.txt`** next to the APK (or the one inside an `.aab`) restores the original class, method
  and field names of an obfuscated app.
- Kotlin names are restored from Kotlin metadata and `SourceDebugExtension`.
- Optional: readable placeholder names for obfuscated code without a mapping file (Settings).
- Cross-platform apps are detected (see [below](#cross-platform-apps)); findings go to `FRAMEWORKS.md`.

## iOS apps (.ipa)

DropDecompiler reads the app's Mach-O binaries itself (both pointer formats: chained fixups, arm64e included, and
classic binds), so what the compiler kept is recovered exactly:

| Folder | Contents |
|---|---|
| `headers/<binary>/` | **Objective-C headers** of every class, category and protocol, like class-dump: superclass, protocols, ivars with offsets, properties with attributes, every method with its types and implementation address. Swift classes show the Swift type of each stored property. |
| `swift/<binary>/<Module>.swift` | **Swift interfaces** from the reflection metadata: classes, structs, enums and protocols with stored properties (`let`/`var`, `weak`, exact types like `[String: Any]` or `(any Delegate)?`), enum cases, superclasses and conformances (`Codable`, `Hashable`, `View`…). One file per module: the app, each Swift package compiled into it, and imported C/Objective-C types. |
| `code/` | **Ghidra pseudo-C** of the executable, with functions named after the Objective-C/Swift methods they implement (`ReaderViewController::viewDidLoad`) and Swift vtable entries grouped under their class. Optional (Settings), it can take 10+ minutes. |
| `app/` | Every file of the bundle; binary plists, `.strings` and compiled `.nib` files decoded to text. |
| `info/` | `Info.plist`, entitlements, provisioning profile, linked libraries, URLs found in the executable, possible hardcoded secrets. |
| `README.md` | An analysis report: identity, build (Xcode, SDK), signing and provisioning type, permissions with the text shown to the user, capabilities, URL schemes, App Transport Security exceptions, hosts it talks to, third-party SDKs, frameworks and extensions. |

Frameworks and app extensions get their own headers and Swift interfaces. App Store downloads are encrypted with
FairPlay: their code can only be read after the app is decrypted on a device it is installed on. The report says so,
and everything else is still extracted.

## Native code (EXE, DLL, SO, Mach-O)

Programs compiled to machine code (C, C++, Go, Rust, Delphi…) are analysed with
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) in headless mode. First, DropDecompiler finds out what the
program really is (`TOOLCHAIN.md`): compiler and exact Visual Studio version from the "Rich" header, number of C / C++
/ assembler object files, the original project folder from the PDB path, the language, and whether it is really a
launcher for another runtime (see [wrapped programs](#wrapped-programs)).

| File | Contents |
|---|---|
| `README.md` | Overview: format, CPU, compiler, entry points to start reading from, toolchain. |
| `functions/` | One `.c` file per function, in folders by namespace / class / Go package. Each file starts with its callers and callees. Functions the decompiler can't handle show their assembly. |
| `functions.txt`, `imports.txt`, `exports.txt`, `strings.txt`, `types.h` | Indexes of the program. |
| `resources/app.rc` | The Windows GUI (dialogs, menus, strings, version info, icons…) as a resource script, checked to recompile byte-for-byte with `rc.exe` when the Windows SDK is installed. |
| `headers/`, `swift/` | For Mach-O files: Objective-C headers and Swift interfaces, as for iOS apps. |

Names come from wherever the binary still carries them: exports, a PDB (next to the file, or downloaded from
Microsoft's symbol server), C++ RTTI (classes, vtables and `this` types are rebuilt for MSVC programs), Go and Rust
symbol tables, Objective-C/Swift metadata. Analysis is the slow step: small tools take under a minute, a 50 MB binary
10+ minutes.

The pseudo-C doesn't compile as is. To get real, verified source, use the AI assistant with
[matching decompilation](ACCURACY.md#matching-decompilation).

## Wrapped programs

Many EXEs aren't native programs: they are a runtime or launcher with the real program inside. DropDecompiler
extracts it instead of decompiling the launcher:

| Program | What you get |
|---|---|
| **PyInstaller** (Python) | Every module as a valid `.pyc` (`pyc/`), and the app's own modules as Python in `original-source/`: decompiled with [pycdc](https://github.com/zrax/pycdc) (built on first use when Visual Studio and CMake are installed), or rebuilt by the matching Python version: exact imports, classes, decorators, signatures with defaults, docstrings, and each function's bytecode. |
| **Electron** | The app's JavaScript, HTML and CSS from `resources/app.asar` (byte-exact), in `original-source/app/`. |
| **Node.js single executable apps** | The embedded main script. |
| **Bun / Deno** compiled executables | The embedded module sources. |
| **Java in an EXE** (Launch4j and similar) | The embedded JAR, decompiled as Java into `java/`. |
| **Delphi / C++Builder** | The UI forms decoded back to `.dfm` text in `forms/`, with their event handler names (plus the Ghidra output). |

Installers (NSIS, Inno Setup, WiX, InstallShield, self-extracting archives), packers and protectors (UPX, Themida,
VMProtect, ASPack, Enigma, MPRESS, PECompact), AutoIt, VB6, Qt, MFC, Unity and Unreal are identified, with what to do
next.

## Websites

Drop a link, paste one with `Ctrl+V`, or type it in the link bar. The page opens in a hidden, sandboxed browser with a
throw-away session (none of your cookies or logins; downloads, pop-ups and permission requests refused). Every
response is recorded, the page is scrolled so lazy content loads, and links on the same site are followed up to the
page limit (robots.txt is respected for every page after the first).

| Folder | Contents |
|---|---|
| `site/` | Every file exactly as the server sent it, with links rewritten so it opens offline. |
| `snapshot/` | Each page as it looked after its scripts ran, scripts removed. |
| `sources/` | **Original source files** (TypeScript, JSX, Vue, SCSS…) from source maps, including maps the site doesn't link to. |
| `beautified/` | Minified JS / CSS / HTML re-indented. |
| `resources.csv` | Every URL with status, type, size and local file. |

Only what a browser receives can be downloaded: server-side code never leaves the server.

## Lua

`.lua` `.luac` and Lua bytecode (5.0–5.4) are decompiled with [unluac](https://sourceforge.net/projects/unluac/)
(compiled from source on first use), LuaJIT bytecode with
[LuaJIT Decompiler v2](https://github.com/marsinator358/luajit-decompiler-v2). Plain scripts are copied; obfuscated
or encrypted ones are flagged; a `.zip` of scripts works too.

## Manifests

- **Windows / .NET manifests**: decoded (UTF-16 → UTF-8), re-indented and explained (execution level, DPI awareness,
  supported Windows versions, dependencies).
- **Steam depot manifests**: the file list with sizes, flags and hashes (`files.txt`, `files.csv`). Encrypted file
  names are decrypted when the depot key is in a file next to the manifest (Steam's `config.vdf`, a `.lua` with
  `addappid(<depot>, 1, "<key>")`, or `<depot>;<key>`); nothing is guessed. A manifest only lists files:
  DropDecompiler does not download depot content.
- Unity and other text manifests are copied as readable text.

## Anything else

Any other file is identified (type, hashes, entropy), and what can be read is saved: decoded text, strings, a hex
dump, archive contents. The AI assistant can then explain the format.

## Cross-platform apps

Inside iOS and Android packages:

- **React Native**: the JavaScript bundle is split back into its modules and re-indented; Hermes bytecode is
  identified and its strings extracted.
- **Cordova / Capacitor / Ionic**: the web app (the actual source) is in `web-app/`.
- **Xamarin / .NET MAUI**: assemblies are decompiled to C#; compressed Android assemblies are identified.
- **Flutter** and **Unity (IL2CPP)**: identified, with the tools that go further.
