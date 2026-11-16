# Accuracy

Decompiled code is a reconstruction: compiling throws away names, comments, formatting and structure. DropDecompiler
gets as close to the original as each program allows, in this order:

1. **Get the original itself** when the program still points to it (debug symbols, embedded or published sources).
2. **Extract the real program** when the EXE is only a launcher (Python, Electron, Java…).
3. **Recover everything the compiler kept** (metadata, RTTI, symbols) so names and types are exact.
4. **Prove rewritten code against the original machine code** with matching decompilation.

## 1. Original sources and debug symbols

Switches in **Settings → Decompilers**. `ORIGINAL-SOURCE.md` in the output lists what was found.

| | Recovered | From |
|---|---|---|
| .NET | **The exact source files** (`original-source/<assembly>/`) and the original local variable names | Sources embedded in the PDB; Source Link (GitHub, GitLab, Azure DevOps…); PDBs on the NuGet and Microsoft symbol servers |
| Java | **The exact source files** of libraries | A `<name>-sources.jar` next to the jar, or the `-sources.jar` on Maven Central (from the jar's `pom.properties`) |
| Android | **Original class, method and field names** of obfuscated apps | A ProGuard / R8 `mapping.txt` next to the APK, or the one inside an `.aab` |
| Native | **Real function names, types and structures** | The program's PDB on Microsoft's symbol server (Windows and Microsoft programs) |
| Websites | **Original source files** (TypeScript, JSX, Vue, SCSS…) | Source maps, including unlinked `.map` files and sources a map only references |

Measured on real files: Newtonsoft.Json 13.0.3 → all 235 original `.cs` files in about 2 s (NuGet symbols + Source
Link); commons-lang3 3.17.0 → 249 original `.java` files; `hostname.exe` → every function named from Microsoft's PDB.

Downloading symbols sends the program's debug ID (a GUID) to Microsoft's / NuGet's symbol server; it can be turned
off.

## 2. Wrapped programs

See [Formats → wrapped programs](FORMATS.md#wrapped-programs). For these, the result is the program's own language:
Python modules, JavaScript files (byte-identical for Electron), Java classes, Delphi forms.

## 3. Everything the compiler kept

- **Toolchain** (`TOOLCHAIN.md`): the PE "Rich" header records every compiler build that produced the object files,
  so the exact Visual Studio version and the number of C, C++ and assembler objects are known; the PDB path in the
  debug directory reveals the original project folder and configuration (`C:\src\MyApp\x64\Release\MyApp.pdb`).
  GCC/MinGW, Clang/LLVM, Go, Rust, Delphi, Nim and Zig are recognized too.
- **C++**: for MSVC programs with RTTI, Ghidra's class recovery rebuilds classes, vtables, constructors/destructors
  and `this` types before decompiling.
- **Objective-C and Swift**: exact class/method/property/type names and Swift stored-property types from the metadata
  (see [iOS](FORMATS.md#ios-apps-ipa)); decompiled functions are named after the methods they implement.
- **Python**: imports, classes, decorators with arguments, signatures with defaults, keyword-only and positional-only
  parameters, and docstrings are rebuilt exactly from the bytecode.

## 4. Matching decompilation

The most accurate way to recover native C/C++ is the technique game-decompilation projects use: write C, compile it
with the same compiler, and compare the machine code with the original **until it is identical**. A function whose
source compiles to the original instructions is, for all practical purposes, the original source.

DropDecompiler gives the AI assistant a `compile_and_compare` tool for Windows programs built with Microsoft C/C++
when Visual Studio (with the C++ workload) is installed:

1. The function's original instructions are disassembled from the EXE/DLL with `dumpbin`.
2. The rewritten C/C++ is compiled with `cl` under the usual Release/Debug settings (`/O2`, `/O1`, `/Od`, with and
   without `/GS`) and disassembled the same way.
3. Both are normalized: jumps inside the function become instruction indexes, references to other functions and
   data become `ref`, and alignment padding is ignored. Everything else (instructions, registers, immediates, stack
   offsets) must be identical.
4. The result is **EXACT MATCH** or a similarity score with the differing instructions, which the assistant uses
   to adjust the code (operand order, loop shape, types, signedness…) and try again.

Results are recorded in `ai/MATCHING.md`, and the best version of each function is saved in `ai/matched/`.

Tested on a program compiled with `/O2`: the original source of two functions matched exactly (78 and 39
instructions, including a vectorized loop); a rewrite with the same behaviour but different code scored 6.5%; swapping
two arguments of one call scored 94.9%, with exactly the two differing register moves reported.

Limits: exact matches need the same compiler generation as the original (`TOOLCHAIN.md` names it; older MSVC
toolsets can be added in the Visual Studio Installer). Link-time code generation (`/GL`) and profile-guided
optimization can inline or split functions across source files, which makes some functions unmatchable one at a
time.

## What can't be recovered

- Comments, local variable names and formatting of native code without symbols.
- Server-side code of websites.
- Code of encrypted apps (App Store FairPlay) without decrypting them on a device.
- Programs protected by virtualizing protectors (VMProtect, Themida), beyond identifying them.
