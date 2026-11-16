// Exports Ghidra's decompiled C for every function of the program (one file per function, in folders
// per namespace / Go package), plus README.md, functions.txt, imports.txt, exports.txt, strings.txt and
// types.h. Run headless by DropDecompiler:  -postScript DropDecompilerExport.java <outDir> [timeoutSecs]
// Progress is printed as "DDX:PROGRESS done/total" and status lines as "DDX:INFO message".
//@category DropDecompiler
//@runtime Java

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.task.TaskMonitor;

public class DropDecompilerExport extends GhidraScript {

	private static final int MAX_LIST = 12;
	private static final int MAX_STRINGS = 300000;
	private static final String[] START_NAMES = { "main", "wmain", "WinMain", "wWinMain", "_main", "DllMain",
		"main.main", "_start", "start", "entry", "WinMainCRTStartup", "wWinMainCRTStartup", "mainCRTStartup",
		"wmainCRTStartup", "_DllMainCRTStartup", "DllEntryPoint", "TlsCallback_0" };

	private Path out;
	private boolean golang;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("usage: DropDecompilerExport.java <outDir> [timeoutSecs]");
			return;
		}
		out = Paths.get(args[0]);
		int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 60;
		Files.createDirectories(out);
		if (args.length > 2 && !args[2].isEmpty()) {
			applyNames(Paths.get(args[2]));
		}
		golang = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase().contains("go");

		// Decide every function's file up front, so names are unique and stable.
		List<Function> funcs = new ArrayList<>();
		Map<Address, String> files = new HashMap<>();
		Set<String> taken = new HashSet<>();
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			if (f.isExternal() || f.isThunk()) {
				continue;
			}
			funcs.add(f);
			files.put(f.getEntryPoint(), uniquePath(f, taken));
		}
		println("DDX:INFO Decompiling " + funcs.size() + " functions…");

		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(currentProgram);
		DecompileConfigurer configurer = d -> {
			d.setOptions(options);
			d.toggleCCode(true);
			d.toggleSyntaxTree(true);
			d.setSimplificationStyle("decompile");
		};

		int total = funcs.size();
		int step = Math.max(1, (total + 49) / 50); // ~50 progress lines
		AtomicInteger done = new AtomicInteger();
		AtomicInteger failed = new AtomicInteger();
		Map<Address, Boolean> ok = new ConcurrentHashMap<>();
		DecompilerCallback<Boolean> callback = new DecompilerCallback<Boolean>(currentProgram, configurer) {
			@Override
			public Boolean process(DecompileResults res, TaskMonitor m) throws Exception {
				Function f = res.getFunction();
				boolean good = writeFunction(f, res, files.get(f.getEntryPoint()), m);
				ok.put(f.getEntryPoint(), good);
				if (!good) {
					failed.incrementAndGet();
				}
				int n = done.incrementAndGet();
				if (n % step == 0 || n == total) {
					report("DDX:PROGRESS " + n + "/" + total);
				}
				return good;
			}
		};
		callback.setTimeout(timeout);
		try {
			if (total > 0) {
				ParallelDecompiler.decompileFunctions(callback, funcs, monitor);
			}
		}
		finally {
			callback.dispose();
		}

		println("DDX:INFO Writing imports, exports, strings and types…");
		writeIndex(funcs, files, ok);
		writeImports();
		writeExports(files);
		writeStrings();
		writeTypes();
		writeReadme(funcs, files, failed.get());
		println("DDX:INFO Exported " + (total - failed.get()) + " functions as C" +
			(failed.get() > 0 ? " (" + failed.get() + " shown as assembly)" : ""));
	}

	private synchronized void report(String line) {
		println(line);
	}

	// ------------------------------------------------------------------ per function

	private boolean writeFunction(Function f, DecompileResults res, String rel, TaskMonitor m)
			throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append("// ").append(displayName(f)).append(" @ ").append(f.getEntryPoint())
				.append("  (").append(f.getBody().getNumAddresses()).append(" bytes)\n");
		appendList(sb, "// Called by: ", f.getCallingFunctions(m));
		appendList(sb, "// Calls:     ", f.getCalledFunctions(m));
		sb.append('\n');

		DecompiledFunction df = res == null ? null : res.getDecompiledFunction();
		boolean good = df != null && df.getC() != null;
		if (good) {
			sb.append(df.getC().replace("\r\n", "\n").trim()).append('\n');
		}
		else {
			String why = res == null ? "no result" : res.getErrorMessage();
			why = why == null || why.trim().isEmpty() ? "unknown error" : why.trim().replace("*/", "* /");
			sb.append("// Ghidra could not decompile this function, so its assembly is shown instead.\n");
			sb.append("// Reason: ").append(why.replace("\n", " ")).append("\n/*\n");
			InstructionIterator ins = currentProgram.getListing().getInstructions(f.getBody(), true);
			while (ins.hasNext()) {
				Instruction i = ins.next();
				sb.append(i.getAddress()).append("  ").append(i.toString().replace("*/", "* /")).append('\n');
			}
			sb.append("*/\n");
		}
		Path p = out.resolve(rel);
		Files.createDirectories(p.getParent());
		Files.write(p, sb.toString().getBytes(StandardCharsets.UTF_8));
		return good;
	}

	private static void appendList(StringBuilder sb, String label, Set<Function> set) {
		if (set == null || set.isEmpty()) {
			return;
		}
		List<String> names = new ArrayList<>();
		for (Function f : set) {
			names.add(displayName(f));
		}
		Collections.sort(names);
		sb.append(label);
		for (int i = 0; i < Math.min(MAX_LIST, names.size()); i++) {
			sb.append(i == 0 ? "" : ", ").append(names.get(i));
		}
		if (names.size() > MAX_LIST) {
			sb.append(", … (+").append(names.size() - MAX_LIST).append(" more)");
		}
		sb.append('\n');
	}

	// ------------------------------------------------------------------ file names

	/** Go repeats the package in the name ("runtime::runtime.main"); drop the namespace there. */
	private static String displayName(Function f) {
		Namespace ns = f.getParentNamespace();
		if (ns == null || ns.isGlobal() || f.getName().startsWith(ns.getName() + ".")) {
			return f.getName();
		}
		return f.getName(true);
	}

	/**
	 * Names functions from a list DropDecompiler built from the binary's own metadata (for example the
	 * Objective-C / Swift method implementations of an iOS app): one "address<TAB>class<TAB>name" per line.
	 * Only functions that still have Ghidra's placeholder names (FUN_...) are renamed.
	 */
	private void applyNames(Path file) {
		int named = 0;
		List<String> lines;
		try {
			lines = Files.readAllLines(file, StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			return;
		}
		for (String line : lines) {
			String[] parts = line.split("\t");
			if (parts.length < 3) {
				continue;
			}
			try {
				Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(parts[0], 16));
				Function f = getFunctionAt(a);
				if (f == null) {
					f = createFunction(a, null);
				}
				if (f == null) {
					continue;
				}
				// A method Ghidra filed under a mangled Swift class name ("_TtC3App7Foo") is moved to the readable one.
				Namespace current = f.getParentNamespace();
				boolean mangledHome = current != null && !current.isGlobal() && current.getName().startsWith("_Tt");
				SourceType source = f.getSymbol().getSource();
				if (!mangledHome && (source == SourceType.IMPORTED || source == SourceType.USER_DEFINED)) {
					continue;
				}
				if (!mangledHome && !f.getName().startsWith("FUN_") && source != SourceType.DEFAULT) {
					continue;
				}
				Namespace ns = NamespaceUtils.createNamespaceHierarchy(parts[1], null, currentProgram, SourceType.IMPORTED);
				if (mangledHome && !f.getName().startsWith("FUN_")) {
					// Ghidra already named the Objective-C method; only move it under the readable Swift class name.
					f.setParentNamespace(ns);
					named++;
					continue;
				}
				try {
					f.setName(parts[2], SourceType.IMPORTED);
				}
				catch (InvalidInputException e) {
					f.setName(parts[2].replaceAll("[^A-Za-z0-9_$+.-]", "_"), SourceType.IMPORTED);
				}
				f.setParentNamespace(ns);
				named++;
			}
			catch (Exception e) {
				// a bad line or a name clash: keep Ghidra's name
			}
		}
		println("DDX:INFO Named " + named + " functions from the app's Objective-C / Swift metadata");
	}

	private String uniquePath(Function f, Set<String> taken) {
		List<String> dirs = new ArrayList<>();
		String name = f.getName();
		for (Namespace ns = f.getParentNamespace(); ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
			// Go package paths ("github.com/x/y") become nested folders.
			dirs.addAll(0, golang ? Arrays.asList(ns.getName().split("/")) : Collections.singletonList(ns.getName()));
		}
		Namespace parent = f.getParentNamespace();
		if (parent != null && !parent.isGlobal() && name.startsWith(parent.getName() + ".") &&
			name.length() > parent.getName().length() + 1) {
			name = name.substring(parent.getName().length() + 1);
		}
		// Go symbols without a namespace ("github.com/x/y.(*T).Method"): group them by package.
		if (golang && dirs.isEmpty()) {
			int slash = name.lastIndexOf('/');
			int dot = name.indexOf('.', slash + 1);
			if (dot > 0) {
				dirs.addAll(Arrays.asList(name.substring(0, dot).split("/")));
				name = name.substring(dot + 1);
			}
		}
		dirs.removeIf(String::isEmpty);
		StringBuilder dir = new StringBuilder("functions/");
		int depth = 0;
		for (String d : dirs) {
			if (depth++ == 6) { // keep paths short enough for Windows
				dir.append(clean(String.join(".", dirs.subList(6, dirs.size())), 40)).append('/');
				break;
			}
			dir.append(clean(d, 40)).append('/');
		}
		String base = clean(name, 60);
		String rel = dir + base + ".c";
		if (!taken.add(rel.toLowerCase())) {
			rel = dir + base + "@" + f.getEntryPoint() + ".c";
			taken.add(rel.toLowerCase());
		}
		return rel;
	}

	private static String clean(String s, int max) {
		String c = s.replaceAll("[<>:\"/\\\\|?*\\x00-\\x1f]", "_").replaceAll("\\s+", " ").trim();
		c = c.replaceAll("[. ]+$", "");
		if (c.isEmpty()) {
			c = "_";
		}
		if (c.matches("(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\\..*)?")) {
			c = "_" + c;
		}
		if (c.length() > max) {
			c = c.substring(0, max - 9) + "~" + String.format("%08x", s.hashCode());
		}
		return c;
	}

	// ------------------------------------------------------------------ side files

	private void writeIndex(List<Function> funcs, Map<Address, String> files, Map<Address, Boolean> ok)
			throws IOException {
		try (BufferedWriter w = writer("functions.txt")) {
			w.write("Address           Size  Name  ->  File   (* = shown as assembly)\n\n");
			for (Function f : funcs) {
				Address a = f.getEntryPoint();
				w.write(String.format("%-16s %6d  %s%s  ->  %s%n", a, f.getBody().getNumAddresses(),
					Boolean.FALSE.equals(ok.get(a)) ? "*" : "", displayName(f), files.get(a)));
			}
		}
	}

	private void writeImports() throws IOException {
		Map<String, List<String>> byLib = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		SymbolIterator syms = currentProgram.getSymbolTable().getExternalSymbols();
		while (syms.hasNext()) {
			Symbol s = syms.next();
			Namespace lib = s.getParentNamespace();
			String libName = lib == null || lib.isGlobal() ? "<unknown>" : lib.getName();
			byLib.computeIfAbsent(libName, k -> new ArrayList<>()).add(s.getName());
		}
		if (byLib.isEmpty()) {
			return;
		}
		try (BufferedWriter w = writer("imports.txt")) {
			for (Map.Entry<String, List<String>> e : byLib.entrySet()) {
				Collections.sort(e.getValue(), String.CASE_INSENSITIVE_ORDER);
				w.write(e.getKey() + "  (" + e.getValue().size() + ")\n");
				for (String n : e.getValue()) {
					w.write("    " + n + "\n");
				}
				w.write("\n");
			}
		}
	}

	private void writeExports(Map<Address, String> files) throws IOException {
		List<String> lines = new ArrayList<>();
		AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
		while (it.hasNext()) {
			Address a = it.next();
			Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
			String file = files.get(a);
			lines.add(String.format("%-16s %s%s", a, s == null ? "?" : s.getName(true),
				file == null ? "" : "  ->  " + file));
		}
		if (lines.isEmpty()) {
			return;
		}
		try (BufferedWriter w = writer("exports.txt")) {
			w.write("Entry points and exported symbols\n\n");
			for (String l : lines) {
				w.write(l + "\n");
			}
		}
	}

	private void writeStrings() throws IOException {
		int n = 0;
		try (BufferedWriter w = writer("strings.txt")) {
			w.write("Strings found in the binary (address, then text)\n\n");
			DataIterator strings = DefinedStringIterator.forProgram(currentProgram);
			while (strings.hasNext()) {
				Data d = strings.next();
				String s;
				try {
					s = StringDataInstance.getStringDataInstance(d).getStringValue();
				}
				catch (Exception e) {
					s = null;
				}
				if (s == null) {
					Object v = d.getValue();
					s = v == null ? null : v.toString();
				}
				// Skip the PE/ELF header block ("MZ", ".text"…) and tiny fragments.
				MemoryBlock block = currentProgram.getMemory().getBlock(d.getAddress());
				if (s == null || s.trim().length() < 3 || (block != null && block.getName().equals("Headers"))) {
					continue;
				}
				w.write(d.getAddress() + "  " + s.replace("\r", "\\r").replace("\n", "\\n") + "\n");
				if (++n >= MAX_STRINGS) {
					w.write("… stopped after " + MAX_STRINGS + " strings\n");
					break;
				}
			}
		}
	}

	private void writeTypes() {
		try {
			StringWriter sw = new StringWriter();
			DataTypeWriter dtw = new DataTypeWriter(currentProgram.getDataTypeManager(), sw);
			dtw.write(monitor);
			String text = sw.toString().trim();
			if (!text.isEmpty()) {
				Files.write(out.resolve("types.h"), ("// Data types Ghidra knows for this program (" +
					"structures, enums, typedefs) — referenced by the decompiled code.\n\n" + text + "\n")
							.getBytes(StandardCharsets.UTF_8));
			}
		}
		catch (Exception e) {
			println("DDX:INFO Skipped types.h: " + e.getMessage());
		}
	}

	private void writeReadme(List<Function> funcs, Map<Address, String> files, int failed) throws IOException {
		Map<String, String> info = new LinkedHashMap<>();
		info.put("File", currentProgram.getName());
		info.put("Format", currentProgram.getExecutableFormat());
		info.put("Processor", currentProgram.getLanguageID().getIdAsString());
		info.put("Compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
		Map<String, String> meta = currentProgram.getMetadata();
		for (String k : new String[] { "Compiler", "PDB File", "Debug Misc", "Created With" }) {
			String v = meta.get(k);
			if (v != null && !v.isEmpty() && !"unknown".equalsIgnoreCase(v)) {
				info.put(k.equals("Compiler") ? "Compiler (detected)" : k, v);
			}
		}
		info.put("Image base", currentProgram.getImageBase().toString());
		info.put("Functions", funcs.size() + " exported" + (failed > 0 ? " (" + failed + " as assembly)" : ""));
		String sha = currentProgram.getExecutableSHA256();
		if (sha != null) {
			info.put("SHA-256", sha);
		}
		info.put("Decompiler", "Ghidra " + Application.getApplicationVersion());

		// Good places to start reading.
		Map<String, Function> byName = new HashMap<>();
		for (Function f : funcs) {
			byName.putIfAbsent(f.getName(), f);
			byName.putIfAbsent(f.getName(true), f);
		}
		List<String[]> start = new ArrayList<>();
		Set<Address> seen = new HashSet<>();
		for (String n : START_NAMES) {
			Function f = byName.get(n);
			if (f != null && seen.add(f.getEntryPoint())) {
				start.add(new String[] { displayName(f), files.get(f.getEntryPoint()) });
			}
		}
		AddressIterator eps = currentProgram.getSymbolTable().getExternalEntryPointIterator();
		int exportCount = 0;
		while (eps.hasNext() && exportCount < 25) {
			Address a = eps.next();
			if (files.containsKey(a) && seen.add(a)) {
				start.add(new String[] { displayName(currentProgram.getFunctionManager().getFunctionAt(a)), files.get(a) });
				exportCount++;
			}
		}

		// Shown as plain text in DropDecompiler's viewer, so it is laid out to read well unrendered.
		StringBuilder sb = new StringBuilder();
		sb.append("# ").append(currentProgram.getName()).append(" — decompiled with Ghidra\n\n");
		for (Map.Entry<String, String> e : info.entrySet()) {
			sb.append(String.format("    %-20s %s%n", e.getKey(), e.getValue()));
		}
		sb.append("\n## Where to start\n\n");
		if (start.isEmpty()) {
			sb.append("No entry point was identified; browse functions/.\n");
		}
		int width = 0;
		for (String[] s : start) {
			width = Math.max(width, Math.min(40, s[0].length()));
		}
		for (String[] s : start) {
			sb.append(String.format("- %-" + width + "s  %s%n", s[0], s[1]));
		}
		sb.append("\n## What's here\n\n");
		sb.append("- functions/       one .c file per function, in folders by namespace / class / package.\n");
		sb.append("                   Each file starts with the functions that call it and that it calls.\n");
		sb.append("- functions.txt    every function with its address, size and file\n");
		sb.append("- imports.txt      DLL / library functions the program uses\n");
		sb.append("- exports.txt      functions it exposes to other programs\n");
		sb.append("- strings.txt      text found in the binary (search it, then find the address in the code)\n");
		sb.append("- types.h          structures and types used by the decompiled code\n");
		sb.append("\n## Reading the output\n\n");
		sb.append("This is NOT the original source code: compiling throws that away. Ghidra rebuilt\n");
		sb.append("C-like pseudo-code from the machine code. The logic and control flow are accurate, but:\n\n");
		sb.append("- names like FUN_00401000, local_10 and param_1 are placeholders\n");
		sb.append("- types like undefined4 mean \"4 bytes, type unknown\"\n");
		sb.append("- it will not compile as-is\n\n");
		sb.append("Real names come from exports, debug symbols (.pdb), C++ RTTI, Go/Rust symbol tables\n");
		sb.append("or known library signatures.\n");
		Files.write(out.resolve("README.md"), sb.toString().getBytes(StandardCharsets.UTF_8));
	}

	private BufferedWriter writer(String name) throws IOException {
		return Files.newBufferedWriter(out.resolve(name), StandardCharsets.UTF_8);
	}
}
