// DropDecompiler "thorough analysis": turns on Ghidra analyzers that are off by default because they are slow,
// but make the decompiled code closer to the original source (real parameter counts and types, return types).
// Runs as a headless pre-script, before auto-analysis.
//@category DropDecompiler
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class DropDecompilerThorough extends GhidraScript {

	private static final String[] ANALYZERS = {
		"Decompiler Parameter ID", // infers parameters / return values of every function with the decompiler
		"Shared Return Calls", // tail calls become calls, so functions aren't merged into their callers
	};

	@Override
	protected void run() throws Exception {
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		for (String name : ANALYZERS) {
			if (options.containsKey(name)) {
				setAnalysisOption(currentProgram, name, "true");
				println("DDX:INFO Thorough analysis: " + name + " enabled");
			}
		}
	}
}
