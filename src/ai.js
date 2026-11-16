// AI assistant: a Claude agent that works inside one decompiled output folder. It can list, read and
// search the decompiled files (and peek at the original input), and writes what it reconstructs into
// the folder's `ai/` subfolder, so the source browser shows it next to the decompiler's output.
// Plain Node (no Electron); main.js owns the API key and forwards events to the UI.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const sdk = require('@anthropic-ai/sdk');

const Anthropic = sdk.default || sdk;

const MODELS = {
  'claude-opus-5-5': { name: 'Claude Opus 5.5', input: 4, output: 20, cacheRead: 0.2, fallbacks: true },
  'claude-sonnet-5-5': { name: 'Claude Sonnet 5.5', input: 2, output: 10, cacheRead: 0.1, fallbacks: true },
  'claude-haiku-5-5': { name: 'Claude Haiku 5.5', input: 0.1, output: 0.5, cacheRead: 0.01, fallbacks: false },
};
const DEFAULT_MODEL = 'claude-opus-5-5';

const AI_DIR = 'ai';
const MAX_READ = 120 * 1024; // characters returned by one read_file call
const MAX_LIST = 3000;
const MAX_HITS = 300;
const MAX_TURNS = { chat: 30, reconstruct: 80 };
const SKIP = /(^|\/)(bin|obj|node_modules|\.vs|build)\//;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|bmp|cur|ani|so|dll|exe|jar|zip|class|dex|arsc|ttf|otf|woff2?|mp3|ogg|wav|mp4|bin|dat|db|pdb|res|lib|obj|7z|rar|gz)$/i;

// ---------------------------------------------------------------- prompt

const SYSTEM = `You are the reverse-engineering assistant built into DropDecompiler, a desktop app that decompiles programs and files (.NET, Java, Android, native code through Ghidra, Lua bytecode, manifests, whole websites and any other file) into a folder the user browses.
If the folder has original-source/ (see ORIGINAL-SOURCE.md), those are the exact files the authors wrote, recovered from debug symbols, Source Link or Maven Central: read them first, and use the decompiled code only for what they don't cover.
For an iOS app: headers/<image>/ has exact Objective-C headers (class-dump, with IMP addresses), swift/<image>/<Module>.swift has the exact Swift types and stored properties, code/ has Ghidra pseudo-C named Class::selector, app/ has decoded plists/strings/nibs, info/ has entitlements and URLs. Rebuild Swift from these: types and properties are exact, method bodies come from the pseudo-C.
For a website, the folder holds the downloaded site (site/), rendered snapshots (snapshot/), original sources recovered from source maps (sources/, prefer these over bundles when present) and re-indented minified files (beautified/).

You work on ONE output folder. Your tools read that folder, search it, look at raw bytes of the original input file, and write files into its "${AI_DIR}/" subfolder. You cannot run code.

How to work:
- Look before you answer. Start from README.md / BUILD.md if present, then list and read the files that matter. Read files in full rather than guessing from names.
- Decompiler output has lost names, comments and structure. Recover them from evidence: strings, API calls, imports, call graphs, constants, resource names, error messages. Say how sure you are when a name or purpose is a guess.
- Native code from Ghidra is pseudo-C with placeholder names (FUN_00401000, param_1, local_10). Prioritise entry points, exported functions and functions that use interesting strings or APIs; skip library/CRT code (compiler runtime, statically linked libraries) unless asked.

When asked to reconstruct or rewrite code:
- Write clean, readable source into "${AI_DIR}/" with write_file, organised like a real project (for example ${AI_DIR}/src/..., one file per module or class). Use the original language when it is a high-level language (C#, Java, Kotlin, Lua). For native code write idiomatic C or C++ (C++ when RTTI/classes are present).
- Keep the behaviour exactly the same: same logic, same constants, same strings, same order of side effects. Improve names, types, structure and comments only. Never invent features. Mark anything uncertain with a "// ?" comment.
- Give functions and variables meaningful names, recover structs/enums where the evidence supports them, and add a short comment above each function saying what it does.
- Always finish a reconstruction by writing ${AI_DIR}/README.md: what the program is and does, how it is organised, the mapping from original names (FUN_..., obfuscated names) to your names, what you could not recover, and how to build it.
- Large programs: cover the program's own code first (main logic, UI, networking, file formats), most important first, and say what is left out.

Answer in the language the user writes in. Be concise in chat: the reconstructed files hold the detail. Refer to files by their path in the folder.`;

const MATCH_PROMPT = `

Matching decompilation is available (compile_and_compare). For native Windows code it is the way to get the ORIGINAL source back: a function whose rewrite compiles to exactly the original instructions is equivalent to what its authors wrote.
- When you rewrite a function of the program's own code (not the C runtime or a library), compare it. Read the differences (registers, operation order, loop shape, types and signedness, inlined helpers) and adjust the C to remove them: compilers are deterministic, so each difference points to a difference in the source.
- Keep going until EXACT MATCH or until three attempts in a row stop improving; then keep the best version. Start with small functions: they match fastest and reveal the types and conventions the program uses.
- Use the toolchain in README.md / TOOLCHAIN.md (C or C++, Visual Studio version) to choose the language. Exact matches need the same compiler generation; a different one can leave small differences.
- Every result is recorded in ${AI_DIR}/MATCHING.md and the best code in ${AI_DIR}/matched/. In your summary, say how many functions match exactly.`;

/** Matching needs the original Windows PE, Ghidra's functions.txt and Visual Studio's C++ tools. */
async function matchingAvailable(root, inputFile) {
  if (!inputFile) return false;
  try {
    const fh = await fsp.open(inputFile, 'r');
    const b = Buffer.alloc(2);
    await fh.read(b, 0, 2, 0);
    await fh.close();
    if (b.toString('latin1') !== 'MZ') return false;
    if (!fs.existsSync(path.join(root, 'functions.txt')) && !fs.existsSync(path.join(root, 'code', 'functions.txt'))) return false;
    return !!(await require('./msvc').findVs());
  } catch { return false; }
}

const RECONSTRUCT_PROMPT =`Analyse this decompiled program and reconstruct it as clean, readable source code in the ${AI_DIR}/ folder, following your reconstruction rules. When you are done, reply with a short summary of what the program does and what you wrote.`;

function jobContext(job) {
  const lines = ['Output folder for this conversation:'];
  if (job.name) lines.push(`- Original file: ${job.name}`);
  if (job.engineName) lines.push(`- Decompiler used: ${job.engineName} (${job.engine})`);
  if (job.label) lines.push(`- Detected type: ${job.label}`);
  if (job.inputAvailable) lines.push('- The original input file is available through read_original.');
  return lines.join('\n');
}

// ---------------------------------------------------------------- tools

const TOOLS = [
  {
    name: 'list_files',
    description: 'List files in the output folder (paths relative to it, with sizes). Optionally only under a subfolder and/or whose path contains a text.',
    input_schema: {
      type: 'object',
      properties: {
        dir: { type: 'string', description: 'Subfolder to list, e.g. "functions/main". Empty for the whole folder.' },
        contains: { type: 'string', description: 'Only paths containing this text (case-insensitive).' },
      },
      required: [],
    },
  },
  {
    name: 'read_file',
    description: `Read a text file from the output folder, with line numbers. At most ${MAX_READ / 1024} KB per call: use start_line / end_line for big files.`,
    input_schema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path relative to the output folder.' },
        start_line: { type: 'integer', description: 'First line to read (1-based).' },
        end_line: { type: 'integer', description: 'Last line to read (inclusive).' },
      },
      required: ['path'],
    },
  },
  {
    name: 'search',
    description: 'Search all text files of the output folder with a JavaScript regular expression (case-insensitive). Returns matching lines as path:line: text.',
    input_schema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Regular expression.' },
        dir: { type: 'string', description: 'Only search under this subfolder.' },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'read_original',
    description: 'Look at the raw bytes of the original input file: a hex dump of a range, or the printable strings it contains.',
    input_schema: {
      type: 'object',
      properties: {
        mode: { type: 'string', enum: ['hex', 'strings'] },
        offset: { type: 'integer', description: 'Start offset in bytes (default 0).' },
        length: { type: 'integer', description: 'Bytes to read (hex: max 4096, strings: max 4 MB).' },
      },
      required: ['mode'],
    },
  },
  {
    name: 'write_file',
    description: `Create or overwrite a text file in the ${AI_DIR}/ subfolder of the output folder. Paths are relative to ${AI_DIR}/ (a leading "${AI_DIR}/" is accepted).`,
    eager_input_streaming: true,
    input_schema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: `Path inside ${AI_DIR}/, e.g. "src/main.c".` },
        content: { type: 'string', description: 'Full file content.' },
      },
      required: ['path', 'content'],
    },
  },
];

// Matching decompilation (Windows EXE/DLL built with Microsoft C/C++, when Visual Studio is installed).
const MATCH_TOOL = {
  name: 'compile_and_compare',
  description: 'Compiles a C or C++ rewrite of one function of the original Windows program with Microsoft C/C++ and compares the generated machine code with the original, instruction by instruction (registers, constants and control flow must match; addresses of other functions/data are ignored). Returns "EXACT MATCH" when the code is equivalent to the original source, otherwise a similarity score and the differing instructions. Include every type, struct and declaration the function needs; declare called functions (their bodies are not compared).',
  eager_input_streaming: true,
  input_schema: {
    type: 'object',
    properties: {
      function: { type: 'string', description: 'The function to compare: its name in functions.txt, its address (hex), or its file (functions/…c).' },
      code: { type: 'string', description: 'Complete compilable source: declarations plus the function definition.' },
      language: { type: 'string', enum: ['c', 'cpp'], description: 'c (default) or cpp.' },
      flags: { type: 'string', description: 'Compiler flags such as "/O2 /GS-". Leave out to try the usual Release/Debug settings.' },
    },
    required: ['function', 'code'],
  },
};

const SCHEMAS = Object.fromEntries([...TOOLS, MATCH_TOOL].map((t) => [t.name, t.input_schema]));

/** Checks a tool input against its schema (streamed inputs are not validated by the API). */
function validate(name, input) {
  const schema = SCHEMAS[name];
  if (!schema) return `Unknown tool "${name}"`;
  if (!input || typeof input !== 'object' || Array.isArray(input)) return 'Input must be an object';
  for (const k of schema.required) if (!(k in input)) return `Missing "${k}"`;
  for (const [k, v] of Object.entries(input)) {
    const p = schema.properties[k];
    if (!p) return `Unknown field "${k}"`;
    if (p.type === 'string' && typeof v !== 'string') return `"${k}" must be a string`;
    if (p.type === 'integer' && !Number.isInteger(v)) return `"${k}" must be an integer`;
    if (p.enum && !p.enum.includes(v)) return `"${k}" must be one of ${p.enum.join(', ')}`;
  }
  return null;
}

function inside(root, rel) {
  const full = path.resolve(root, String(rel || '').replace(/^[\\/]+/, ''));
  if (full !== root && !full.startsWith(root + path.sep)) throw new Error('Path is outside the output folder');
  return full;
}

async function walk(root, sub) {
  const out = [];
  const start = inside(root, sub);
  async function go(dir) {
    let ents;
    try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (out.length >= 20000) return;
      const full = path.join(dir, e.name);
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (rel === '.dropdecompiler.json') continue;
      if (e.isDirectory()) { if (!SKIP.test(rel + '/')) await go(full); } else out.push(rel);
    }
  }
  await go(start);
  return out.sort();
}

function isBinary(buf) {
  return buf.subarray(0, 8000).includes(0);
}

function extractStrings(buf, min = 5) {
  const out = [];
  let cur = '';
  let start = 0;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) {
      if (!cur) start = i;
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= min) out.push(`0x${start.toString(16)}: ${cur}`);
      cur = '';
    }
  }
  if (cur.length >= min) out.push(`0x${start.toString(16)}: ${cur}`);
  // UTF-16LE strings (Windows programs)
  cur = '';
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const c = buf[i];
    if (buf[i + 1] === 0 && c >= 0x20 && c < 0x7f) {
      if (!cur) start = i;
      cur += String.fromCharCode(c);
    } else {
      if (cur.length >= min) out.push(`0x${start.toString(16)} (utf16): ${cur}`);
      cur = '';
    }
  }
  return out;
}

function hexDump(buf, base) {
  const lines = [];
  for (let i = 0; i < buf.length; i += 16) {
    const row = buf.subarray(i, i + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${(base + i).toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join('\n');
}

async function runTool(ctx, name, input) {
  const { root } = ctx;
  if (name === 'list_files') {
    let files = await walk(root, input.dir || '');
    if (input.contains) files = files.filter((f) => f.toLowerCase().includes(input.contains.toLowerCase()));
    const total = files.length;
    files = files.slice(0, MAX_LIST);
    const sized = await Promise.all(files.map(async (f) => {
      const st = await fsp.stat(path.join(root, f)).catch(() => null);
      return `${f}  (${st ? st.size.toLocaleString('en') : '?'} bytes)`;
    }));
    return (sized.join('\n') || '(no files)') + (total > MAX_LIST ? `\n… ${total - MAX_LIST} more files: narrow with dir / contains.` : '');
  }

  if (name === 'read_file') {
    const full = inside(root, input.path);
    const buf = await fsp.readFile(full);
    if (isBinary(buf)) return `Binary file (${buf.length.toLocaleString('en')} bytes). Use read_original for the input file, or another file.`;
    const lines = buf.toString('utf8').split(/\r?\n/);
    const from = Math.max(1, input.start_line || 1);
    const to = Math.min(lines.length, input.end_line || lines.length);
    let out = '';
    let n = from;
    for (; n <= to; n++) {
      const line = `${n}\t${lines[n - 1]}\n`;
      if (out.length + line.length > MAX_READ) break;
      out += line;
    }
    const header = `${input.path} — lines ${from}-${n - 1} of ${lines.length}`;
    return header + '\n' + out + (n <= to ? `… truncated: continue with start_line=${n}` : '');
  }

  if (name === 'search') {
    let re;
    try { re = new RegExp(input.pattern, 'i'); } catch (e) { throw new Error('Invalid regular expression: ' + e.message); }
    const files = (await walk(root, input.dir || '')).filter((f) => !BINARY_EXT.test(f));
    const hits = [];
    for (const f of files) {
      if (hits.length >= MAX_HITS) break;
      const buf = await fsp.readFile(path.join(root, f)).catch(() => null);
      if (!buf || buf.length > 8 * 1024 * 1024 || isBinary(buf)) continue;
      const text = buf.toString('utf8');
      if (!re.test(text)) continue;
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length && hits.length < MAX_HITS; i++) {
        if (re.test(lines[i])) hits.push(`${f}:${i + 1}: ${lines[i].trim().slice(0, 240)}`);
      }
    }
    return hits.length ? hits.join('\n') + (hits.length >= MAX_HITS ? '\n… more matches: narrow the pattern or dir.' : '') : 'No matches.';
  }

  if (name === 'read_original') {
    if (!ctx.inputFile) throw new Error('The original input file is not available for this folder.');
    const fh = await fsp.open(ctx.inputFile, 'r');
    try {
      const { size } = await fh.stat();
      const offset = Math.max(0, Math.min(size, input.offset || 0));
      const max = input.mode === 'hex' ? 4096 : 4 * 1024 * 1024;
      const len = Math.max(0, Math.min(input.length || (input.mode === 'hex' ? 512 : max), max, size - offset));
      const buf = Buffer.alloc(len);
      await fh.read(buf, 0, len, offset);
      if (input.mode === 'hex') return `File size ${size.toLocaleString('en')} bytes\n` + hexDump(buf, offset);
      const strs = extractStrings(buf).map((s) => s.replace(/^0x([0-9a-f]+)/, (_m, h) => '0x' + (parseInt(h, 16) + offset).toString(16)));
      let out = strs.join('\n');
      if (out.length > MAX_READ) out = out.slice(0, MAX_READ) + '\n… truncated: read a smaller range.';
      return `File size ${size.toLocaleString('en')} bytes, strings in 0x${offset.toString(16)}-0x${(offset + len).toString(16)}:\n` + (out || '(none)');
    } finally {
      await fh.close();
    }
  }

  if (name === 'write_file') {
    const rel = input.path.replace(/\\/g, '/').replace(/^\/+/, '').replace(new RegExp(`^${AI_DIR}/`), '');
    const aiRoot = path.join(root, AI_DIR);
    const full = inside(aiRoot, rel);
    if (full === aiRoot) throw new Error('A file name is required');
    await fsp.mkdir(path.dirname(full), { recursive: true });
    await fsp.writeFile(full, input.content);
    const relOut = path.relative(root, full).split(path.sep).join('/');
    ctx.onFile(relOut);
    return `Wrote ${relOut} (${input.content.split('\n').length} lines)`;
  }

  if (name === 'compile_and_compare') {
    if (!ctx.inputFile) throw new Error('The original program is not available for this folder.');
    const matching = require('./matching');
    const fn = await matching.findFunction(root, input.function);
    if (!fn) throw new Error(`Function "${input.function}" was not found in functions.txt (use its name, its address, or its file).`);
    const r = await matching.compare({ binary: ctx.inputFile, va: fn.va, size: fn.size, code: input.code, lang: input.language, flags: input.flags, name: fn.name.split('::').pop() });
    if (r.errors && !r.score) return `Compilation failed:\n${r.errors}`;
    await recordMatch(ctx, fn, input, r);
    const pct = (r.score * 100).toFixed(1);
    if (r.exact) return `EXACT MATCH with ${r.flags}: all ${r.originalCount} instructions are identical to the original. Saved as ${AI_DIR}/matched/${matchFile(fn)}.`;
    return `${pct}% similar with ${r.flags} (original ${r.originalCount} instructions, yours ${r.yoursCount}). Lines "-" are only in the original, "+" only in yours:\n${r.diff}`;
  }

  throw new Error(`Unknown tool "${name}"`);
}

const matchFile = (fn) => `${fn.name.replace(/::/g, '.').replace(/[<>:"/\\|?*\s]/g, '_').slice(0, 100)}.${fn.file && /\.cpp$/.test(fn.file) ? 'cpp' : 'c'}`;

/** Keeps the best attempt per function in ai/matched/ and a summary table in ai/MATCHING.md. */
async function recordMatch(ctx, fn, input, r) {
  const dir = path.join(ctx.root, AI_DIR);
  const stateFile = path.join(dir, 'matching.json');
  let state = {};
  try { state = JSON.parse(await fsp.readFile(stateFile, 'utf8')); } catch { /* first result */ }
  const key = fn.va.toString(16);
  const prev = state[key];
  if (prev && prev.score >= r.score) return;
  state[key] = { name: fn.name, va: key, score: r.score, exact: r.exact, flags: r.flags, file: matchFile(fn) };
  await fsp.mkdir(path.join(dir, 'matched'), { recursive: true });
  const head = `// ${fn.name} at 0x${key}: ${r.exact ? 'EXACT MATCH with the original machine code' : `${(r.score * 100).toFixed(1)}% similar to the original machine code`} (Microsoft C/C++ ${r.flags}).\n// Verified by DropDecompiler's compile-and-compare.\n\n`;
  await fsp.writeFile(path.join(dir, 'matched', matchFile(fn)), head + input.code);
  await fsp.writeFile(stateFile, JSON.stringify(state, null, 1));
  const rows = Object.values(state).sort((a, b) => b.score - a.score);
  const exact = rows.filter((x) => x.exact).length;
  await fsp.writeFile(path.join(dir, 'MATCHING.md'), [
    '# Matching decompilation', '',
    `Functions rewritten in C/C++ and verified by compiling them with Microsoft C/C++ and comparing the machine code with the original program. **${exact} of ${rows.length}** match exactly: for those, the code in \`matched/\` compiles to the same instructions as the original source did.`, '',
    '| Function | Address | Result | Flags | File |', '|---|---|---|---|---|',
    ...rows.map((x) => `| ${x.name} | 0x${x.va} | ${x.exact ? '✓ exact' : `${(x.score * 100).toFixed(1)}%`} | ${x.flags} | matched/${x.file} |`), '',
  ].join('\n'));
  ctx.onFile(`${AI_DIR}/matched/${matchFile(fn)}`);
}

function describeTool(name, input) {
  if (name === 'compile_and_compare') return `Compiling and comparing ${input.function}`;
  if (name === 'list_files') return `Listing ${input.dir || 'files'}${input.contains ? ` matching “${input.contains}”` : ''}`;
  if (name === 'read_file') return `Reading ${input.path}`;
  if (name === 'search') return `Searching /${input.pattern}/`;
  if (name === 'read_original') return input.mode === 'hex' ? 'Looking at the original bytes' : 'Reading strings of the original file';
  if (name === 'write_file') return `Writing ${AI_DIR}/${String(input.path).replace(new RegExp(`^${AI_DIR}/`), '')}`;
  return name;
}

// ---------------------------------------------------------------- agent

function cost(model, usage) {
  const m = MODELS[model] || MODELS[DEFAULT_MODEL];
  const write = (usage.cache_creation_input_tokens || 0) * m.input * 1.25;
  return ((usage.input_tokens || 0) * m.input + write + (usage.cache_read_input_tokens || 0) * m.cacheRead + (usage.output_tokens || 0) * m.output) / 1e6;
}

/**
 * One conversation about one output folder. `send()` runs the agent loop until Claude answers
 * without calling a tool. Events go to `emit({ type, ... })`:
 *   text {delta} · tool {label} · file {rel} · status {text} · done {usage, cost} · error {message}
 */
class Conversation {
  constructor({ root, job, inputFile }) {
    this.root = path.resolve(root);
    this.job = job || {};
    this.inputFile = inputFile || null;
    this.messages = [];
    this.totalCost = 0;
    this.controller = null;
  }

  get busy() { return !!this.controller; }

  stop() { this.controller?.abort(); }

  async send({ apiKey, model, mode = 'chat', text, currentFile, emit }) {
    if (this.busy) throw new Error('The assistant is already working on this folder.');
    model = MODELS[model] ? model : DEFAULT_MODEL;
    const client = apiKey ? new Anthropic({ apiKey }) : new Anthropic();
    const ctl = new AbortController();
    this.controller = ctl;

    let content = mode === 'reconstruct' ? RECONSTRUCT_PROMPT + (text ? '\n\n' + text : '') : text;
    if (currentFile) content = `(I am looking at ${currentFile} in the viewer.)\n\n${content}`;
    if (!this.messages.length) content = jobContext({ ...this.job, inputAvailable: !!this.inputFile }) + '\n\n' + content;
    // Keep a copy so a failed turn can be rolled back and the conversation stays valid.
    const start = this.messages.length;
    this.messages.push({ role: 'user', content });

    const ctx = { root: this.root, inputFile: this.inputFile, onFile: (rel) => emit({ type: 'file', rel }) };
    const usage = { input_tokens: 0, output_tokens: 0, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
    if (this.canMatch === undefined) this.canMatch = await matchingAvailable(this.root, this.inputFile);
    const params = {
      model,
      max_tokens: 64000,
      system: this.canMatch ? SYSTEM + MATCH_PROMPT : SYSTEM,
      tools: this.canMatch ? [...TOOLS, MATCH_TOOL] : TOOLS,
      cache_control: { type: 'ephemeral' },
      output_config: { effort: mode === 'reconstruct' ? 'high' : 'medium' },
    };
    if (MODELS[model].fallbacks) {
      // If a safety classifier declines a turn, the API retries it on a fallback model in the same call.
      params.betas = ['server-side-fallback-2026-07-01'];
      params.fallbacks = 'default';
    }

    let jsonRetries = 0;
    let finished = false;
    try {
      for (let turn = 0; turn < MAX_TURNS[mode === 'reconstruct' ? 'reconstruct' : 'chat']; turn++) {
        emit({ type: 'status', text: 'Thinking…' });
        const stream = client.beta.messages.stream({ ...params, messages: this.messages }, { signal: ctl.signal });
        stream.on('text', (delta) => emit({ type: 'text', delta }));
        stream.on('streamEvent', (ev) => {
          if (ev.type === 'content_block_start' && ev.content_block.type === 'tool_use') {
            emit({ type: 'status', text: ev.content_block.name === 'write_file' ? 'Writing code…' : 'Working…' });
          }
        });

        let msg;
        try {
          msg = await stream.finalMessage();
          jsonRetries = 0;
        } catch (err) {
          // A streamed tool input that isn't valid JSON: ask again (at most twice in a row).
          if (err instanceof Anthropic.APIError || ctl.signal.aborted || jsonRetries++ >= 2) throw err;
          continue;
        }
        for (const k of Object.keys(usage)) usage[k] += msg.usage?.[k] || 0;

        if (msg.stop_reason === 'refusal') {
          this.messages.push({ role: 'assistant', content: msg.content });
          emit({ type: 'text', delta: '\n\n_The model declined to continue this request._' });
          finished = true;
          break;
        }
        if (msg.stop_reason === 'pause_turn') {
          this.messages.push({ role: 'assistant', content: msg.content });
          continue;
        }
        const calls = msg.content.filter((b) => b.type === 'tool_use');
        this.messages.push({ role: 'assistant', content: msg.content });
        if (!calls.length) { finished = true; break; }
        if (msg.stop_reason === 'max_tokens') {
          // The last tool input was cut off: don't run it, tell Claude to write smaller pieces.
          this.messages.push({ role: 'user', content: calls.map((c) => ({
            type: 'tool_result', tool_use_id: c.id, is_error: true,
            content: 'Your output hit the length limit and this call was cut off. Split big files into several smaller write_file calls.',
          })) });
          continue;
        }

        const results = [];
        for (const call of calls) {
          if (ctl.signal.aborted) break;
          const problem = validate(call.name, call.input);
          if (problem) {
            results.push({ type: 'tool_result', tool_use_id: call.id, is_error: true, content: `Invalid input: ${problem}` });
            continue;
          }
          emit({ type: 'tool', label: describeTool(call.name, call.input) });
          try {
            results.push({ type: 'tool_result', tool_use_id: call.id, content: await runTool(ctx, call.name, call.input) });
          } catch (e) {
            results.push({ type: 'tool_result', tool_use_id: call.id, is_error: true, content: e.message });
          }
        }
        if (ctl.signal.aborted) throw new Anthropic.APIUserAbortError();
        this.messages.push({ role: 'user', content: results });
      }
      if (!finished) emit({ type: 'text', delta: '\n\n_Stopped: the step limit for one request was reached. Send “continue” to go on._' });
      const c = cost(model, usage);
      this.totalCost += c;
      emit({ type: 'done', usage, cost: c, totalCost: this.totalCost });
    } catch (err) {
      // Drop the unfinished tail so every tool_use left in the history has its tool_result,
      // and the next send() works. Work already done (files written, turns completed) is kept.
      const top = () => this.messages[this.messages.length - 1];
      if (this.messages.length > start + 1 && top().role === 'user') this.messages.pop();
      if (this.messages.length > start + 1 && top().role === 'assistant' && top().content.some((b) => b.type === 'tool_use')) this.messages.pop();
      if (this.messages.length === start + 1) this.messages.length = start;
      const c = cost(model, usage);
      this.totalCost += c;
      if (ctl.signal.aborted || err instanceof Anthropic.APIUserAbortError) emit({ type: 'done', stopped: true, usage, cost: c, totalCost: this.totalCost });
      else emit({ type: 'error', message: friendlyError(err) });
    } finally {
      this.controller = null;
    }
  }
}

function friendlyError(err) {
  if (err instanceof Anthropic.AuthenticationError) return 'Anthropic rejected the sign-in or API key. Sign in again or check the key in the assistant settings (gear icon).';
  if (err instanceof Anthropic.PermissionDeniedError) return 'This API key has no access to that model.';
  if (err instanceof Anthropic.RateLimitError) return 'Rate limit reached: wait a minute and try again.';
  if (err instanceof Anthropic.BadRequestError) return 'Request rejected: ' + (err.error?.error?.message || err.message);
  if (err instanceof Anthropic.APIConnectionError) return 'Could not reach the Claude API. Check your internet connection.';
  if (err instanceof Anthropic.APIError) return `Claude API error ${err.status ?? ''}: ${err.error?.error?.message || err.message}`;
  if (/credential|api key|apiKey|authentication/i.test(err?.message || '')) return 'Not signed in. Use "Sign in with Anthropic" or paste an API key in the assistant settings (gear icon).';
  return err?.message || String(err);
}

module.exports = { Conversation, MODELS, DEFAULT_MODEL, AI_DIR };
