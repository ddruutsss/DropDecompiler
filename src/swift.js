// Swift type dump: reads the Swift 5 reflection metadata of a Mach-O image (__swift5_types, __swift5_fieldmd,
// __swift5_protos, __swift5_proto) and writes a Swift interface: every class, struct, enum and protocol the
// module defines, with superclass, protocol conformances, stored properties (let/var and their types) and enum
// cases. Method bodies are compiled code; they are in the decompiled functions.

const { demangleType, demangleSymbol } = require('./swiftnames');

const KIND = { 0: 'module', 1: 'extension', 2: 'anonymous', 3: 'protocol', 4: 'opaque', 16: 'class', 17: 'struct', 18: 'enum' };
// Modules whose names are left out when printing types (what Swift code normally writes without a prefix).
const IMPLICIT = new Set(['Swift', 'Foundation', 'UIKit', 'SwiftUI', 'CoreGraphics', 'CoreFoundation', 'Combine', 'ObjectiveC', 'Dispatch', '_Concurrency', 'os', 'Darwin', 'QuartzCore', 'AppKit', 'Observation', 'SwiftData']);

function shorten(name, ownModule) {
  if (!name) return name;
  return name.replace(/\b([A-Za-z_][\w]*)\.(?=[A-Za-z_])/g, (m, mod, off, s) => {
    // only the first segment of a qualified name is a module
    if (off > 0 && /[\w.]/.test(s[off - 1])) return m;
    return IMPLICIT.has(mod) || mod === ownModule ? '' : m;
  });
}

class SwiftReader {
  constructor(m) {
    this.m = m;
    this.names = new Map();
  }

  /** Target of a relative pointer that may be indirect (low bit set: the target holds a pointer). */
  relIndirect(vm) {
    const d = this.m.i32(vm);
    if (!d) return null;
    if (d & 1) { const p = this.m.ptr(vm + (d & ~1)); return p; }
    return { addr: vm + d };
  }

  /** Reads a mangled name with symbolic references starting at vm. */
  mangled(vm) {
    if (!vm) return null;
    const m = this.m;
    const tokens = [];
    let p = vm;
    for (let n = 0; n < 4096; n++) {
      const c = m.u8(p);
      if (c === 0) break;
      if (c >= 0x01 && c <= 0x17) { tokens.push({ kind: c, target: p + 1 + m.i32(p + 1) }); p += 5; continue; }
      if (c >= 0x18 && c <= 0x1f) { tokens.push({ kind: c, target: p + 1 }); p += 9; continue; }
      tokens.push(String.fromCharCode(c));
      p++;
    }
    return tokens;
  }

  resolveRef(tok) {
    if (tok.kind === 0x01) return this.fullName(tok.target);
    if (tok.kind === 0x02) {
      const p = this.m.ptr(tok.target);
      if (p?.addr) return this.fullName(p.addr);
      if (p?.sym) return demangleSymbol(p.sym) || p.sym.replace(/^_/, '');
    }
    return null;
  }

  typeName(vm) {
    const tokens = this.mangled(vm);
    if (!tokens || !tokens.length) return null;
    const r = demangleType(tokens, (t) => this.resolveRef(t));
    if (r) return r;
    // Not covered: show what can be read, with references resolved.
    return '/* ' + tokens.map((t) => (typeof t === 'string' ? t : `<${this.resolveRef(t) || '?'}>`)).join('') + ' */';
  }

  /** Fully qualified name of a context descriptor (Module.Outer.Inner). */
  fullName(desc, depth = 0) {
    if (!desc || depth > 20) return null;
    if (this.names.has(desc)) return this.names.get(desc);
    const m = this.m;
    const flags = m.u32(desc);
    const kind = flags & 0x1f;
    let own = null;
    if (kind === 1) own = null; // extension: named after the extended type
    else if (kind === 2) own = '(private)';
    else own = m.cstr(m.rel(desc + 8));
    let parentName = null;
    const parent = this.relIndirect(desc + 4);
    if (parent?.addr) parentName = this.fullName(parent.addr, depth + 1);
    else if (parent?.sym) parentName = demangleSymbol(parent.sym);
    if (kind === 1) {
      const ext = this.typeName(m.rel(desc + 8));
      own = null;
      parentName = ext && !ext.startsWith('/*') ? ext : parentName;
    }
    const name = kind === 2 ? parentName : [parentName, own].filter(Boolean).join('.');
    this.names.set(desc, name);
    return name;
  }

  /** The module a descriptor is declared in (extensions and nested types included). */
  moduleName(desc, depth = 0) {
    if (!desc || depth > 30) return null;
    const m = this.m;
    if ((m.u32(desc) & 0x1f) === 0) return m.cstr(m.rel(desc + 8));
    const parent = this.relIndirect(desc + 4);
    if (parent?.addr) return this.moduleName(parent.addr, depth + 1);
    if (parent?.sym) return (demangleSymbol(parent.sym) || '').split('.')[0] || null;
    return null;
  }

  fields(fd) {
    const m = this.m;
    if (!fd) return [];
    const recSize = m.u16(fd + 10) || 12;
    const n = m.u32(fd + 12);
    const out = [];
    for (let k = 0; k < n && k < 5000; k++) {
      const r = fd + 16 + k * recSize;
      const flags = m.u32(r);
      const typeRel = m.rel(r + 4);
      const name = m.cstr(m.rel(r + 8)) || `field${k}`;
      out.push({ name, type: typeRel ? this.typeName(typeRel) : null, isVar: (flags & 2) !== 0, indirect: (flags & 1) !== 0 });
    }
    return out;
  }
}

const METHOD_KIND = ['method', 'init', 'getter', 'setter', 'modify', 'read'];

/**
 * Functions that the Swift metadata identifies: every type's metadata accessor, and the methods,
 * initializers and property accessors in each class's vtable (by kind and slot: Swift keeps no method names).
 * Returns [{ addr, cls, sel, kind }] in the same shape as the Objective-C methods.
 */
function swiftFunctions(m) {
  const r = new SwiftReader(m);
  const out = [];
  const sec = m.section('__swift5_types', ['__TEXT']);
  if (!sec) return out;
  for (let k = 0; k < sec.size / 4; k++) {
    const at = sec.addr + k * 4;
    const d = m.i32(at);
    let desc = at + (d & ~3);
    if (d & 1) desc = m.addr(desc);
    if (!desc) continue;
    try {
      const flags = m.u32(desc);
      const kind = flags & 0x1f;
      if (kind < 16 || kind > 18) continue;
      const name = (r.fullName(desc) || '').replace(/^__C\./, '');
      if (!name) continue;
      const accessor = m.rel(desc + 12);
      if (accessor) out.push({ addr: accessor, cls: name, sel: 'typeMetadataAccessor', kind: '+' });
      // Class vtable (non-generic classes; generic ones have a variable-size header first).
      const kf = flags >>> 16;
      if (kind !== 16 || (flags & 0x80) || !(kf & 0x8000)) continue;
      let p = desc + 44;
      if (kf & 0x2000) p += 4; // resilient superclass
      const init = kf & 3;
      if (init === 1) p += 12; // singleton metadata initialization
      else if (init === 2) p += 4; // foreign metadata initialization
      const size = m.u32(p + 4);
      if (size > 5000) continue;
      const counts = {};
      for (let j = 0; j < size; j++) {
        const md = p + 8 + j * 8;
        const mf = m.u32(md);
        const impl = m.rel(md + 4);
        if (!impl) continue;
        const what = METHOD_KIND[mf & 0x0f] || 'method';
        counts[what] = (counts[what] || 0) + 1;
        const label = `${(mf & 0x10) || what === 'init' ? '' : 'static_'}${what}${what === 'init' && counts[what] === 1 ? '' : '_' + counts[what]}${(mf & 0x40) ? '_async' : ''}`;
        out.push({ addr: impl, cls: name, sel: label, kind: (mf & 0x10) ? '-' : '+' });
      }
    } catch { /* damaged descriptor */ }
  }
  return out;
}

/** Reads every type the image defines. */
function dumpTypes(m) {
  const r = new SwiftReader(m);
  const types = [];
  const sec = m.section('__swift5_types', ['__TEXT']);
  if (sec) {
    for (let k = 0; k < sec.size / 4; k++) {
      const at = sec.addr + k * 4;
      const d = m.i32(at);
      let desc = at + (d & ~3);
      if (d & 1) desc = m.addr(desc); // indirect
      if (!desc) continue;
      try {
        const flags = m.u32(desc);
        const kind = KIND[flags & 0x1f];
        if (!['class', 'struct', 'enum'].includes(kind)) continue;
        const t = { kind, desc, name: r.fullName(desc), module: r.moduleName(desc), generic: (flags & 0x80) !== 0, fields: [], conformances: [] };
        t.fields = r.fields(m.rel(desc + 16));
        if (kind === 'class') {
          const sup = m.rel(desc + 20);
          if (sup) t.superclass = r.typeName(sup);
        }
        if (kind === 'enum') {
          t.payloadCases = m.u32(desc + 20) & 0xffffff;
          t.emptyCases = m.u32(desc + 24);
        }
        types.push(t);
      } catch { /* damaged descriptor */ }
    }
  }
  const byDesc = new Map(types.map((t) => [t.desc, t]));

  // Protocols the module defines.
  const protocols = [];
  const ps = m.section('__swift5_protos', ['__TEXT']);
  if (ps) {
    for (let k = 0; k < ps.size / 4; k++) {
      const p = r.relIndirect(ps.addr + k * 4);
      if (!p?.addr) continue;
      try {
        protocols.push({ name: r.fullName(p.addr), module: r.moduleName(p.addr), requirements: m.u32(p.addr + 16) });
      } catch { /* damaged */ }
    }
  }

  // Protocol conformances (struct Manga: Codable, Hashable…).
  let conformanceCount = 0;
  const cs = m.section('__swift5_proto', ['__TEXT']);
  if (cs) {
    for (let k = 0; k < cs.size / 4; k++) {
      const c = m.rel(cs.addr + k * 4);
      if (!c) continue;
      try {
        const proto = r.relIndirect(c);
        const protoName = proto?.addr ? r.fullName(proto.addr) : proto?.sym ? demangleSymbol(proto.sym) : null;
        const flags = m.u32(c + 12);
        const refKind = (flags >> 3) & 7;
        let target = null;
        if (refKind === 0) target = m.rel(c + 4);
        else if (refKind === 1) { const p = m.rel(c + 4); target = p ? m.addr(p) : 0; }
        const t = target && byDesc.get(target);
        if (t && protoName) { t.conformances.push(protoName); conformanceCount++; }
      } catch { /* damaged */ }
    }
  }
  return { types, protocols, conformanceCount };
}

const moduleOf = (name) => (name && !name.startsWith('/*') ? name.split('.')[0] : '?');

/**
 * Swift interfaces of an image, one per module: the image's own module, the Swift packages statically linked
 * into it, and the C / Objective-C / C++ types it imports (__C). Returns null if the image has no Swift types.
 * { files: { 'Module.swift': text }, module, counts: { classes, structs, enums, protocols }, modules: [names] }
 */
function swiftInterface(m, image) {
  const { types, protocols } = dumpTypes(m);
  if (!types.length && !protocols.length) return null;
  const tally = {};
  const modOf = (x) => x.module || moduleOf(x.name);
  for (const t of types) { const mod = modOf(t); if (mod !== '__C' && mod !== '?') tally[mod] = (tally[mod] || 0) + 1; }
  const own = Object.entries(tally).sort((a, b) => b[1] - a[1])[0]?.[0] || image;
  const groups = new Map();
  const add = (mod, item) => { if (!groups.has(mod)) groups.set(mod, { types: [], protocols: [] }); groups.get(mod)[item.kind ? 'types' : 'protocols'].push(item); };
  for (const t of types) add(modOf(t), t);
  for (const p of protocols) add(modOf(p), p);

  const files = {};
  for (const [mod, g] of groups) {
    const imported = mod === '__C';
    const sh = (s) => shorten(s, imported ? '__C' : mod).replace(/\b__C\./g, '');
    const fileName = imported ? 'Imported C and ObjC types.swift' : `${mod === '?' ? 'Unknown' : mod}.swift`;
    const count = (k) => g.types.filter((t) => t.kind === k).length;
    const out = [
      imported
        ? `// C, C++ and Objective-C types that ${image} uses from Swift (imported by the compiler, not defined by the app).`
        : `// Swift interface of module ${mod}${mod === own ? ` (the code of ${image})` : `, compiled into ${image}`}. Generated by DropDecompiler from the binary's reflection metadata.`,
      `// ${count('class')} classes, ${count('struct')} structs, ${count('enum')} enums, ${g.protocols.length} protocols.`,
      '// Stored properties, enum cases, superclasses and protocol conformances are exact; method bodies are compiled code.',
      '',
    ];
    for (const t of [...g.types].sort((a, b) => String(a.name).localeCompare(String(b.name)))) {
      const name = sh(t.name) || '(unknown)';
      const inherits = [t.superclass && !t.superclass.startsWith('/*') ? sh(t.superclass) : null, ...new Set(t.conformances.map(sh))].filter(Boolean);
      out.push(`${t.kind} ${name}${t.generic ? '<…>' : ''}${inherits.length ? ': ' + inherits.join(', ') : ''} {`);
      if (t.kind === 'enum') {
        for (const f of t.fields) {
          const payload = f.type && f.type !== '()' ? `(${sh(f.type).replace(/^\((.*)\)$/, '$1')})` : '';
          out.push(`    ${f.indirect ? 'indirect ' : ''}case ${f.name}${payload}`);
        }
      } else {
        for (const f of t.fields) {
          const type = f.type ? sh(f.type) : '/* unknown */';
          const own = /^(weak|unowned(unsafe)|unowned) /.exec(type);
          out.push(`    ${own ? own[1] + ' ' : ''}${f.isVar ? 'var' : 'let'} ${f.name}: ${own ? type.slice(own[0].length) : type}`);
        }
      }
      out.push('}', '');
    }
    for (const p of [...g.protocols].sort((a, b) => String(a.name).localeCompare(String(b.name)))) {
      out.push(`protocol ${sh(p.name)} {  // ${p.requirements} requirement${p.requirements === 1 ? '' : 's'}`, '}', '');
    }
    files[fileName] = out.join('\n');
  }
  const ownTypes = groups.get(own)?.types || [];
  // Field types by type name, for the Objective-C headers of Swift classes.
  const fieldsByType = new Map();
  for (const t of types) {
    if (t.kind !== 'class' || !t.name) continue;
    const sh = (s) => shorten(s, modOf(t)).replace(/__C./g, '');
    fieldsByType.set(t.name, new Map(t.fields.map((f) => [f.name, { type: f.type ? sh(f.type) : null, isVar: f.isVar }])));
  }
  return {
    files, module: own, fieldsByType,
    modules: [...groups.keys()].filter((x) => x !== '__C' && x !== '?' && x !== own),
    counts: {
      classes: ownTypes.filter((t) => t.kind === 'class').length, structs: ownTypes.filter((t) => t.kind === 'struct').length,
      enums: ownTypes.filter((t) => t.kind === 'enum').length, protocols: groups.get(own)?.protocols.length || 0, total: types.length,
    },
  };
}

module.exports = { swiftInterface, dumpTypes, swiftFunctions };
