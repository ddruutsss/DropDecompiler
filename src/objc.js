// Objective-C class-dump: reads the Objective-C 2 runtime metadata of a Mach-O image (__objc_classlist,
// __objc_catlist, __objc_protolist) and writes header files like class-dump: every class with its superclass,
// protocols, ivars (with offsets), properties (with attributes) and methods (with types and implementation
// addresses), plus categories and protocols. Swift classes that are visible to Objective-C are included,
// with demangled names.

const { demangleClassName } = require('./swiftnames');

// ---------------------------------------------------------------- type encodings

const SIMPLE = {
  c: 'char', i: 'int', s: 'short', l: 'int', q: 'long long', C: 'unsigned char', I: 'unsigned int', S: 'unsigned short',
  L: 'unsigned int', Q: 'unsigned long long', f: 'float', d: 'double', D: 'long double', B: '_Bool', v: 'void',
  '*': 'char *', '#': 'Class', ':': 'SEL', '?': 'CDUnknownFunctionPointerType', t: '__int128', T: 'unsigned __int128',
};
const QUALIFIERS = { r: 'const', n: 'in', N: 'inout', o: 'out', O: 'bycopy', R: 'byref', V: 'oneway', A: '_Atomic', j: '_Complex' };

/** Parses one Objective-C type encoding starting at s[i]. Returns { type: { base, ptr, tail }, i } or null. */
function parseType(s, i) {
  const quals = [];
  while (QUALIFIERS[s[i]] && i < s.length) quals.push(QUALIFIERS[s[i++]]);
  const q = quals.filter((x) => x === 'const' || x === '_Atomic').join(' ');
  const wrap = (t) => ({ ...t, base: (q ? q + ' ' : '') + t.base });
  const c = s[i];
  if (c === undefined) return null;
  if (c === '@') {
    if (s[i + 1] === '?') return { type: wrap({ base: 'CDUnknownBlockType', ptr: '' }), i: i + 2 };
    if (s[i + 1] === '"') {
      const e = s.indexOf('"', i + 2);
      const name = s.slice(i + 2, e);
      i = e + 1;
      if (!name) return { type: wrap({ base: 'id', ptr: '' }), i };
      if (name.startsWith('<')) return { type: wrap({ base: `id ${name}`, ptr: '' }), i }; // id<Protocol>
      const lt = name.indexOf('<');
      const cls = lt > 0 ? name.slice(0, lt) : name;
      return { type: wrap({ base: demangleClassName(cls) + (lt > 0 ? ' ' + name.slice(lt) : ''), ptr: '*', cls: demangleClassName(cls) }), i };
    }
    return { type: wrap({ base: 'id', ptr: '' }), i: i + 1 };
  }
  if (c === '^') {
    const inner = parseType(s, i + 1);
    if (!inner) return null;
    const t = inner.type;
    return { type: wrap({ base: t.base, ptr: (t.ptr || '') + '*', tail: t.tail }), i: inner.i };
  }
  if (c === 'b') {
    let j = i + 1;
    while (/\d/.test(s[j])) j++;
    return { type: wrap({ base: 'unsigned int', ptr: '', bits: s.slice(i + 1, j) }), i: j };
  }
  if (c === '[') {
    let j = i + 1;
    while (/\d/.test(s[j])) j++;
    const n = s.slice(i + 1, j);
    const inner = parseType(s, j);
    if (!inner) return null;
    return { type: wrap({ base: inner.type.base, ptr: inner.type.ptr, tail: `[${n}]` + (inner.type.tail || '') }), i: inner.i + 1 };
  }
  if (c === '{' || c === '(') {
    const close = c === '{' ? '}' : ')';
    let depth = 0;
    let j = i;
    for (; j < s.length; j++) {
      if (s[j] === '{' || s[j] === '(') depth++;
      else if (s[j] === '}' || s[j] === ')') { depth--; if (!depth) break; }
      else if (s[j] === '"') j = s.indexOf('"', j + 1);
    }
    const body = s.slice(i + 1, j);
    const eq = body.indexOf('=');
    let name = (eq >= 0 ? body.slice(0, eq) : body).trim();
    const kw = c === '{' ? 'struct' : 'union';
    if (!name || name === '?') name = `${kw === 'struct' ? 'CDStruct' : 'CDUnion'}_${hash(body)}`;
    return { type: wrap({ base: `${kw} ${name}`, ptr: '', fields: eq >= 0 ? body.slice(eq + 1) : null, close }), i: j + 1 };
  }
  if (SIMPLE[c]) return { type: wrap({ base: SIMPLE[c], ptr: '' }), i: i + 1 };
  return { type: wrap({ base: `/* ${c} */ void`, ptr: '*' }), i: i + 1 };
}

function hash(s) {
  let h = 0;
  for (let k = 0; k < s.length; k++) h = (h * 31 + s.charCodeAt(k)) >>> 0;
  return h.toString(16).slice(0, 6);
}

/** "type name" with the pointer stars and array suffix in the right place. */
function decl(t, name) {
  if (!t) return `id ${name}`;
  const star = t.ptr ? ' ' + t.ptr : ' ';
  return `${t.base}${star}${name}${t.tail || ''}${t.bits ? ' : ' + t.bits : ''}`.replace(/ +/g, ' ').replace(/\* (\w)/, '*$1');
}

function typeName(t) {
  if (!t) return 'id';
  return `${t.base}${t.ptr ? ' ' + t.ptr : ''}${t.tail || ''}`.trim();
}

/** Splits a method type encoding ("v24@0:8@16") into [returnType, ...argTypes]. */
function methodTypes(enc) {
  const out = [];
  let i = 0;
  while (enc && i < enc.length) {
    const r = parseType(enc, i);
    if (!r) break;
    out.push(r.type);
    i = r.i;
    while (/[\d-]/.test(enc[i])) i++;
  }
  return out;
}

function methodLine(kind, sel, types, imp) {
  const t = methodTypes(types);
  const ret = typeName(t[0] || { base: 'id', ptr: '' });
  const args = t.slice(3); // skip return, self, _cmd
  let text;
  if (!sel.includes(':')) text = `${kind} (${ret})${sel};`;
  else {
    const parts = sel.split(':').slice(0, -1);
    text = `${kind} (${ret})` + parts.map((p, k) => `${p}:(${typeName(args[k])})arg${k + 1}`).join(' ') + ';';
  }
  return imp ? `${text}\t// IMP=0x${imp.toString(16)}` : text;
}

function propertyLine(name, attrs) {
  let type = null;
  const flags = [];
  let ivar = null;
  let getter = null;
  let setter = null;
  // The type comes first and can contain commas (structs), so it is parsed, not split.
  if (attrs.startsWith('T')) {
    const r = parseType(attrs, 1);
    if (r) { type = r.type; attrs = attrs.slice(r.i); }
  }
  for (const a of attrs.split(',').filter(Boolean)) {
    const k = a[0];
    if (k === 'R') flags.push('readonly');
    else if (k === 'C') flags.push('copy');
    else if (k === '&') flags.push('retain');
    else if (k === 'W') flags.push('weak');
    else if (k === 'N') flags.push('nonatomic');
    else if (k === 'D') flags.push('dynamic');
    else if (k === 'G') getter = a.slice(1);
    else if (k === 'S') setter = a.slice(1);
    else if (k === 'V') ivar = a.slice(1);
  }
  if (getter) flags.push(`getter=${getter}`);
  if (setter) flags.push(`setter=${setter}`);
  const dyn = flags.includes('dynamic');
  const head = `@property${flags.filter((f) => f !== 'dynamic').length ? `(${flags.filter((f) => f !== 'dynamic').join(', ')})` : ''} ${decl(type, name)};`;
  return head + (dyn ? ' // @dynamic ' + name + ';' : ivar ? ` // @synthesize ${name}=${ivar};` : '');
}

// ---------------------------------------------------------------- metadata readers

function className(m, ptr, cache) {
  if (!ptr) return null;
  if (ptr.sym) return demangleClassName(ptr.sym.replace(/^_OBJC_(META)?CLASS_\$_/, ''));
  if (cache.has(ptr.addr)) return cache.get(ptr.addr);
  const data = m.addr(ptr.addr + 32);
  const ro = data - (data % 8);
  const name = ro ? demangleClassName(m.cstr(m.addr(ro + 24)) || '') : null;
  cache.set(ptr.addr, name);
  return name;
}

function readMethods(m, list) {
  if (!list) return [];
  const flags = m.u32(list);
  const count = m.u32(list + 4);
  if (count > 100000) return [];
  const relative = (flags & 0x80000000) !== 0;
  const size = flags & 0xfffc || (relative ? 12 : 24);
  const out = [];
  for (let k = 0; k < count; k++) {
    const e = list + 8 + k * size;
    if (relative) {
      const selRef = e + m.i32(e);
      const name = (flags & 0x40000000) ? m.cstr(selRef) : m.cstr(m.addr(selRef));
      const types = m.cstr(e + 4 + m.i32(e + 4));
      const impOff = m.i32(e + 8);
      out.push({ name, types, imp: impOff ? e + 8 + impOff : 0 });
    } else {
      out.push({ name: m.cstr(m.addr(e)), types: m.cstr(m.addr(e + 8)), imp: m.addr(e + 16) });
    }
  }
  return out.filter((x) => x.name);
}

function readIvars(m, list) {
  if (!list) return [];
  const size = m.u32(list) || 32;
  const count = m.u32(list + 4);
  if (count > 100000) return [];
  const out = [];
  for (let k = 0; k < count; k++) {
    const e = list + 8 + k * size;
    const offPtr = m.addr(e);
    out.push({ offset: offPtr ? m.u32(offPtr) : null, name: m.cstr(m.addr(e + 8)), type: m.cstr(m.addr(e + 16)) || '', size: m.u32(e + 28) });
  }
  return out.filter((x) => x.name);
}

function readProperties(m, list) {
  if (!list) return [];
  const size = m.u32(list) || 16;
  const count = m.u32(list + 4);
  if (count > 100000) return [];
  const out = [];
  for (let k = 0; k < count; k++) {
    const e = list + 8 + k * size;
    out.push({ name: m.cstr(m.addr(e)), attrs: m.cstr(m.addr(e + 8)) || '' });
  }
  return out.filter((x) => x.name);
}

function readProtocolNames(m, list) {
  if (!list) return [];
  const count = Number(m.raw64(list) & 0xffffffn);
  const out = [];
  for (let k = 0; k < count && k < 1000; k++) {
    const p = m.ptr(list + 8 + k * 8);
    if (p?.addr) out.push(demangleClassName(m.cstr(m.addr(p.addr + 8)) || '?'));
    else if (p?.sym) out.push(p.sym.replace(/^__OBJC_PROTOCOL_\$_/, '').replace(/^_OBJC_PROTOCOL_\$_/, ''));
  }
  return out;
}

function readClass(m, addr, cache) {
  const data = m.addr(addr + 32);
  const ro = data - (data % 8);
  if (!ro) return null;
  const roFlags = m.u32(ro);
  const name = m.cstr(m.addr(ro + 24));
  if (!name) return null;
  const meta = m.addr(addr);
  const metaData = meta ? m.addr(meta + 32) : 0;
  const metaRo = metaData - (metaData % 8);
  return {
    name: demangleClassName(name),
    rawName: name,
    swift: (data & 3) !== 0 || /^_Tt/.test(name),
    superclass: className(m, m.ptr(addr + 8), cache),
    root: (roFlags & 2) !== 0,
    instanceSize: m.u32(ro + 8),
    protocols: readProtocolNames(m, m.addr(ro + 40)),
    ivars: readIvars(m, m.addr(ro + 48)),
    properties: readProperties(m, m.addr(ro + 64)),
    methods: readMethods(m, m.addr(ro + 32)),
    classMethods: metaRo ? readMethods(m, m.addr(metaRo + 32)) : [],
    classProperties: [],
    address: addr,
  };
}

/** Reads all Objective-C metadata of an image. */
function dump(m) {
  const cache = new Map();
  const classes = [];
  const cl = m.section('__objc_classlist');
  if (cl) {
    for (let k = 0; k < cl.size / 8; k++) {
      const p = m.ptr(cl.addr + k * 8);
      if (!p?.addr) continue;
      try { const c = readClass(m, p.addr, cache); if (c) classes.push(c); } catch { /* damaged entry */ }
    }
  }
  const categories = [];
  const cat = m.section('__objc_catlist');
  if (cat) {
    for (let k = 0; k < cat.size / 8; k++) {
      const a = m.addr(cat.addr + k * 8);
      if (!a) continue;
      try {
        categories.push({
          name: m.cstr(m.addr(a)) || '?',
          cls: className(m, m.ptr(a + 8), cache) || '?',
          methods: readMethods(m, m.addr(a + 16)),
          classMethods: readMethods(m, m.addr(a + 24)),
          protocols: readProtocolNames(m, m.addr(a + 32)),
          properties: readProperties(m, m.addr(a + 40)),
        });
      } catch { /* damaged entry */ }
    }
  }
  const protocols = [];
  const pl = m.section('__objc_protolist');
  if (pl) {
    const seen = new Set();
    for (let k = 0; k < pl.size / 8; k++) {
      const a = m.addr(pl.addr + k * 8);
      if (!a) continue;
      const name = demangleClassName(m.cstr(m.addr(a + 8)) || '');
      if (!name || seen.has(name)) continue;
      seen.add(name);
      const size = m.u32(a + 64);
      const extended = size >= 80 ? m.addr(a + 72) : 0;
      // Extended method types carry the class names of arguments ("@\"NSString\"").
      const lists = [24, 32, 40, 48].map((o) => readMethods(m, m.addr(a + o)));
      let idx = 0;
      if (extended) for (const list of lists) for (const meth of list) { const t = m.cstr(m.addr(extended + 8 * idx++)); if (t) meth.types = t; }
      protocols.push({
        name, protocols: readProtocolNames(m, m.addr(a + 16)),
        methods: lists[0], classMethods: lists[1], optionalMethods: lists[2], optionalClassMethods: lists[3],
        properties: readProperties(m, m.addr(a + 56)),
      });
    }
  }
  const info = m.section('__objc_imageinfo');
  const swiftVersion = info ? (m.u32(info.addr + 4) >> 8) & 0xff : 0;
  return { classes, categories, protocols, swiftVersion };
}

// ---------------------------------------------------------------- header output

function header(image, title) {
  return [`//`, `//   ${title}`, `//   Generated by DropDecompiler (class-dump format) from ${image}.`, `//   Method bodies are compiled code: see the decompiled functions at the IMP addresses.`, `//`, ''];
}

function forwardDecls(lines, own) {
  const classes = new Set();
  const protos = new Set();
  for (const l of lines) {
    for (const m of l.matchAll(/\b([A-Z_][\w.]*) \*(?!\/)/g)) if (m[1] !== own && !/^(struct|union|CD)/.test(m[1])) classes.add(m[1]);
    for (const m of l.matchAll(/id <([^>]+)>/g)) for (const p of m[1].split(/,\s*/)) protos.add(p);
  }
  const out = [];
  if (classes.size) out.push(`@class ${[...classes].sort().join(', ')};`);
  if (protos.size) out.push(`@protocol ${[...protos].sort().join(', ')};`);
  return out.length ? [...out, ''] : [];
}

function classHeader(c, image, swiftFields) {
  const body = [];
  body.push(`@interface ${c.name}${c.superclass ? ' : ' + c.superclass : c.root ? '' : ' : NSObject'}${c.protocols.length ? ` <${c.protocols.join(', ')}>` : ''}`);
  if (c.ivars.length) {
    body.push('{');
    const sf = c.swift ? swiftFields?.get(c.name) : null;
    for (const v of c.ivars) {
      const t = v.type ? parseType(v.type, 0)?.type : null;
      const off = v.offset ? `+${v.offset}` : '';
      if (t) { body.push(`    ${decl(t, v.name)};${off ? `\t// ${off}` : ''}`); continue; }
      // A Swift stored property: its type comes from the Swift metadata.
      const f = sf?.get(v.name);
      const own = f?.type && /^(weak|unowned\(unsafe\)|unowned) /.exec(f.type);
      const type = f?.type ? (own ? f.type.slice(own[0].length) : f.type) : 'id /* Swift */';
      const note = f ? `Swift ${own ? own[1] + ' ' : ''}${f.isVar ? 'var' : 'let'}` : 'Swift property';
      body.push(`    ${type} ${v.name};\t// ${note}${off ? ', ' + off : ''}`);
    }
    body.push('}');
  }
  body.push('');
  for (const p of c.properties) body.push(propertyLine(p.name, p.attrs));
  if (c.properties.length) body.push('');
  for (const meth of c.classMethods) body.push(methodLine('+', meth.name, meth.types, meth.imp));
  for (const meth of c.methods) body.push(methodLine('-', meth.name, meth.types, meth.imp));
  body.push('', '@end', '');
  const head = header(image, c.swift ? `Swift class ${c.name}${c.rawName !== c.name ? ` (${c.rawName})` : ''}` : `${c.name}.h`);
  return [...head, ...forwardDecls(body, c.name), ...body].join('\n');
}

function categoryHeader(cat, image) {
  const body = [`@interface ${cat.cls} (${cat.name})${cat.protocols.length ? ` <${cat.protocols.join(', ')}>` : ''}`, ''];
  for (const p of cat.properties) body.push(propertyLine(p.name, p.attrs));
  if (cat.properties.length) body.push('');
  for (const meth of cat.classMethods) body.push(methodLine('+', meth.name, meth.types, meth.imp));
  for (const meth of cat.methods) body.push(methodLine('-', meth.name, meth.types, meth.imp));
  body.push('', '@end', '');
  return [...header(image, `${cat.cls}+${cat.name}.h`), ...forwardDecls(body, cat.cls), ...body].join('\n');
}

function protocolHeader(p, image) {
  const body = [`@protocol ${p.name}${p.protocols.length ? ` <${p.protocols.join(', ')}>` : ''}`];
  for (const prop of p.properties) body.push(propertyLine(prop.name, prop.attrs));
  for (const meth of p.classMethods) body.push(methodLine('+', meth.name, meth.types));
  for (const meth of p.methods) body.push(methodLine('-', meth.name, meth.types));
  if (p.optionalMethods.length || p.optionalClassMethods.length) {
    body.push('', '@optional');
    for (const meth of p.optionalClassMethods) body.push(methodLine('+', meth.name, meth.types));
    for (const meth of p.optionalMethods) body.push(methodLine('-', meth.name, meth.types));
  }
  body.push('@end', '');
  return [...header(image, `${p.name}-Protocol.h`), ...forwardDecls(body, null), ...body].join('\n');
}

const fileSafe = (s) => s.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').slice(0, 150);

/**
 * Class-dump of an image as files: { 'Class.h': text, ... } plus an index. Returns { files, summary, methods }
 * where `methods` lists every implementation address with a readable name (for naming decompiled functions).
 */
function classDump(m, image, { swiftFields } = {}) {
  const d = dump(m);
  const files = {};
  const methods = [];
  for (const c of d.classes) {
    files[`${fileSafe(c.name)}.h`] = classHeader(c, image, swiftFields);
    for (const meth of c.methods) if (meth.imp) methods.push({ addr: meth.imp, cls: c.name, sel: meth.name, kind: '-' });
    for (const meth of c.classMethods) if (meth.imp) methods.push({ addr: meth.imp, cls: c.name, sel: meth.name, kind: '+' });
  }
  for (const cat of d.categories) {
    files[`${fileSafe(cat.cls)}+${fileSafe(cat.name)}.h`] = categoryHeader(cat, image);
    for (const meth of cat.methods) if (meth.imp) methods.push({ addr: meth.imp, cls: `${cat.cls}(${cat.name})`, sel: meth.name, kind: '-' });
    for (const meth of cat.classMethods) if (meth.imp) methods.push({ addr: meth.imp, cls: `${cat.cls}(${cat.name})`, sel: meth.name, kind: '+' });
  }
  for (const p of d.protocols) files[`${fileSafe(p.name)}-Protocol.h`] = protocolHeader(p, image);
  if (d.classes.length || d.categories.length || d.protocols.length) {
    const tree = d.classes.map((c) => `${c.name}${c.superclass ? ' : ' + c.superclass : ''}${c.swift ? '   (Swift)' : ''}`).sort();
    files['_CLASSES.txt'] = [`${image}: ${d.classes.length} classes, ${d.categories.length} categories, ${d.protocols.length} protocols`, '', ...tree, ''].join('\n');
  }
  return {
    files, methods,
    summary: { classes: d.classes.length, swiftClasses: d.classes.filter((c) => c.swift).length, categories: d.categories.length, protocols: d.protocols.length, methods: methods.length, swiftVersion: d.swiftVersion },
    classes: d.classes,
  };
}

module.exports = { classDump, dump, parseType, methodTypes, methodLine, propertyLine };
