// Swift name demangling for what binaries store in their metadata: Objective-C names of Swift classes
// ("_TtC6Aidoku14MangaViewController"), type references in field and superclass descriptors
// ("SaySSG" = [String], with symbolic references to other descriptors) and descriptor symbols
// ("$s5UIKit16UIViewControllerCMn"). Covers the forms types are written in; anything else is returned raw.

const STD_TYPES = {
  a: 'Array', b: 'Bool', D: 'Dictionary', d: 'Double', f: 'Float', h: 'Set', I: 'DefaultIndices', i: 'Int', J: 'Character',
  N: 'ClosedRange', n: 'Range', O: 'ObjectIdentifier', P: 'UnsafePointer', p: 'UnsafeMutablePointer', R: 'UnsafeBufferPointer',
  r: 'UnsafeMutableBufferPointer', S: 'String', s: 'Substring', u: 'UInt', V: 'UnsafeRawPointer', v: 'UnsafeMutableRawPointer',
  W: 'UnsafeRawBufferPointer', w: 'UnsafeMutableRawBufferPointer', q: 'Optional',
  // protocols
  Q: 'Equatable', H: 'Hashable', L: 'Comparable', E: 'Encodable', e: 'Decodable', B: 'BinaryFloatingPoint', F: 'FloatingPoint',
  G: 'RandomNumberGenerator', j: 'Numeric', z: 'BinaryInteger', Z: 'SignedInteger', k: 'RandomAccessCollection',
  K: 'BidirectionalCollection', l: 'Collection', M: 'MutableCollection', m: 'RangeReplaceableCollection', T: 'Sequence',
  t: 'IteratorProtocol', U: 'UnsignedInteger', X: 'RangeExpression', x: 'Strideable', Y: 'RawRepresentable', y: 'StringProtocol',
};
// Concurrency library ("Sc" + letter).
const STD_CONCURRENCY = {
  A: 'Actor', C: 'CheckedContinuation', c: 'UnsafeContinuation', E: 'CancellationError', e: 'UnownedSerialExecutor',
  F: 'Executor', f: 'SerialExecutor', G: 'TaskGroup', g: 'ThrowingTaskGroup', I: 'AsyncIteratorProtocol', i: 'AsyncSequence',
  J: 'UnownedJob', M: 'MainActor', P: 'TaskPriority', S: 'AsyncStream', s: 'AsyncThrowingStream', T: 'Task', t: 'UnsafeCurrentTask',
};
// Compiler builtins ("B" + letter): hidden storage of actors, raw pointers…
const BUILTIN = { D: 'Builtin.DefaultActorStorage', o: 'Builtin.NativeObject', O: 'Builtin.UnknownObject', p: 'Builtin.RawPointer', b: 'Builtin.BridgeObject', e: 'Builtin.Executor', j: 'Builtin.Job', c: 'Builtin.RawUnsafeContinuation', w: 'Builtin.Word' };
const KINDS = new Set(['C', 'V', 'O', 'P', 'a']);
const genericParam = (index) => (index === 0 ? 'T' : `T${index}`);

/** Objective-C runtime name of a Swift class to Swift syntax: _TtC6Aidoku5Manga -> Aidoku.Manga. */
function demangleClassName(name) {
  if (!name) return name;
  const m = /^_Tt([CVOP]+)(.*)$/.exec(name);
  if (!m) {
    if (/^\$s|^_\$s/.test(name)) return demangleSymbol(name) || name;
    return name;
  }
  let rest = m[2];
  const parts = [];
  while (rest) {
    if (rest[0] === 's' && !/^\d/.test(rest[1] || '')) { parts.push('Swift'); rest = rest.slice(1); continue; }
    // Private discriminator of a fileprivate type: "P33_DA2DF8…" (length, then "_" + hash): skipped.
    const priv = /^P(\d+)/.exec(rest);
    if (priv) { rest = rest.slice(priv[0].length + Number(priv[1])); continue; }
    const n = /^(\d+)/.exec(rest);
    if (!n) return name;
    const len = Number(n[1]);
    parts.push(rest.slice(n[1].length, n[1].length + len));
    rest = rest.slice(n[1].length + len);
  }
  return parts.length >= 2 ? parts.join('.') : name;
}

/** Tokens of a mangled name read from memory: characters and { ref, target } symbolic references. */
function tokenize(str) {
  return typeof str === 'string' ? [...str] : str;
}

/**
 * Demangles a Swift type mangling. `tokens` is a string or a token array (with symbolic references);
 * `resolve(token)` turns a symbolic reference into a type name. Returns null when the form isn't covered.
 */
function demangleType(input, resolve = () => null) {
  const t = tokenize(input);
  const stack = [];
  const MARK = { k: 'mark' };
  const SEP = { k: 'sep' };
  const popType = () => {
    const x = stack.pop();
    return x && (x.k === 'type' || x.k === 'ctx') ? x.s : null;
  };
  const pushType = (s) => stack.push({ k: 'type', s });
  let i = 0;
  let attrs = [];
  let asyncFn = false;
  const readNatural = () => { let s = ''; while (i < t.length && /\d/.test(t[i])) s += t[i++]; return s ? Number(s) : null; };
  while (i < t.length) {
    const c = t[i];
    if (typeof c === 'object') { const name = resolve(c); if (!name) return null; pushType(name); i++; continue; }
    if (/\d/.test(c)) {
      if (c === '0') return null; // word substitutions: not covered
      const n = readNatural();
      const id = t.slice(i, i + n);
      if (id.some((x) => typeof x !== 'string')) return null;
      stack.push({ k: 'ident', s: id.join('') });
      i += n;
      continue;
    }
    i++;
    if (c === 'S') {
      let d = t[i++];
      let times = 1;
      if (/\d/.test(d)) { // "S2S" = String, String (repeated substitution)
        let n = d;
        while (/\d/.test(t[i])) n += t[i++];
        times = Number(n);
        d = t[i++];
      }
      let name = null;
      if (d === 'c') name = STD_CONCURRENCY[t[i++]];
      else if (d === 'g' && times === 1) { const x = popType(); if (!x) return null; pushType(/->|^any |^some /.test(x) ? `(${x})?` : `${x}?`); continue; }
      else if (d === 'o' && times === 1) { stack.push({ k: 'ctx', s: '__C' }); continue; }
      else name = STD_TYPES[d];
      if (!name || times > 16) return null;
      for (let k = 0; k < times; k++) pushType(name);
    } else if (c === 's') stack.push({ k: 'ctx', s: 'Swift' });
    else if (c === 'B') {
      const d = t[i++];
      if (d === 'i') { let n = ''; while (/\d/.test(t[i])) n += t[i++]; if (t[i++] !== '_') return null; pushType(`Builtin.Int${n}`); }
      else if (BUILTIN[d]) pushType(BUILTIN[d]);
      else return null;
    } else if (c === 'x') pushType(genericParam(0)); // first generic parameter
    else if (c === 'q') { // q_ = second generic parameter, q<n>_ = n+2-th
      let n = '';
      while (/\d/.test(t[i])) n += t[i++];
      if (t[i] === 'd') return null; // deeper generic levels: not covered
      if (t[i++] !== '_') return null;
      pushType(genericParam(n === '' ? 1 : Number(n) + 2));
    }
    else if (KINDS.has(c)) {
      const id = stack.pop();
      if (!id || id.k !== 'ident') return null;
      const below = stack[stack.length - 1];
      let ctx = null;
      // What precedes is the context: a module (a bare identifier, "So", "s") or an enclosing type.
      if (below && (below.k === 'ctx' || below.k === 'type' || below.k === 'ident')) ctx = stack.pop().s;
      pushType(ctx && ctx !== '__C' && ctx !== 'Swift' ? `${ctx}.${id.s}` : id.s);
    } else if (c === 'y') stack.push(MARK);
    else if (c === '_' && t[i] === 'p') { // "_p": existential of the protocol before it (any P)
      i++;
      if (stack[stack.length - 1]?.k === 'ident') {
        const id = stack.pop();
        const below = stack[stack.length - 1];
        const ctx = below && (below.k === 'ctx' || below.k === 'ident') ? stack.pop().s : null;
        pushType(ctx && ctx !== '__C' && ctx !== 'Swift' ? `${ctx}.${id.s}` : id.s);
      }
      const x = popType();
      if (!x) return null;
      pushType(`any ${x}`);
    } else if (c === '_') stack.push(SEP);
    else if (c === 'E') { // extension context: <extended type> <module> E
      const mod = stack.pop();
      if (!mod || mod.k !== 'ident') return null;
    }
    else if (c === 'G') {
      const args = [];
      while (stack.length && stack[stack.length - 1] !== MARK) { const x = popType(); if (x === null) return null; args.unshift(x); }
      stack.pop();
      const base = popType();
      if (!base) return null;
      if (base === 'Array' && args.length === 1) pushType(`[${args[0]}]`);
      else if (base === 'Dictionary' && args.length === 2) pushType(`[${args[0]}: ${args[1]}]`);
      else if (base === 'Optional' && args.length === 1) pushType(/->|^any |^some /.test(args[0]) ? `(${args[0]})?` : `${args[0]}?`);
      else pushType(`${base}<${args.join(', ')}>`);
    } else if (c === 't') {
      if (stack[stack.length - 1] === MARK) { stack.pop(); pushType('()'); continue; }
      // Elements are "type label?", the first one followed by "_": (String, exclude: Bool) = SS_Sb7excludet
      const raw = [];
      while (stack.length && stack[stack.length - 1] !== SEP) raw.unshift(stack.pop());
      if (!stack.length) return null;
      stack.pop();
      const first = stack.pop();
      if (first?.k === 'ident') raw.unshift(stack.pop(), first); // first element with a label
      else raw.unshift(first);
      const items = [];
      for (const x of raw) {
        if (!x) return null;
        if (x.k === 'ident' && items.length) items[items.length - 1] = `${x.s}: ${items[items.length - 1]}`;
        else if (x.k === 'type') items.push(x.s);
        else return null;
      }
      pushType(`(${items.join(', ')})`);
    } else if (c === 'p') {
      if (stack[stack.length - 1] === MARK) { stack.pop(); pushType('Any'); } // "yp"
      else if (stack[stack.length - 1]?.k === 'type') { /* existential of the protocol on the stack */ }
      else return null;
    } else if (c === 'X') {
      const d = t[i++];
      if (d === 'l' && stack[stack.length - 1] === MARK) { stack.pop(); pushType('AnyObject'); }
      else if (d === 'D') { /* dynamic Self */ }
      else if ('EBCLK'.includes(d)) { if (!fn()) return null; } // noescape / block / C / thin function types
      else if (d === 'w' || d === 'o' || d === 'u') { // weak / unowned / unowned(unsafe)
        const x = popType();
        if (!x) return null;
        pushType(`${{ w: 'weak', o: 'unowned', u: 'unowned(unsafe)' }[d]} ${x}`);
      }
      else return null;
    } else if (c === 'c') { if (!fn()) return null; }
    else if (c === 'Y') { // function attributes
      const d = t[i++];
      if (d === 'c') { const actor = popType(); if (!actor) return null; attrs.push(`@${actor}`); } // global actor
      else if (d === 'b') attrs.push('@Sendable');
      else if (d === 'a') asyncFn = true;
      else if (d === 'K' || d === 'T' || d === 'J' || d === 'i' || d === 'u') { /* typed throws / isolation markers */ }
      else return null;
    }
    else if (c === 'z') { const x = popType(); if (!x) return null; pushType(`inout ${x}`); }
    else if (c === 'm') { const x = popType(); if (!x) return null; pushType(`${x}.Type`); }
    else if (c === 'h' || c === 'n') { /* parameter ownership: ignore */ }
    else return null;
  }
  function fn() {
    const asText = (x) => (x === MARK ? '()' : x && (x.k === 'type' || x.k === 'ctx') ? x.s : null);
    const result = asText(stack.pop());
    const params = asText(stack.pop());
    if (result === null || params === null) return false;
    const p = params.startsWith('(') ? params : `(${params})`;
    pushType(`${attrs.length ? attrs.join(' ') + ' ' : ''}${p}${asyncFn ? ' async' : ''} -> ${result === '()' ? 'Void' : result}`);
    attrs = [];
    asyncFn = false;
    return true;
  }
  if (stack.length !== 1 || stack[0].k !== 'type') return null;
  return stack[0].s;
}

/** Descriptor/metadata symbols: _$s5UIKit16UIViewControllerCMn -> UIKit.UIViewController. */
function demangleSymbol(sym) {
  const m = /^_?\$s(.*?)(Mn|Mp|Ma|Mm|N|Mf|MF|MV)?$/.exec(sym);
  if (!m) return null;
  // A protocol descriptor ("Mp") names the protocol without its trailing "P".
  return demangleType(m[1]) || (m[2] === 'Mp' ? demangleType(m[1] + 'P') : null);
}

module.exports = { demangleClassName, demangleType, demangleSymbol, STD_TYPES };
