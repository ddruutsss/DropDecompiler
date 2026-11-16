// Compiled Interface Builder files (iOS .nib, and the .nib files inside .storyboardc folders) in Apple's
// "NIBArchive" format: decoded into a readable list of the archived objects (views, labels, buttons,
// constraints, outlets and actions) with their properties, strings resolved inline.

function readNib(buf) {
  if (buf.length < 50 || buf.toString('latin1', 0, 10) !== 'NIBArchive') return null;
  let p = 0;
  const u32 = (o) => buf.readUInt32LE(o);
  // Variable-length integers: 7 bits per byte, little-endian, the LAST byte has its high bit set.
  const varint = () => {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = buf[p++];
      if (b === undefined) throw new Error('truncated');
      v += (b & 0x7f) * 2 ** shift;
      if (b & 0x80) return v;
      shift += 7;
    }
  };
  const [objCount, objOff, keyCount, keyOff, valCount, valOff, clsCount, clsOff] = [18, 22, 26, 30, 34, 38, 42, 46].map(u32);
  if (objCount > 1e6 || keyCount > 1e6 || valCount > 1e7 || clsCount > 1e5) return null;

  p = keyOff;
  const keys = [];
  for (let k = 0; k < keyCount; k++) { const n = varint(); keys.push(buf.toString('utf8', p, p + n)); p += n; }

  p = clsOff;
  const classes = [];
  for (let k = 0; k < clsCount; k++) {
    const n = varint();
    const extra = varint();
    p += extra * 4;
    classes.push(buf.toString('utf8', p, p + n).replace(/\0+$/, ''));
    p += n;
  }

  p = valOff;
  const values = [];
  for (let k = 0; k < valCount; k++) {
    const key = keys[varint()];
    const type = buf[p++];
    let value;
    switch (type) {
      case 0: value = buf.readInt8(p); p += 1; break;
      case 1: value = buf.readInt16LE(p); p += 2; break;
      case 2: value = buf.readInt32LE(p); p += 4; break;
      case 3: value = Number(buf.readBigInt64LE(p)); p += 8; break;
      case 4: value = true; break;
      case 5: value = false; break;
      case 6: value = buf.readFloatLE(p); p += 4; break;
      case 7: value = buf.readDoubleLE(p); p += 8; break;
      case 8: { const n = varint(); value = Buffer.from(buf.subarray(p, p + n)); p += n; break; }
      case 9: value = null; break;
      case 10: value = { ref: buf.readUInt32LE(p) }; p += 4; break;
      default: throw new Error('unknown value type ' + type);
    }
    values.push({ key, value });
  }

  p = objOff;
  const objects = [];
  for (let k = 0; k < objCount; k++) {
    const cls = classes[varint()];
    const first = varint();
    const count = varint();
    objects.push({ cls, values: values.slice(first, first + count) });
  }
  return { objects };
}

const STRING_CLASSES = new Set(['NSString', 'NSMutableString', 'NSLocalizableString', 'NSLocalizedString']);

function dataText(b) {
  if (!b.length) return '""';
  if (b.toString('latin1', 0, 6) === 'bplist') return `<binary plist, ${b.length} bytes>`;
  if (b.toString('latin1', 0, 10) === 'NIBArchive') return `<nested nib, ${b.length} bytes>`;
  const s = b.toString('utf8');
  if (/^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(s) && !s.includes('�')) return JSON.stringify(s);
  return `<${b.length} bytes: ${b.subarray(0, 24).toString('hex')}${b.length > 24 ? '…' : ''}>`;
}

/** Readable text dump of a NIBArchive. */
function nibText(buf, name) {
  const nib = readNib(buf);
  if (!nib) return null;
  const { objects } = nib;
  const inline = (ref) => {
    const o = objects[ref];
    if (!o) return `#${ref}`;
    if (STRING_CLASSES.has(o.cls)) {
      const bytes = o.values.find((v) => v.key === 'NS.bytes' || v.key === 'NS.string');
      if (bytes) return Buffer.isBuffer(bytes.value) ? dataText(bytes.value) : JSON.stringify(String(bytes.value));
    }
    if (o.cls === 'NSNumber' || o.cls === 'NSDecimalNumber') {
      const n = o.values.find((v) => /^NS\.(intval|dblval|fltval|boolval)$/.test(v.key));
      if (n) return String(n.value);
    }
    return `#${ref} ${o.cls}`;
  };
  const show = (v) => {
    if (v === null) return 'nil';
    if (Buffer.isBuffer(v)) return dataText(v);
    if (typeof v === 'object' && 'ref' in v) return inline(v.ref);
    return String(v);
  };
  const lines = [`// ${name}: compiled Interface Builder file, ${objects.length} archived objects. Decoded by DropDecompiler.`, ''];
  const counts = {};
  for (const o of objects) counts[o.cls] = (counts[o.cls] || 0) + 1;
  const ui = Object.entries(counts).filter(([c]) => /^(UI|NS|MK|WK|SK|AV)/.test(c) && !/^NS(Array|Dictionary|String|Mutable|Number|Set|Data|Null)/.test(c))
    .sort((a, b) => b[1] - a[1]).map(([c, n]) => `${c} ×${n}`);
  if (ui.length) lines.push(`// Classes: ${ui.join(', ')}`, '');
  objects.forEach((o, k) => {
    if (STRING_CLASSES.has(o.cls) || o.cls === 'NSNumber') return; // shown inline where they're used
    lines.push(`#${k} ${o.cls}`);
    for (const { key, value } of o.values) lines.push(`    ${key} = ${show(value)}`);
  });
  return lines.join('\n') + '\n';
}

module.exports = { readNib, nibText };
