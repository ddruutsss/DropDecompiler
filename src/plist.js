// Property lists (Apple): binary ("bplist00") and XML, to JS values and back to readable XML.
// Used for Info.plist, entitlements, provisioning profiles, compiled .strings files and .stringsdict.

const APPLE_EPOCH = Date.UTC(2001, 0, 1);

class UID {
  constructor(value) { this.UID = value; }
}

/** Parses a binary property list. Dates become Date, data becomes Buffer, UIDs become UID. */
function parseBinary(buf) {
  if (buf.length < 40 || buf.toString('latin1', 0, 8) !== 'bplist00') throw new Error('not a binary plist');
  const t = buf.length - 32;
  const offsetSize = buf[t + 6];
  const refSize = buf[t + 7];
  const numObjects = Number(buf.readBigUInt64BE(t + 8));
  const top = Number(buf.readBigUInt64BE(t + 16));
  const tableOffset = Number(buf.readBigUInt64BE(t + 24));
  const uint = (off, size) => {
    let v = 0;
    for (let i = 0; i < size; i++) v = v * 256 + buf[off + i];
    return v;
  };
  const offsets = new Array(numObjects);
  for (let i = 0; i < numObjects; i++) offsets[i] = uint(tableOffset + i * offsetSize, offsetSize);
  const seen = new Set();

  const read = (ref, depth = 0) => {
    if (depth > 512 || ref >= numObjects) throw new Error('corrupt binary plist');
    const off = offsets[ref];
    const marker = buf[off];
    const hi = marker >> 4;
    const lo = marker & 0xf;
    const lengthAt = (o) => {
      if (lo !== 0xf) return [lo, o + 1];
      const intMarker = buf[o + 1];
      const size = 1 << (intMarker & 0xf);
      return [uint(o + 2, size), o + 2 + size];
    };
    switch (hi) {
      case 0x0:
        if (marker === 0x08) return false;
        if (marker === 0x09) return true;
        return null;
      case 0x1: {
        const size = 1 << lo;
        if (size === 8) {
          const v = buf.readBigInt64BE(off + 1);
          return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
        }
        if (size === 16) return buf.readBigInt64BE(off + 9);
        return uint(off + 1, size);
      }
      case 0x2: return lo === 2 ? buf.readFloatBE(off + 1) : buf.readDoubleBE(off + 1);
      case 0x3: return new Date(APPLE_EPOCH + buf.readDoubleBE(off + 1) * 1000);
      case 0x4: { const [len, s] = lengthAt(off); return Buffer.from(buf.subarray(s, s + len)); }
      case 0x5: { const [len, s] = lengthAt(off); return buf.toString('latin1', s, s + len); }
      case 0x6: {
        const [len, s] = lengthAt(off);
        const b = Buffer.from(buf.subarray(s, s + len * 2));
        b.swap16();
        return b.toString('utf16le');
      }
      case 0x7: { const [len, s] = lengthAt(off); return buf.toString('utf8', s, s + len); } // UTF-8 string (newer plists)
      case 0x8: return new UID(uint(off + 1, lo + 1));
      case 0xa: case 0xc: {
        if (seen.has(ref)) throw new Error('cyclic binary plist');
        seen.add(ref);
        const [len, s] = lengthAt(off);
        const out = [];
        for (let i = 0; i < len; i++) out.push(read(uint(s + i * refSize, refSize), depth + 1));
        seen.delete(ref);
        return out;
      }
      case 0xd: {
        if (seen.has(ref)) throw new Error('cyclic binary plist');
        seen.add(ref);
        const [len, s] = lengthAt(off);
        const out = {};
        for (let i = 0; i < len; i++) {
          const k = read(uint(s + i * refSize, refSize), depth + 1);
          out[String(k)] = read(uint(s + (len + i) * refSize, refSize), depth + 1);
        }
        seen.delete(ref);
        return out;
      }
      default: throw new Error('unknown binary plist object 0x' + marker.toString(16));
    }
  };
  return read(top);
}

// ---------------------------------------------------------------- XML

function unescapeXml(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d) => String.fromCodePoint(Number(d))).replace(/&amp;/g, '&');
}

/** Parses an XML property list (as found in Info.plist, entitlements and provisioning profiles). */
function parseXml(xml) {
  const tokens = xml.replace(/<\?xml[^>]*>|<!DOCTYPE[^>]*>|<!--[\s\S]*?-->/g, '').match(/<[^>]+>|[^<]+/g) || [];
  let i = 0;
  const next = () => { while (i < tokens.length && !tokens[i].startsWith('<') && !tokens[i].trim()) i++; return tokens[i++]; };
  const text = () => { let s = ''; while (i < tokens.length && !tokens[i].startsWith('<')) s += tokens[i++]; return unescapeXml(s); };
  const value = (tag) => {
    const name = tag.replace(/^<\/?|\/?>$/g, '').split(/\s/)[0];
    if (tag.endsWith('/>')) {
      if (name === 'true') return true;
      if (name === 'false') return false;
      if (name === 'dict') return {};
      if (name === 'array') return [];
      if (name === 'string') return '';
      return null;
    }
    if (name === 'plist') { const v = value(next()); next(); return v; }
    if (name === 'dict') {
      const o = {};
      for (let t = next(); t && t !== '</dict>'; t = next()) {
        if (t !== '<key>') continue;
        const k = text();
        next(); // </key>
        o[k] = value(next());
      }
      return o;
    }
    if (name === 'array') {
      const a = [];
      for (let t = next(); t && t !== '</array>'; t = next()) a.push(value(t));
      return a;
    }
    const s = text();
    next(); // closing tag
    if (name === 'string') return s;
    if (name === 'integer') return Number(s);
    if (name === 'real') return Number(s);
    if (name === 'date') return new Date(s);
    if (name === 'data') return Buffer.from(s.replace(/\s+/g, ''), 'base64');
    if (name === 'true') return true;
    if (name === 'false') return false;
    return s;
  };
  const first = next();
  return first ? value(first) : null;
}

/** Any property list in a buffer (binary or XML). */
function parse(buf) {
  if (buf.toString('latin1', 0, 8) === 'bplist00') return parseBinary(buf);
  let text = buf.toString('utf8');
  if (buf[0] === 0xff && buf[1] === 0xfe) text = buf.subarray(2).toString('utf16le');
  return parseXml(text);
}

function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Serializes a value as an XML plist, the format Xcode uses. Long data blobs are kept, wrapped. */
function toXml(value) {
  const lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">', '<plist version="1.0">'];
  const emit = (v, ind) => {
    const pad = '\t'.repeat(ind);
    if (v === null || v === undefined) lines.push(`${pad}<string></string>`);
    else if (v === true) lines.push(`${pad}<true/>`);
    else if (v === false) lines.push(`${pad}<false/>`);
    else if (typeof v === 'number') lines.push(Number.isInteger(v) ? `${pad}<integer>${v}</integer>` : `${pad}<real>${v}</real>`);
    else if (typeof v === 'bigint') lines.push(`${pad}<integer>${v}</integer>`);
    else if (typeof v === 'string') lines.push(`${pad}<string>${escapeXml(v)}</string>`);
    else if (v instanceof Date) lines.push(`${pad}<date>${isNaN(v) ? '' : v.toISOString().replace(/\.\d{3}Z$/, 'Z')}</date>`);
    else if (Buffer.isBuffer(v)) {
      const b64 = v.toString('base64');
      lines.push(`${pad}<data>`);
      for (let k = 0; k < b64.length; k += 68) lines.push(pad + b64.slice(k, k + 68));
      lines.push(`${pad}</data>`);
    } else if (v instanceof UID) {
      lines.push(`${pad}<dict>`, `${pad}\t<key>CF$UID</key>`, `${pad}\t<integer>${v.UID}</integer>`, `${pad}</dict>`);
    } else if (Array.isArray(v)) {
      if (!v.length) { lines.push(`${pad}<array/>`); return; }
      lines.push(`${pad}<array>`);
      for (const x of v) emit(x, ind + 1);
      lines.push(`${pad}</array>`);
    } else {
      const keys = Object.keys(v);
      if (!keys.length) { lines.push(`${pad}<dict/>`); return; }
      lines.push(`${pad}<dict>`);
      for (const k of keys) { lines.push(`${pad}\t<key>${escapeXml(k)}</key>`); emit(v[k], ind + 1); }
      lines.push(`${pad}</dict>`);
    }
  };
  emit(value, 0);
  lines.push('</plist>', '');
  return lines.join('\n');
}

/** A .strings file (binary plist dictionary) back in Xcode's text form: "key" = "value"; */
function toStrings(dict) {
  const q = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\t/g, '\\t') + '"';
  return Object.entries(dict).map(([k, v]) => `${q(k)} = ${q(typeof v === 'string' ? v : JSON.stringify(v))};`).join('\n') + '\n';
}

/** The XML plist inside a CMS-signed provisioning profile (embedded.mobileprovision). */
function provisioningPlist(buf) {
  const s = buf.toString('latin1');
  const a = s.indexOf('<?xml');
  const b = s.indexOf('</plist>', a);
  if (a < 0 || b < 0) return null;
  return buf.subarray(a, b + 8).toString('utf8');
}

module.exports = { parse, parseBinary, parseXml, toXml, toStrings, provisioningPlist, UID };
