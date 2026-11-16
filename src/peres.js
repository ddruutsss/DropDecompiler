// Windows PE resources (icons, dialogs, menus, string tables, version info, manifest…) → a .rc project
// that rc.exe compiles back into the same resources. Dialogs, menus, string tables and version info are
// written as readable, editable RC script; everything else is saved as a file the .rc includes.
// When rc.exe is available every resource is checked by compiling it again and comparing bytes;
// any text-form resource that doesn't come back identical is switched to its raw binary form.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

const RT = {
  CURSOR: 1, BITMAP: 2, ICON: 3, MENU: 4, DIALOG: 5, STRING: 6, FONTDIR: 7, FONT: 8, ACCELERATOR: 9,
  RCDATA: 10, MESSAGETABLE: 11, GROUP_CURSOR: 12, GROUP_ICON: 14, VERSION: 16, DLGINCLUDE: 17,
  PLUGPLAY: 19, VXD: 20, ANICURSOR: 21, ANIICON: 22, HTML: 23, MANIFEST: 24,
};
const RT_NAME = Object.fromEntries(Object.entries(RT).map(([k, v]) => [v, k]));

// ---------------------------------------------------------------- PE parsing

function rvaToOffset(sections, rva) {
  for (const s of sections) {
    if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return rva - s.va + s.raw;
  }
  return -1;
}

/** All resources of a PE file: [{ type, name, lang, data }] (type/name are numbers or strings). */
function readResources(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return [];
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 24 > buf.length || buf.readUInt32LE(pe) !== 0x4550) return [];
  const nSections = buf.readUInt16LE(pe + 6);
  const optSize = buf.readUInt16LE(pe + 20);
  const opt = pe + 24;
  const magic = buf.readUInt16LE(opt);
  const dirs = opt + (magic === 0x20b ? 112 : 96);
  const resRva = buf.readUInt32LE(dirs + 2 * 8);
  if (!resRva) return [];
  const sections = [];
  for (let i = 0, s = opt + optSize; i < nSections; i++, s += 40) {
    sections.push({
      vsize: buf.readUInt32LE(s + 8), va: buf.readUInt32LE(s + 12),
      rawSize: buf.readUInt32LE(s + 16), raw: buf.readUInt32LE(s + 20),
    });
  }
  const root = rvaToOffset(sections, resRva);
  if (root < 0) return [];

  const out = [];
  const seen = new Set(); // guards against looping directories in damaged files
  const nameAt = (off) => {
    const p = root + off;
    const len = buf.readUInt16LE(p);
    return buf.toString('utf16le', p + 2, p + 2 + len * 2);
  };
  const walk = (dirOff, level, ids) => {
    if (seen.has(dirOff) || level > 2) return;
    seen.add(dirOff);
    const d = root + dirOff;
    const count = buf.readUInt16LE(d + 12) + buf.readUInt16LE(d + 14);
    for (let i = 0; i < count; i++) {
      const e = d + 16 + i * 8;
      const nameField = buf.readUInt32LE(e);
      const dataField = buf.readUInt32LE(e + 4);
      const id = nameField & 0x80000000 ? nameAt(nameField & 0x7fffffff) : nameField & 0xffff;
      if (dataField & 0x80000000) {
        walk(dataField & 0x7fffffff, level + 1, [...ids, id]);
      } else if (level === 2) {
        const leaf = root + dataField;
        const off = rvaToOffset(sections, buf.readUInt32LE(leaf));
        const size = buf.readUInt32LE(leaf + 4);
        if (off < 0 || off + size > buf.length) continue;
        out.push({ type: ids[0], name: ids[1], lang: id, data: Buffer.from(buf.subarray(off, off + size)) });
      }
    }
  };
  try { walk(0, 0, []); } catch { /* truncated resource section: keep what was read */ }
  return out;
}

/** Entries of a compiled .res file, in the same shape as readResources. */
function readRes(buf) {
  const out = [];
  let p = 0;
  const sz = () => {
    if (buf.readUInt16LE(p) === 0xffff) { const v = buf.readUInt16LE(p + 2); p += 4; return v; }
    const start = p;
    while (buf.readUInt16LE(p) !== 0) p += 2;
    const s = buf.toString('utf16le', start, p);
    p += 2;
    return s;
  };
  while (p + 32 <= buf.length) {
    const start = p;
    const dataSize = buf.readUInt32LE(p);
    const headerSize = buf.readUInt32LE(p + 4);
    p += 8;
    const type = sz();
    const name = sz();
    p = (p + 3) & ~3;
    p += 6; // DataVersion, MemoryFlags
    const lang = buf.readUInt16LE(p);
    p = start + headerSize;
    const data = Buffer.from(buf.subarray(p, p + dataSize));
    p = (p + dataSize + 3) & ~3;
    if (type === 0 && name === 0 && dataSize === 0) continue; // the empty first entry
    out.push({ type, name, lang, data });
  }
  return out;
}

// ---------------------------------------------------------------- RC text helpers

const hex = (n) => '0x' + (n >>> 0).toString(16).padStart(8, '0');

// rc.exe: "" is a quote; \xHHHH (exactly 4 digits in L"" strings) for anything unusual. A literal
// backslash is written as \x005c because rc drops some \\ sequences.
function rcStr(s) {
  let o = 'L"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') o += '""';
    else if (c >= 0x20 && c < 0x7f && ch !== '\\') o += ch;
    else if (c > 0xffff) {
      const u = ch.charCodeAt(0), l = ch.charCodeAt(1);
      o += '\\x' + u.toString(16).padStart(4, '0') + '\\x' + l.toString(16).padStart(4, '0');
    } else o += '\\x' + c.toString(16).padStart(4, '0');
  }
  return o + '"';
}

// rc uppercases string names whatever you write; Windows looks names up case-insensitively anyway.
function rcName(n) {
  if (typeof n === 'number') return String(n);
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(n) ? n : null;
}

const langStmt = (lang) => `LANGUAGE ${lang & 0x3ff}, ${lang >> 10}`;

class Reader {
  constructor(buf) { this.b = buf; this.p = 0; }
  u8() { return this.b[this.p++]; }
  u16() { const v = this.b.readUInt16LE(this.p); this.p += 2; return v; }
  i16() { const v = this.b.readInt16LE(this.p); this.p += 2; return v; }
  u32() { const v = this.b.readUInt32LE(this.p); this.p += 4; return v; }
  align4() { this.p = (this.p + 3) & ~3; }
  sz() {
    const start = this.p;
    while (this.b.readUInt16LE(this.p) !== 0) this.p += 2;
    const s = this.b.toString('utf16le', start, this.p);
    this.p += 2;
    return s;
  }
  szOrOrd() {
    const first = this.b.readUInt16LE(this.p);
    if (first === 0) { this.p += 2; return null; }
    if (first === 0xffff) { this.p += 2; return this.u16(); }
    return this.sz();
  }
  get done() { return this.p >= this.b.length; }
}

// ---------------------------------------------------------------- dialogs

const WS_CHILD = 0x40000000;
const WS_VISIBLE = 0x10000000;

function styleExpr(style, defaults) {
  // rc ORs `defaults` into control styles; NOT takes back bits the original didn't have.
  let s = hex(style);
  for (const bit of [WS_CHILD, WS_VISIBLE]) if (defaults & bit && !(style & bit)) s += ' | NOT ' + hex(bit);
  return s;
}

function dialogToRc(name, data) {
  const r = new Reader(data);
  const ex = data.length >= 4 && data.readUInt16LE(0) === 1 && data.readUInt16LE(2) === 0xffff;
  let helpId = 0, exStyle, style;
  if (ex) { r.u16(); r.u16(); helpId = r.u32(); exStyle = r.u32(); style = r.u32(); }
  else { style = r.u32(); exStyle = r.u32(); }
  const count = r.u16();
  const [x, y, cx, cy] = [r.i16(), r.i16(), r.i16(), r.i16()];
  const menu = r.szOrOrd();
  const cls = r.szOrOrd();
  const title = r.sz();
  const lines = [`${name} ${ex ? 'DIALOGEX' : 'DIALOG'} ${x}, ${y}, ${cx}, ${cy}${ex && helpId ? ', ' + helpId : ''}`];
  if (title) lines.push(`CAPTION ${rcStr(title)}`);
  lines.push(`STYLE ${hex(style)}`);
  if (exStyle) lines.push(`EXSTYLE ${hex(exStyle)}`);
  if (menu !== null) lines.push(`MENU ${typeof menu === 'number' ? menu : rcName(menu) ?? rcStr(menu)}`);
  if (cls !== null) lines.push(`CLASS ${typeof cls === 'number' ? cls : rcStr(cls)}`);
  if (style & 0x40) { // DS_SETFONT (and DS_SHELLFONT)
    const pt = r.u16();
    if (ex) {
      const weight = r.u16(), italic = r.u8(), charset = r.u8();
      lines.push(`FONT ${pt}, ${rcStr(r.sz())}, ${weight}, ${italic}, ${charset}`);
    } else lines.push(`FONT ${pt}, ${rcStr(r.sz())}`);
  }
  lines.push('BEGIN');
  for (let i = 0; i < count; i++) {
    r.align4();
    let cHelp = 0, cEx, cStyle, id;
    if (ex) { cHelp = r.u32(); cEx = r.u32(); cStyle = r.u32(); }
    else { cStyle = r.u32(); cEx = r.u32(); }
    const [ix, iy, icx, icy] = [r.i16(), r.i16(), r.i16(), r.i16()];
    id = ex ? r.u32() | 0 : r.i16();
    const ccls = r.szOrOrd();
    const text = r.szOrOrd();
    const extra = r.u16();
    if (extra) throw new Error('control creation data');
    if (ccls === null) throw new Error('control without class');
    const ORD = { 0x80: 'BUTTON', 0x81: 'EDIT', 0x82: 'STATIC', 0x83: 'LISTBOX', 0x84: 'SCROLLBAR', 0x85: 'COMBOBOX' };
    if (typeof ccls === 'string' && Object.values(ORD).includes(ccls.toUpperCase())) throw new Error('predefined class by name');
    const clsText = typeof ccls === 'number' ? (ORD[ccls] ? `"${ORD[ccls]}"` : null) : rcStr(ccls);
    if (!clsText) throw new Error('unknown class ordinal');
    const textExpr = text === null ? '""' : typeof text === 'number' ? String(text) : rcStr(text);
    let line = `    CONTROL ${textExpr}, ${id}, ${clsText}, ${styleExpr(cStyle, WS_CHILD | WS_VISIBLE)}, ${ix}, ${iy}, ${icx}, ${icy}`;
    if (cEx || cHelp) line += `, ${hex(cEx)}`;
    if (cHelp) line += `, ${cHelp}`;
    lines.push(line);
  }
  lines.push('END');
  return lines.join('\n');
}

// ---------------------------------------------------------------- menus

const MENU_FLAGS = { 0x1: 'GRAYED', 0x2: 'INACTIVE', 0x8: 'CHECKED', 0x20: 'MENUBARBREAK', 0x40: 'MENUBREAK', 0x4000: 'HELP' };

function menuToRc(name, data) {
  const r = new Reader(data);
  const ver = r.u16();
  const lines = [];
  if (ver === 0) {
    if (r.u16() !== 0) throw new Error('menu header');
    lines.push(`${name} MENU`);
    const items = (depth) => {
      const pad = '    '.repeat(depth);
      lines.push(pad.slice(4) + 'BEGIN');
      for (;;) {
        const flags = r.u16();
        const popup = flags & 0x10;
        const id = popup ? 0 : r.u16();
        const text = r.sz();
        const rest = flags & ~0x90;
        let opts = '';
        for (const [bit, word] of Object.entries(MENU_FLAGS)) if (rest & bit) opts += ', ' + word;
        if (rest & ~Object.keys(MENU_FLAGS).reduce((a, b) => a | b, 0)) throw new Error('menu flags');
        if (popup) {
          lines.push(`${pad}POPUP ${rcStr(text)}${opts}`);
          items(depth + 1);
        } else if (!text && !id && !rest) lines.push(`${pad}MENUITEM SEPARATOR`);
        else lines.push(`${pad}MENUITEM ${rcStr(text)}, ${id}${opts}`);
        if (flags & 0x80) break;
      }
      lines.push(pad.slice(4) + 'END');
    };
    items(1);
  } else if (ver === 1) {
    const off = r.u16();
    const help = r.u32();
    r.p = 4 + off;
    lines.push(`${name} MENUEX${help ? '' : ''}`);
    const items = (depth) => {
      const pad = '    '.repeat(depth);
      lines.push(pad.slice(4) + 'BEGIN');
      for (;;) {
        r.align4();
        const type = r.u32(), state = r.u32(), id = r.u32() | 0, res = r.u16();
        const text = r.sz();
        if (res & 1) {
          r.align4();
          const h = r.u32();
          lines.push(`${pad}POPUP ${rcStr(text)}, ${id}, ${hex(type)}, ${hex(state)}, ${h}`);
          items(depth + 1);
        } else lines.push(`${pad}MENUITEM ${rcStr(text)}, ${id}, ${hex(type)}, ${hex(state)}`);
        if (res & 0x80) break;
      }
      lines.push(pad.slice(4) + 'END');
    };
    items(1);
  } else throw new Error('menu version');
  return lines.join('\n');
}

// ---------------------------------------------------------------- version info

function versionToRc(name, data) {
  const node = (p) => {
    const len = data.readUInt16LE(p);
    const valLen = data.readUInt16LE(p + 2);
    const type = data.readUInt16LE(p + 4);
    const r = new Reader(data);
    r.p = p + 6;
    const key = r.sz();
    r.align4();
    const valStart = r.p;
    const valBytes = type === 1 ? valLen * 2 : valLen;
    r.p += valBytes;
    r.align4();
    const kids = [];
    while (r.p < p + len) {
      const k = node(r.p);
      kids.push(k);
      r.p = (r.p + k.len + 3) & ~3;
    }
    return { len, key, type, value: data.subarray(valStart, valStart + valBytes), kids };
  };
  const root = node(0);
  if (root.key !== 'VS_VERSION_INFO' || root.value.length !== 52) throw new Error('version layout');
  const f = root.value;
  if (f.readUInt32LE(0) !== 0xfeef04bd) throw new Error('version signature');
  if (f.readUInt32LE(44) || f.readUInt32LE(48)) throw new Error('file date');
  const ver = (o) => [f.readUInt16LE(o + 2), f.readUInt16LE(o), f.readUInt16LE(o + 6), f.readUInt16LE(o + 4)].join(', ');
  const lines = [
    `${name} VERSIONINFO`,
    `FILEVERSION ${ver(8)}`,
    `PRODUCTVERSION ${ver(16)}`,
    `FILEFLAGSMASK ${hex(f.readUInt32LE(24))}`,
    `FILEFLAGS ${hex(f.readUInt32LE(28))}`,
    `FILEOS ${hex(f.readUInt32LE(32))}`,
    `FILETYPE ${hex(f.readUInt32LE(36))}`,
    `FILESUBTYPE ${hex(f.readUInt32LE(40))}`,
  ];
  const block = (n, depth) => {
    const pad = '    '.repeat(depth);
    lines.push(pad.slice(4) + 'BEGIN');
    for (const k of n.kids) {
      if (k.kids.length || (!k.value.length && k.type === 1 && depth < 3)) {
        lines.push(`${pad}BLOCK ${rcStr(k.key)}`);
        block(k, depth + 1);
      } else if (k.type === 1) {
        lines.push(`${pad}VALUE ${rcStr(k.key)}, ${rcStr(k.value.toString('utf16le').replace(/\0+$/, ''))}`);
      } else {
        if (k.value.length % 2) throw new Error('odd binary value');
        const words = [];
        for (let i = 0; i < k.value.length; i += 2) words.push('0x' + k.value.readUInt16LE(i).toString(16));
        lines.push(`${pad}VALUE ${rcStr(k.key)}, ${words.join(', ')}`);
      }
    }
    lines.push(pad.slice(4) + 'END');
  };
  block(root, 1);
  return lines.join('\n');
}

// ---------------------------------------------------------------- string tables

function stringTableToRc(block, data, lang) {
  const r = new Reader(data);
  const lines = ['STRINGTABLE', langStmt(lang), 'BEGIN'];
  for (let i = 0; i < 16 && !r.done; i++) {
    const len = r.u16();
    const s = data.toString('utf16le', r.p, r.p + len * 2);
    r.p += len * 2;
    if (len) lines.push(`    ${(block - 1) * 16 + i}, ${rcStr(s)}`);
  }
  if (lines.length === 3) throw new Error('empty string table'); // rc rejects an empty table
  lines.push('END');
  return lines.join('\n');
}

// ---------------------------------------------------------------- accelerators

function acceleratorsToRc(name, data) {
  const lines = [`${name} ACCELERATORS`, 'BEGIN'];
  for (let p = 0; p + 8 <= data.length; p += 8) {
    const flags = data.readUInt16LE(p), key = data.readUInt16LE(p + 2), cmd = data.readUInt16LE(p + 4);
    if (flags & ~0x9f) throw new Error('accelerator flags');
    const opts = [flags & 1 ? 'VIRTKEY' : 'ASCII'];
    if (flags & 2) opts.push('NOINVERT');
    if (flags & 4) opts.push('SHIFT');
    if (flags & 8) opts.push('CONTROL');
    if (flags & 0x10) opts.push('ALT');
    lines.push(`    ${key}, ${cmd}, ${opts.join(', ')}`);
    if (flags & 0x80) break;
  }
  lines.push('END');
  return lines.join('\n');
}

// ---------------------------------------------------------------- .res writer

// Resource types rc.exe only accepts as script, never as a raw file. When their script form can't be
// written exactly, they go into a pre-compiled extra.res that is linked next to app.res.
const SCRIPT_ONLY = new Set([RT.MENU, RT.DIALOG, RT.ACCELERATOR, 15, RT.VERSION, 18]);

function resEntry(r) {
  const id = (v) => {
    if (typeof v === 'number') { const b = Buffer.alloc(4); b.writeUInt16LE(0xffff, 0); b.writeUInt16LE(v, 2); return b; }
    return Buffer.from(v.toUpperCase() + '\0', 'utf16le');
  };
  let names = Buffer.concat([id(r.type), id(r.name)]);
  if ((8 + names.length) % 4) names = Buffer.concat([names, Buffer.alloc(4 - ((8 + names.length) % 4))]);
  const tail = Buffer.alloc(16);
  tail.writeUInt16LE(0x1030, 4); // MOVEABLE | PURE | DISCARDABLE, like rc.exe
  tail.writeUInt16LE(r.lang, 6);
  const head = Buffer.alloc(8);
  head.writeUInt32LE(r.data.length, 0);
  head.writeUInt32LE(8 + names.length + 16, 4);
  const pad = Buffer.alloc((4 - (r.data.length % 4)) % 4);
  return Buffer.concat([head, names, tail, r.data, pad]);
}

function writeResFile(entries) {
  return Buffer.concat([resEntry({ type: 0, name: 0, lang: 0, data: Buffer.alloc(0) }).subarray(0, 32), ...entries.map(resEntry)]);
}

// ---------------------------------------------------------------- icons, cursors, bitmaps

function groupToFile(group, images, cursor) {
  const r = new Reader(group);
  r.u16();
  const kind = r.u16();
  const count = r.u16();
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (cursor) {
      const w = r.u16(), h = r.u16(), planes = r.u16(), bits = r.u16(), size = r.u32(), id = r.u16();
      entries.push({ w, h, planes, bits, size, id });
    } else {
      const w = r.u8(), h = r.u8(), colors = r.u8(), res = r.u8(), planes = r.u16(), bits = r.u16(), size = r.u32(), id = r.u16();
      entries.push({ w, h, colors, res, planes, bits, size, id });
    }
  }
  const datas = entries.map((e) => images.get(e.id));
  if (datas.some((d) => !d)) return null;
  const head = Buffer.alloc(6 + 16 * count);
  head.writeUInt16LE(0, 0);
  head.writeUInt16LE(kind, 2);
  head.writeUInt16LE(count, 4);
  let offset = head.length;
  const bodies = [];
  entries.forEach((e, i) => {
    let d = datas[i];
    const o = 6 + 16 * i;
    if (cursor) {
      const hx = d.readUInt16LE(0), hy = d.readUInt16LE(2);
      d = d.subarray(4);
      head.writeUInt8(e.w & 0xff, o);
      head.writeUInt8((e.h / 2) & 0xff, o + 1);
      head.writeUInt16LE(hx, o + 4);
      head.writeUInt16LE(hy, o + 6);
    } else {
      head.writeUInt8(e.w, o);
      head.writeUInt8(e.h, o + 1);
      head.writeUInt8(e.colors, o + 2);
      head.writeUInt8(e.res, o + 3);
      head.writeUInt16LE(e.planes, o + 4);
      head.writeUInt16LE(e.bits, o + 6);
    }
    head.writeUInt32LE(d.length, o + 8);
    head.writeUInt32LE(offset, o + 12);
    offset += d.length;
    bodies.push(d);
  });
  return Buffer.concat([head, ...bodies]);
}

function dibToBmp(dib) {
  const hs = dib.readUInt32LE(0);
  let palette = 0;
  if (hs >= 40) {
    const bits = dib.readUInt16LE(14), comp = dib.readUInt32LE(16), used = dib.readUInt32LE(32);
    palette = (used || (bits <= 8 ? 1 << bits : 0)) * 4;
    if (hs === 40 && (comp === 3 || comp === 6)) palette += comp === 3 ? 12 : 16;
  } else if (hs === 12) {
    const bits = dib.readUInt16LE(10);
    palette = (bits <= 8 ? 1 << bits : 0) * 3;
  }
  const fh = Buffer.alloc(14);
  fh.write('BM', 0, 'latin1');
  fh.writeUInt32LE(14 + dib.length, 2);
  fh.writeUInt32LE(14 + hs + palette, 10);
  return Buffer.concat([fh, dib]);
}

// ---------------------------------------------------------------- project writer

const keyOf = (r) => `${typeof r.type === 'string' ? r.type.toUpperCase() : r.type}|${typeof r.name === 'string' ? r.name.toUpperCase() : r.name}|${r.lang}`;
const sha = (b) => crypto.createHash('sha1').update(b).digest('hex');

/** Compare rebuilt resources with the originals. Icons/cursors are compared by image content. */
function compareResources(orig, rebuilt) {
  const imgTypes = new Set([RT.ICON, RT.CURSOR]);
  const groupTypes = new Set([RT.GROUP_ICON, RT.GROUP_CURSOR]);
  const imgs = (list) => list.filter((r) => imgTypes.has(r.type)).map((r) => r.type + ':' + sha(r.data)).sort();
  const groupSig = (r, list) => {
    // Image ids are renumbered by rc, so a group is compared by the content of the images it lists.
    const cursor = r.type === RT.GROUP_CURSOR;
    const imgType = cursor ? RT.CURSOR : RT.ICON;
    const n = r.data.readUInt16LE(4);
    const parts = [r.data.subarray(0, 6).toString('hex')];
    for (let i = 0; i < n; i++) {
      const e = r.data.subarray(6 + i * 14, 6 + i * 14 + 14);
      const id = e.readUInt16LE(12);
      const img = list.find((x) => x.type === imgType && x.name === id);
      parts.push(e.subarray(0, 12).toString('hex') + ':' + (img ? sha(img.data) : 'missing'));
    }
    return parts.join('/');
  };
  const map = new Map(rebuilt.map((r) => [keyOf(r), r]));
  const bad = [];
  for (const r of orig) {
    if (imgTypes.has(r.type)) continue;
    const other = map.get(keyOf(r));
    // Version info sometimes carries a few bytes of zero padding after its declared length.
    const trim = (b) => (r.type === RT.VERSION ? b.subarray(0, b.readUInt16LE(0)) : b);
    const same = other && (groupTypes.has(r.type) ? groupSig(r, orig) === groupSig(other, rebuilt) : trim(r.data).equals(trim(other.data)));
    if (!same) bad.push(keyOf(r));
  }
  const a = imgs(orig).join(), b = imgs(rebuilt).join();
  return { bad, imagesMatch: a === b };
}

/**
 * Writes `<dir>/app.rc` and `<dir>/res/*` from the resources of `peFile`.
 * Returns { count, text, raw, skipped, rcPath } or null if the file has no resources.
 * `textFallback` is a set of resource keys to write in raw form (used after a failed round-trip).
 */
async function writeRcProject(resources, dir, textFallback = new Set()) {
  if (!resources.length) return null;
  const resDir = path.join(dir, 'res');
  await fsp.rm(resDir, { recursive: true, force: true });
  await fsp.mkdir(resDir, { recursive: true });
  const parts = [
    '// Resources extracted by DropDecompiler. Compile with:  rc /fo app.res app.rc',
    '// (or add app.rc to a Visual Studio project). Dialogs, menus, strings and version info are editable here.',
    '#pragma code_page(65001)',
    '',
  ];
  const stats = { count: 0, text: 0, raw: 0, extra: 0, skipped: [] };
  const extra = [];
  const fileName = (r, ext) => {
    const t = typeof r.type === 'number' ? (RT_NAME[r.type] || 'type' + r.type).toLowerCase() : r.type.replace(/[^\w]/g, '_');
    const n = String(r.name).replace(/[^\w]/g, '_');
    return `${t}_${n}${r.lang ? '_' + r.lang.toString(16) : ''}${ext}`;
  };
  const writeRes = async (r, data, ext) => {
    const f = fileName(r, ext);
    await fsp.writeFile(path.join(resDir, f), data);
    return `"res/${f}"`;
  };
  const icons = new Map(resources.filter((r) => r.type === RT.ICON).map((r) => [r.name, r.data]));
  const cursors = new Map(resources.filter((r) => r.type === RT.CURSOR).map((r) => [r.name, r.data]));

  for (const r of resources) {
    if (r.type === RT.ICON || r.type === RT.CURSOR) continue; // written through their groups
    stats.count++;
    const name = rcName(r.name);
    const typeTok = typeof r.type === 'number' ? String(r.type) : rcName(r.type);
    const lang = langStmt(r.lang);
    const toExtra = () => { stats.extra++; extra.push(r); };
    const raw = async () => {
      const riff = r.data.subarray(0, 4).toString('latin1') === 'RIFF';
      if (SCRIPT_ONLY.has(r.type) || r.type === RT.BITMAP || ((r.type === RT.ANICURSOR || r.type === RT.ANIICON) && !riff)) return toExtra();
      stats.raw++;
      parts.push(lang, `${name} ${typeTok} ${await writeRes(r, r.data, '.bin')}`, '');
    };
    // Names rc can't spell (spaces, punctuation) only fit in extra.res.
    if (name === null || typeTok === null) { toExtra(); continue; }
    const asText = !textFallback.has(keyOf(r));
    try {
      if (r.type === RT.GROUP_ICON || r.type === RT.GROUP_CURSOR) {
        const cur = r.type === RT.GROUP_CURSOR;
        const file = groupToFile(r.data, cur ? cursors : icons, cur);
        if (!file) { stats.skipped.push(keyOf(r)); stats.count--; continue; }
        stats.raw++;
        parts.push(lang, `${name} ${cur ? 'CURSOR' : 'ICON'} ${await writeRes(r, file, cur ? '.cur' : '.ico')}`, '');
      } else if (r.type === RT.BITMAP && asText) {
        stats.raw++;
        parts.push(lang, `${name} BITMAP ${await writeRes(r, dibToBmp(r.data), '.bmp')}`, '');
      } else if (r.type === RT.MANIFEST) {
        stats.raw++;
        parts.push(lang, `${name} 24 ${await writeRes(r, r.data, '.manifest')}`, '');
      } else if (asText && r.type === RT.DIALOG) {
        parts.push(lang, dialogToRc(name, r.data), '');
        stats.text++;
      } else if (asText && r.type === RT.MENU) {
        parts.push(lang, menuToRc(name, r.data), '');
        stats.text++;
      } else if (asText && r.type === RT.VERSION) {
        parts.push(lang, versionToRc(name, r.data), '');
        stats.text++;
      } else if (asText && r.type === RT.STRING && typeof r.name === 'number') {
        parts.push(stringTableToRc(r.name, r.data, r.lang), '');
        stats.text++;
      } else if (asText && r.type === RT.ACCELERATOR) {
        parts.push(lang, acceleratorsToRc(name, r.data), '');
        stats.text++;
      } else {
        await raw();
      }
    } catch {
      await raw(); // anything the text writers don't understand is kept byte-for-byte
    }
  }
  const rcPath = path.join(dir, 'app.rc');
  const extraPath = path.join(dir, 'extra.res');
  await fsp.rm(extraPath, { force: true });
  if (extra.length) {
    await fsp.writeFile(extraPath, writeResFile(extra));
    parts.splice(3, 0, `// ${extra.length} resource(s) that can't be written as script are in extra.res, already compiled: link it next to app.res.`);
  }
  await fsp.writeFile(rcPath, parts.join('\n') + '\n', 'utf8');
  return { ...stats, rcPath, extraPath: extra.length ? extraPath : null };
}

/** Newest rc.exe from an installed Windows SDK, or null. */
async function findRc() {
  if (process.platform !== 'win32') return null;
  const base = path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'Windows Kits', '10', 'bin');
  let vers = [];
  try { vers = (await fsp.readdir(base)).filter((v) => /^10\./.test(v)); } catch { return null; }
  vers.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  for (const v of vers) {
    for (const a of [arch, 'x64', 'x86']) {
      const p = path.join(base, v, a, 'rc.exe');
      try { await fsp.access(p); return p; } catch { /* next */ }
    }
  }
  return null;
}

module.exports = { readResources, readRes, writeRcProject, writeResFile, compareResources, findRc, keyOf, RT, RT_NAME };
