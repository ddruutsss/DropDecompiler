// Mach-O reader (iOS / macOS executables, frameworks, dylibs): headers, load commands, segments and sections,
// linked libraries, encryption (FairPlay), code-signature entitlements, and pointer decoding for both modern
// "chained fixups" (iOS 15+, incl. arm64e) and the classic rebase/bind opcodes, so that Objective-C and Swift
// metadata can be followed exactly as dyld would.

const CPU = { 7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32' };
const PLATFORM = { 1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 10: 'DriverKit', 11: 'visionOS', 12: 'visionOS Simulator' };
const FILETYPE = { 1: 'object', 2: 'executable', 6: 'dylib', 7: 'dyld', 8: 'bundle', 9: 'dylib stub', 10: 'dSYM', 11: 'kext' };

const LC = {
  SEGMENT_64: 0x19, SYMTAB: 0x2, DYLIB: [0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20], ID_DYLIB: 0xd, UUID: 0x1b,
  RPATH: 0x8000001c, MAIN: 0x80000028, BUILD_VERSION: 0x32, VERSION_MIN_IPHONEOS: 0x25, VERSION_MIN_MACOSX: 0x24,
  ENCRYPTION_INFO: 0x21, ENCRYPTION_INFO_64: 0x2c, CODE_SIGNATURE: 0x1d, DYLD_INFO: 0x22, DYLD_INFO_ONLY: 0x80000022,
  CHAINED_FIXUPS: 0x80000034, SOURCE_VERSION: 0x2a,
};

const ver = (v) => `${v >>> 16}.${(v >>> 8) & 0xff}.${v & 0xff}`.replace(/\.0$/, '');

/** Slices of a (possibly universal) Mach-O file: [{ cpu, offset, size }]. */
function slices(buf) {
  const magic = buf.readUInt32BE(0);
  if (magic === 0xcafebabe || magic === 0xcafebabf) {
    const n = buf.readUInt32BE(4);
    const is64 = magic === 0xcafebabf;
    const out = [];
    for (let i = 0; i < n && i < 32; i++) {
      const o = 8 + i * (is64 ? 32 : 20);
      const cpu = buf.readUInt32BE(o);
      const sub = buf.readUInt32BE(o + 4) & 0xffffff;
      const offset = is64 ? Number(buf.readBigUInt64BE(o + 8)) : buf.readUInt32BE(o + 8);
      const size = is64 ? Number(buf.readBigUInt64BE(o + 16)) : buf.readUInt32BE(o + 12);
      out.push({ cpu: (CPU[cpu] || `cpu ${cpu}`) + (cpu === 0x0100000c && sub === 2 ? 'e' : ''), offset, size });
    }
    return out;
  }
  const le = buf.readUInt32LE(0);
  if (le === 0xfeedfacf || le === 0xfeedface) return [{ cpu: null, offset: 0, size: buf.length }];
  return [];
}

function isMachO(buf) {
  if (buf.length < 8) return false;
  const le = buf.readUInt32LE(0);
  if (le === 0xfeedfacf || le === 0xfeedface) return true;
  const be = buf.readUInt32BE(0);
  // 0xCAFEBABE is shared with Java classes: a universal binary has a small slice count there.
  return (be === 0xcafebabe || be === 0xcafebabf) && buf.readUInt32BE(4) > 0 && buf.readUInt32BE(4) < 45;
}

class MachO {
  /** Opens the best slice of a Mach-O buffer for analysis (arm64, then arm64e, then the first 64-bit one). */
  static open(buf) {
    const list = slices(buf);
    if (!list.length) throw new Error('not a Mach-O file');
    const pick = list.find((s) => s.cpu === 'arm64') || list.find((s) => s.cpu === 'arm64e') || list.find((s) => /64/.test(s.cpu || '')) || list[0];
    const m = new MachO(buf.subarray(pick.offset, pick.offset + pick.size));
    m.slices = list.map((s) => s.cpu).filter(Boolean);
    return m;
  }

  constructor(buf) {
    this.buf = buf;
    const magic = buf.readUInt32LE(0);
    if (magic !== 0xfeedfacf) throw new Error(magic === 0xfeedface ? '32-bit Mach-O files are not supported' : 'not a 64-bit Mach-O file');
    this.cputype = buf.readUInt32LE(4);
    this.cpusubtype = buf.readUInt32LE(8) & 0xffffff;
    this.cpu = (CPU[this.cputype] || `cpu ${this.cputype}`) + (this.cputype === 0x0100000c && this.cpusubtype === 2 ? 'e' : '');
    this.filetype = FILETYPE[buf.readUInt32LE(12)] || 'unknown';
    this.flags = buf.readUInt32LE(24);
    this.segments = [];
    this.dylibs = [];
    this.rpaths = [];
    this.binds = new Map(); // vmaddr -> symbol (classic binds)
    this.chained = null;
    this.parseCommands(buf.readUInt32LE(16));
    this.base = (this.segments.find((s) => s.name === '__TEXT') || { vmaddr: 0 }).vmaddr;
    if (this.chained) this.parseChainedFixups();
    else if (this.dyldInfo) this.parseBinds();
  }

  parseCommands(ncmds) {
    const b = this.buf;
    let p = 32;
    for (let i = 0; i < ncmds && p + 8 <= b.length; i++) {
      const cmd = b.readUInt32LE(p);
      const size = b.readUInt32LE(p + 4);
      if (size < 8) break;
      const str = (off) => { const s = p + b.readUInt32LE(p + off); const e = b.indexOf(0, s); return b.toString('utf8', s, e < 0 || e > p + size ? p + size : e); };
      if (cmd === LC.SEGMENT_64) {
        const seg = {
          name: b.toString('latin1', p + 8, p + 24).replace(/\0.*$/, ''),
          vmaddr: Number(b.readBigUInt64LE(p + 24)), vmsize: Number(b.readBigUInt64LE(p + 32)),
          fileoff: Number(b.readBigUInt64LE(p + 40)), filesize: Number(b.readBigUInt64LE(p + 48)), sections: [],
        };
        const nsects = b.readUInt32LE(p + 64);
        for (let s = 0; s < nsects; s++) {
          const o = p + 72 + s * 80;
          seg.sections.push({
            name: b.toString('latin1', o, o + 16).replace(/\0.*$/, ''), segment: seg.name,
            addr: Number(b.readBigUInt64LE(o + 32)), size: Number(b.readBigUInt64LE(o + 40)), offset: b.readUInt32LE(o + 48),
          });
        }
        this.segments.push(seg);
      } else if (LC.DYLIB.includes(cmd)) {
        const kind = { 0xc: 'load', 0x80000018: 'weak', 0x8000001f: 'reexport', 0x80000023: 'upward', 0x20: 'lazy' }[cmd];
        this.dylibs.push({ name: str(8), kind, current: ver(b.readUInt32LE(p + 16)), compat: ver(b.readUInt32LE(p + 20)) });
      } else if (cmd === LC.ID_DYLIB) this.installName = str(8);
      else if (cmd === LC.RPATH) this.rpaths.push(str(8));
      else if (cmd === LC.UUID) {
        const h = b.subarray(p + 8, p + 24).toString('hex').toUpperCase();
        this.uuid = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
      } else if (cmd === LC.MAIN) this.entryoff = Number(b.readBigUInt64LE(p + 8));
      else if (cmd === LC.BUILD_VERSION) {
        this.build = { platform: PLATFORM[b.readUInt32LE(p + 8)] || 'unknown', minos: ver(b.readUInt32LE(p + 12)), sdk: ver(b.readUInt32LE(p + 16)) };
      } else if (cmd === LC.VERSION_MIN_IPHONEOS || cmd === LC.VERSION_MIN_MACOSX) {
        this.build ||= { platform: cmd === LC.VERSION_MIN_IPHONEOS ? 'iOS' : 'macOS', minos: ver(b.readUInt32LE(p + 8)), sdk: ver(b.readUInt32LE(p + 12)) };
      } else if (cmd === LC.ENCRYPTION_INFO || cmd === LC.ENCRYPTION_INFO_64) {
        this.encryption = { cryptoff: b.readUInt32LE(p + 8), cryptsize: b.readUInt32LE(p + 12), cryptid: b.readUInt32LE(p + 16) };
      } else if (cmd === LC.CODE_SIGNATURE) this.codeSig = { off: b.readUInt32LE(p + 8), size: b.readUInt32LE(p + 12) };
      else if (cmd === LC.DYLD_INFO || cmd === LC.DYLD_INFO_ONLY) {
        this.dyldInfo = { bindOff: b.readUInt32LE(p + 16), bindSize: b.readUInt32LE(p + 20), weakOff: b.readUInt32LE(p + 24), weakSize: b.readUInt32LE(p + 28) };
      } else if (cmd === LC.CHAINED_FIXUPS) this.chained = { off: b.readUInt32LE(p + 8), size: b.readUInt32LE(p + 12) };
      else if (cmd === LC.SYMTAB) this.symtab = { symoff: b.readUInt32LE(p + 8), nsyms: b.readUInt32LE(p + 12), stroff: b.readUInt32LE(p + 16), strsize: b.readUInt32LE(p + 20) };
      else if (cmd === LC.SOURCE_VERSION) {
        const v = b.readBigUInt64LE(p + 8);
        this.sourceVersion = [Number(v >> 40n), Number((v >> 30n) & 0x3ffn), Number((v >> 20n) & 0x3ffn), Number((v >> 10n) & 0x3ffn), Number(v & 0x3ffn)].join('.').replace(/(\.0)+$/, '');
      }
      p += size;
    }
  }

  /** True when the code is FairPlay-encrypted (App Store builds): it can't be decompiled as it is. */
  get encrypted() { return !!(this.encryption && this.encryption.cryptid); }

  // ---------------------------------------------------------------- addressing

  section(name, segments = ['__DATA_CONST', '__DATA', '__DATA_DIRTY', '__TEXT', '__AUTH_CONST', '__AUTH']) {
    for (const seg of segments) {
      const s = this.segments.find((x) => x.name === seg)?.sections.find((x) => x.name === name);
      if (s) return s;
    }
    for (const seg of this.segments) { const s = seg.sections.find((x) => x.name === name); if (s) return s; }
    return null;
  }

  segmentIndexOf(vm) {
    return this.segments.findIndex((s) => vm >= s.vmaddr && vm < s.vmaddr + s.vmsize);
  }

  /** File offset of a virtual address, or -1 if it isn't backed by file data. */
  off(vm) {
    for (const s of this.segments) {
      if (vm >= s.vmaddr && vm < s.vmaddr + s.filesize) return s.fileoff + (vm - s.vmaddr);
    }
    return -1;
  }

  u32(vm) { const o = this.off(vm); return o < 0 || o + 4 > this.buf.length ? 0 : this.buf.readUInt32LE(o); }
  i32(vm) { const o = this.off(vm); return o < 0 || o + 4 > this.buf.length ? 0 : this.buf.readInt32LE(o); }
  u16(vm) { const o = this.off(vm); return o < 0 || o + 2 > this.buf.length ? 0 : this.buf.readUInt16LE(o); }
  u8(vm) { const o = this.off(vm); return o < 0 || o >= this.buf.length ? 0 : this.buf[o]; }
  raw64(vm) { const o = this.off(vm); return o < 0 || o + 8 > this.buf.length ? 0n : this.buf.readBigUInt64LE(o); }

  cstr(vm, max = 4096) {
    const o = this.off(vm);
    if (o < 0) return null;
    const e = this.buf.indexOf(0, o);
    return this.buf.toString('utf8', o, e < 0 ? Math.min(this.buf.length, o + max) : Math.min(e, o + max));
  }

  /** Target of a relative 32-bit pointer stored at `vm` (Swift metadata). */
  rel(vm) { const d = this.i32(vm); return d ? vm + d : 0; }

  /**
   * Reads the pointer stored at `vm` the way dyld would bind/rebase it.
   * Returns { addr } for a pointer into this image, { sym } for a bind to another image, or null.
   */
  ptr(vm) {
    const raw = this.raw64(vm);
    if (this.chained) return this.decodeChained(raw, this.chainedFormat(vm));
    const sym = this.binds.get(vm);
    if (sym) return { sym };
    if (!raw) return null;
    return { addr: Number(raw & 0xffffffffffffn) };
  }

  /** Pointer at `vm` as an address in this image (0 when null or bound elsewhere). */
  addr(vm) { const p = this.ptr(vm); return p && p.addr ? p.addr : 0; }

  // ---------------------------------------------------------------- chained fixups (LC_DYLD_CHAINED_FIXUPS)

  parseChainedFixups() {
    const b = this.buf;
    const h = this.chained.off;
    const startsOff = h + b.readUInt32LE(h + 4);
    const importsOff = h + b.readUInt32LE(h + 8);
    const symbolsOff = h + b.readUInt32LE(h + 12);
    const count = b.readUInt32LE(h + 16);
    const importsFormat = b.readUInt32LE(h + 20);
    this.chained.formats = [];
    const segCount = b.readUInt32LE(startsOff);
    for (let i = 0; i < segCount; i++) {
      const so = b.readUInt32LE(startsOff + 4 + i * 4);
      this.chained.formats[i] = so ? b.readUInt16LE(startsOff + so + 6) : 0;
    }
    this.chained.defaultFormat = this.chained.formats.find((f) => f) || 2;
    const name = (off) => { const s = symbolsOff + off; const e = b.indexOf(0, s); return b.toString('utf8', s, e); };
    this.chained.imports = [];
    for (let i = 0; i < count; i++) {
      if (importsFormat === 1) { const v = b.readUInt32LE(importsOff + i * 4); this.chained.imports.push(name(v >>> 9)); }
      else if (importsFormat === 2) { const v = b.readUInt32LE(importsOff + i * 8); this.chained.imports.push(name(v >>> 9)); }
      else if (importsFormat === 3) { const v = b.readUInt32LE(importsOff + i * 16 + 4); this.chained.imports.push(name(v)); }
    }
  }

  chainedFormat(vm) {
    const i = this.segmentIndexOf(vm);
    return (i >= 0 && this.chained.formats[i]) || this.chained.defaultFormat;
  }

  decodeChained(raw, fmt) {
    if (!raw) return null;
    const imports = this.chained.imports;
    if (fmt === 2 || fmt === 6) { // DYLD_CHAINED_PTR_64 / 64_OFFSET
      if (raw >> 63n) return { sym: imports[Number(raw & 0xffffffn)] || null };
      const target = Number(raw & 0xfffffffffn);
      return { addr: fmt === 6 ? this.base + target : target };
    }
    if (fmt === 1 || fmt === 9 || fmt === 12) { // arm64e variants
      const auth = raw >> 63n;
      const bind = (raw >> 62n) & 1n;
      if (bind) return { sym: imports[Number(raw & (fmt === 12 ? 0xffffffn : 0xffffn))] || null };
      if (auth) return { addr: this.base + Number(raw & 0xffffffffn) };
      const target = Number(raw & 0x7ffffffffffn);
      return { addr: fmt === 1 ? target : this.base + target };
    }
    return { addr: Number(raw & 0xffffffffffn) };
  }

  // ---------------------------------------------------------------- classic binds (LC_DYLD_INFO)

  parseBinds() {
    const run = (off, size) => {
      const b = this.buf;
      let p = off;
      const end = off + size;
      let sym = null;
      let seg = 0;
      let segOff = 0;
      const uleb = () => { let v = 0; let s = 0; let x; do { x = b[p++]; v += (x & 0x7f) * 2 ** s; s += 7; } while (x & 0x80 && p < end); return v; };
      const sleb = () => { let v = 0; let s = 0; let x; do { x = b[p++]; v |= (x & 0x7f) << s; s += 7; } while (x & 0x80 && p < end); return v; };
      const bind = () => { const sg = this.segments[seg]; if (sg && sym) this.binds.set(sg.vmaddr + segOff, sym); };
      while (p < end) {
        const byte = b[p++];
        const op = byte & 0xf0;
        const imm = byte & 0x0f;
        if (op === 0x00) continue; // DONE (separates entries; keep reading to the end)
        else if (op === 0x10 || op === 0x30 || op === 0x50) { /* ordinal / type: not needed */ }
        else if (op === 0x20) uleb();
        else if (op === 0x40) { const e = b.indexOf(0, p); sym = b.toString('utf8', p, e); p = e + 1; }
        else if (op === 0x60) sleb();
        else if (op === 0x70) { seg = imm; segOff = uleb(); }
        else if (op === 0x80) segOff += uleb();
        else if (op === 0x90) { bind(); segOff += 8; }
        else if (op === 0xa0) { bind(); segOff += uleb() + 8; }
        else if (op === 0xb0) { bind(); segOff += imm * 8 + 8; }
        else if (op === 0xc0) { const n = uleb(); const skip = uleb(); for (let k = 0; k < n; k++) { bind(); segOff += skip + 8; } }
        else break; // threaded binds (arm64e, pre-iOS 15): not decoded
      }
    };
    const d = this.dyldInfo;
    if (d.bindSize) run(d.bindOff, d.bindSize);
    if (d.weakSize) run(d.weakOff, d.weakSize);
  }

  // ---------------------------------------------------------------- code signature

  /** { identifier, teamId, entitlements (XML string) } from the embedded code signature. */
  signature() {
    if (!this.codeSig) return null;
    const b = this.buf;
    const base = this.codeSig.off;
    if (base + 12 > b.length || b.readUInt32BE(base) !== 0xfade0cc0) return null;
    const out = {};
    const n = b.readUInt32BE(base + 8);
    for (let i = 0; i < n && i < 64; i++) {
      const off = base + b.readUInt32BE(base + 16 + i * 8);
      if (off + 8 > b.length) continue;
      const magic = b.readUInt32BE(off);
      const len = b.readUInt32BE(off + 4);
      if (magic === 0xfade7171) out.entitlements = b.toString('utf8', off + 8, off + len);
      else if (magic === 0xfade0c02 && !out.identifier) {
        const version = b.readUInt32BE(off + 8);
        const ident = b.readUInt32BE(off + 20);
        out.identifier = b.toString('utf8', off + ident, b.indexOf(0, off + ident));
        if (version >= 0x20200) {
          const team = b.readUInt32BE(off + 48);
          if (team) out.teamId = b.toString('utf8', off + team, b.indexOf(0, off + team));
        }
      }
    }
    return out;
  }

  /** Exported symbol names from the symbol table (empty for stripped binaries). */
  symbols(limit = 200000) {
    if (!this.symtab) return [];
    const { symoff, nsyms, stroff } = this.symtab;
    const out = [];
    for (let i = 0; i < nsyms && out.length < limit; i++) {
      const o = symoff + i * 16;
      if (o + 16 > this.buf.length) break;
      const type = this.buf[o + 4];
      if (type & 0xe0) continue; // debugging (stab) entries
      if ((type & 0x0e) !== 0x0e) continue; // only defined in a section
      const s = stroff + this.buf.readUInt32LE(o);
      const name = this.buf.toString('utf8', s, this.buf.indexOf(0, s));
      out.push({ name, addr: Number(this.buf.readBigUInt64LE(o + 8)) });
    }
    return out;
  }
}

module.exports = { MachO, isMachO, slices };
