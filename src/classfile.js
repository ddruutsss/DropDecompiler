// Minimal Java .class reader: the class name, version, and its fields and methods. Used to check that a
// recompiled class still offers everything the rest of the program may call or read.

const ACC_PRIVATE = 0x0002;
const ACC_SYNTHETIC = 0x1000;

/** { name, major, members: Set("name:descriptor") of non-private, non-synthetic fields/methods } or null. */
function readClass(buf) {
  try {
    if (buf.length < 10 || buf.readUInt32BE(0) !== 0xcafebabe) return null;
    const major = buf.readUInt16BE(6);
    const count = buf.readUInt16BE(8);
    const utf8 = new Map();
    const classes = new Map();
    let p = 10;
    for (let i = 1; i < count; i++) {
      const tag = buf[p++];
      switch (tag) {
        case 1: { const len = buf.readUInt16BE(p); utf8.set(i, buf.toString('utf8', p + 2, p + 2 + len)); p += 2 + len; break; }
        case 7: classes.set(i, buf.readUInt16BE(p)); p += 2; break;
        case 8: case 16: case 19: case 20: p += 2; break;
        case 15: p += 3; break;
        case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18: p += 4; break;
        case 5: case 6: p += 8; i++; break; // long/double take two slots
        default: return null;
      }
    }
    p += 2; // access flags
    const name = utf8.get(classes.get(buf.readUInt16BE(p)));
    p += 4; // this, super
    const ifaces = buf.readUInt16BE(p);
    p += 2 + ifaces * 2;
    const members = new Set();
    for (const kind of ['F', 'M']) {
      const n = buf.readUInt16BE(p);
      p += 2;
      for (let i = 0; i < n; i++) {
        const flags = buf.readUInt16BE(p);
        const mName = utf8.get(buf.readUInt16BE(p + 2));
        const desc = utf8.get(buf.readUInt16BE(p + 4));
        const attrs = buf.readUInt16BE(p + 6);
        p += 8;
        for (let a = 0; a < attrs; a++) p += 6 + buf.readUInt32BE(p + 2);
        if (!(flags & (ACC_PRIVATE | ACC_SYNTHETIC)) && mName !== '<clinit>') members.add(`${kind} ${mName}:${desc}`);
      }
    }
    return { name, major, members };
  } catch {
    return null;
  }
}

module.exports = { readClass };
