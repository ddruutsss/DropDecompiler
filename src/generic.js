// Any other file: identifies it, and writes what can be read from it so the AI assistant (or the user)
// can work on it: readable text (decoded / re-indented), printable strings, a hex dump of the start,
// and the contents of archives.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const { decodeText, isTextual, prettyXml } = require('./manifest');

const SIGNATURES = [
  ['504b0304', 'ZIP archive (also .docx/.xlsx/.apk/.jar…)'],
  ['377abcaf271c', '7-Zip archive'],
  ['526172211a07', 'RAR archive'],
  ['1f8b', 'gzip compressed data'],
  ['425a68', 'bzip2 compressed data'],
  ['fd377a585a00', 'xz compressed data'],
  ['28b52ffd', 'Zstandard compressed data'],
  ['89504e470d0a1a0a', 'PNG image'],
  ['ffd8ff', 'JPEG image'],
  ['474946383', 'GIF image'],
  ['25504446', 'PDF document'],
  ['53514c69746520666f726d6174203300', 'SQLite database'],
  ['556e6974794653', 'Unity asset bundle (UnityFS)'],
  ['4c5a4950', 'lzip compressed data'],
  ['d0cf11e0a1b11ae1', 'Microsoft Compound File (old .doc/.xls/.msi)'],
  ['4d5357494d', 'Windows Imaging (WIM)'],
  ['00000100', 'Windows icon'],
  ['52494646', 'RIFF container (WAV/AVI/WebP)'],
  ['4f676753', 'Ogg media'],
  ['494433', 'MP3 audio'],
  ['1a45dfa3', 'Matroska / WebM video'],
  ['0061736d', 'WebAssembly module'],
  ['7b5c727466', 'RTF document'],
  ['4c000000011402', 'Windows shortcut (.lnk)'],
  ['bebafeca', 'Java/Mach-O fat binary'],
  ['4e45531a', 'NES ROM'],
  ['58585445', 'XXTEA-encrypted data (Cocos2d-x)'],
];

function identify(head, ext) {
  const hex = head.subarray(0, 32).toString('hex');
  for (const [sig, name] of SIGNATURES) if (hex.startsWith(sig)) return name;
  // Python bytecode: 2-byte version magic followed by \r\n
  if (head.length >= 4 && head[2] === 0x0d && head[3] === 0x0a) return 'Python bytecode (.pyc)';
  if (hex.startsWith('6465780a')) return 'Android DEX';
  if (isTextual(head)) {
    const t = decodeText(head).trimStart();
    if (/^[{[]/.test(t)) return 'JSON / text data';
    if (/^</.test(t)) return 'XML / HTML text';
    return `Text (${ext || 'no extension'})`;
  }
  return 'Unknown binary data';
}

function entropy(buf) {
  if (!buf.length) return 0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  let e = 0;
  for (const c of counts) if (c) { const p = c / buf.length; e -= p * Math.log2(p); }
  return e;
}

function strings(buf, min = 5, limit = 40000) {
  const out = [];
  let cur = '';
  let start = 0;
  for (let i = 0; i < buf.length && out.length < limit; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) { if (!cur) start = i; cur += String.fromCharCode(c); }
    else { if (cur.length >= min) out.push(`${start.toString(16).padStart(8, '0')}  ${cur}`); cur = ''; }
  }
  cur = '';
  for (let i = 0; i + 1 < buf.length && out.length < limit; i += 2) {
    const c = buf[i];
    if (buf[i + 1] === 0 && c >= 0x20 && c < 0x7f) { if (!cur) start = i; cur += String.fromCharCode(c); }
    else { if (cur.length >= min) out.push(`${start.toString(16).padStart(8, '0')}  ${cur}   (UTF-16)`); cur = ''; }
  }
  return out;
}

function hexDump(buf) {
  const lines = [];
  for (let i = 0; i < buf.length; i += 16) {
    const row = buf.subarray(i, i + 16);
    lines.push(`${i.toString(16).padStart(8, '0')}  ${[...row].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47)}  ${[...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('')}`);
  }
  return lines.join('\n') + '\n';
}

function pretty(text, name) {
  const t = text.trim();
  if (/^[{[]/.test(t)) { try { return JSON.stringify(JSON.parse(t), null, 2) + '\n'; } catch { /* not JSON */ } }
  if (/^<(\?xml|[A-Za-z])/.test(t) && !/\.html?$/i.test(name)) return prettyXml(t);
  return text;
}

const MAX_EXTRACT = 512 * 1024 * 1024;

async function decompileGeneric(_tools, file, outDir, log) {
  const st = await fsp.stat(file);
  // Very big files are only sampled (their first 256 MB): enough to identify them and pull strings.
  const LIMIT = 256 * 1024 * 1024;
  let buf;
  if (st.size <= LIMIT) buf = await fsp.readFile(file);
  else {
    const fh = await fsp.open(file, 'r');
    buf = Buffer.alloc(LIMIT);
    await fh.read(buf, 0, LIMIT, 0);
    await fh.close();
  }
  const ext = path.extname(file).toLowerCase();
  const name = path.basename(file);
  const kind = identify(buf.subarray(0, 4096), ext);
  const ent = entropy(buf.subarray(0, 4 * 1024 * 1024));
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const notes = [];
  log(`Identified as: ${kind}`);

  if (st.size > LIMIT) notes.push('Only the first 256 MB of this file were analysed.');
  if (isTextual(buf) && st.size <= 64 * 1024 * 1024) {
    const text = decodeText(buf);
    await fsp.mkdir(path.join(outDir, 'source'), { recursive: true });
    await fsp.writeFile(path.join(outDir, 'source', name), pretty(text, name));
    notes.push(`Readable copy (decoded to UTF-8${/^\s*[{[<]/.test(text) ? ', re-indented' : ''}): \`source/${name}\`.`);
  } else {
    let zipped = false;
    if (buf.subarray(0, 2).toString('latin1') === 'PK') {
      try {
        const zip = new AdmZip(file);
        const entries = zip.getEntries();
        const listing = entries.map((e) => `${e.entryName}    ${e.header.size.toLocaleString('en')} bytes`);
        await fsp.writeFile(path.join(outDir, 'archive-contents.txt'), listing.join('\n') + '\n');
        const root = path.resolve(outDir, 'files');
        let total = 0;
        for (const e of entries) {
          if (e.isDirectory) continue;
          total += e.header.size;
          if (total > MAX_EXTRACT) { notes.push('Archive too big to unpack completely: only the first 512 MB were extracted.'); break; }
          const dest = path.resolve(root, e.entryName);
          if (!dest.startsWith(root + path.sep)) continue;
          await fsp.mkdir(path.dirname(dest), { recursive: true });
          await fsp.writeFile(dest, e.getData());
        }
        notes.push(`Archive with ${entries.length.toLocaleString('en')} entries: unpacked into \`files/\`. Drop a file from it into DropDecompiler to decompile it.`);
        zipped = true;
      } catch { /* damaged zip */ }
    }
    const strs = strings(buf);
    await fsp.writeFile(path.join(outDir, 'strings.txt'), strs.join('\n') + '\n');
    await fsp.writeFile(path.join(outDir, 'hexdump.txt'), hexDump(buf.subarray(0, 8192)));
    notes.push(`\`strings.txt\`: ${strs.length.toLocaleString('en')} printable strings (offset in hex). \`hexdump.txt\`: the first 8 KB.`);
    if (!zipped && ent > 7.5) notes.push('The data looks random (high entropy): it is compressed or encrypted, so its strings say little.');
  }

  const md = [
    `# ${name}`, '',
    `- **Type:** ${kind}`,
    `- **Size:** ${st.size.toLocaleString('en')} bytes`,
    `- **SHA-256:** \`${sha256}\``,
    `- **Entropy:** ${ent.toFixed(2)} bits/byte (8 = random)`, '',
    'DropDecompiler has no dedicated decompiler for this kind of file, so it saved what can be read from it.', '',
    ...notes.map((n) => `- ${n}`), '',
    'Open the **AI assistant** and ask it to analyse the file: it can read these files and the original bytes, explain the format and reconstruct readable source where there is code.', '',
  ];
  await fsp.writeFile(path.join(outDir, 'README.md'), md.join('\n'));
}

module.exports = { decompileGeneric, identify };
