// Syntax check of every JavaScript file (no dependencies): `npm run check`.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const roots = ['main.js', 'preload.js', 'launch.js', 'src', 'renderer', 'scripts'];
const files = [];
const walk = (p) => {
  const st = fs.statSync(p);
  if (st.isDirectory()) for (const n of fs.readdirSync(p)) walk(path.join(p, n));
  else if (p.endsWith('.js')) files.push(p);
};
for (const r of roots) if (fs.existsSync(r)) walk(r);
let failed = 0;
for (const f of files) {
  try { execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' }); }
  catch (e) { failed++; console.error(`✗ ${f}\n${e.stderr}`); }
}
for (const j of ['src/data/richids.json', 'src/data/python-stdlib.json', 'package.json']) {
  try { JSON.parse(fs.readFileSync(j, 'utf8')); } catch (e) { failed++; console.error(`✗ ${j}: ${e.message}`); }
}
console.log(failed ? `${failed} file(s) failed` : `✓ ${files.length} JavaScript files OK`);
process.exit(failed ? 1 : 0);
