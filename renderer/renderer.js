const $ = (s) => document.querySelector(s);

const jobs = new Map();
let nextId = 1;
let activeJob = null; // job shown in the viewer
let fileList = []; // relative paths of the active job's output
let currentFile = null;

const ENGINE_NAMES = { java: 'Java', android: 'Android', dotnet: '.NET', 'dotnet-archive': '.NET',
  'dotnet-bundle': '.NET single-file app', native: 'Native code (Ghidra pseudo-C)', folder: 'Folder',
  lua: 'Lua', manifest: 'Manifest', generic: 'File analysis', website: 'Website', ios: 'iOS app' };
const TAG_NAMES = { java: 'Java', android: 'Android', dotnet: '.NET', 'dotnet-archive': '.NET', 'dotnet-bundle': '.NET', native: 'Native', lua: 'Lua', manifest: 'Manifest', generic: 'File', website: 'Web', ios: 'iOS' };
const LANGS = {
  java: 'java', kt: 'kotlin', cs: 'csharp', c: 'c', h: 'c', cpp: 'cpp', hpp: 'cpp', vb: 'vbnet', xml: 'xml', csproj: 'xml', axml: 'xml',
  resx: 'xml', config: 'xml', xaml: 'xml', html: 'xml', htm: 'xml', svg: 'xml', json: 'json', manifest: 'xml',
  properties: 'properties', ini: 'ini', yml: 'yaml', yaml: 'yaml', js: 'javascript', ts: 'typescript',
  css: 'css', sql: 'sql', md: 'markdown', gradle: 'groovy', kts: 'kotlin', sh: 'bash', py: 'python', bat: 'dos', cmd: 'dos',
  rc: 'cpp', m: 'objectivec', mm: 'objectivec', swift: 'swift', plist: 'xml', entitlements: 'xml', strings: 'plaintext', lua: 'lua', jsx: 'javascript', tsx: 'typescript', mjs: 'javascript', cjs: 'javascript', scss: 'scss', less: 'less', vue: 'xml', svelte: 'xml', webmanifest: 'json', map: 'json', luadis: 'plaintext', csv: 'plaintext', sln: 'plaintext', smali: 'plaintext', mf: 'properties', txt: 'plaintext', pro: 'plaintext',
};
// File icon tint per type: muted, so the tree stays calm.
const FILE_TINT = { java: '#d19a66', kt: '#b39ddb', cs: '#a594e0', c: '#6cb0d6', h: '#6cb0d6', cpp: '#6cb0d6', rc: '#6cb0d6',
  xml: '#8fb3cf', xaml: '#8fb3cf', resx: '#8fb3cf', csproj: '#a594e0', sln: '#a594e0', json: '#c9b16d', md: '#a1a7b1',
  png: '#8ebf73', jpg: '#8ebf73', ico: '#8ebf73', bmp: '#8ebf73', gif: '#8ebf73', webp: '#8ebf73', jar: '#d19a66',
  exe: '#e0a26b', dll: '#e0a26b', bat: '#a1a7b1', smali: '#8ebf73', lua: '#7c9fe0', manifest: '#c9b16d', swift: '#e07b53', m: '#6cb0d6', plist: '#8fb3cf', ipa: '#9aa6b8' };

// ------------------------------------------------------------ utils

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function extOf(p) {
  const m = /\.([^./]+)$/.exec(p);
  return m ? m[1].toLowerCase() : '';
}
function basename(p) {
  return p.split(/[\\/]/).pop();
}
const isLink = (s) => /^https?:\/\/\S+$/i.test(String(s).trim());
function linkName(url) {
  try { const u = new URL(url); return u.host + (u.pathname === '/' ? '' : u.pathname); } catch { return url; }
}
/** A web address from typed or pasted text ("example.com" → "https://example.com"), or null. */
function toLink(text) {
  const t = String(text || '').trim().split(/\s+/)[0];
  if (!t) return null;
  if (isLink(t)) return t;
  if (/^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/\S*)?$/i.test(t) && !/^[a-z]:/i.test(t)) return 'https://' + t;
  return null;
}
let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 2800);
}
function fmtSize(n) {
  return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n > 1024 ? (n / 1024).toFixed(0) + ' KB' : n + ' B';
}
function cleanError(e) {
  return String(e?.message || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');
}

function updateStatusBar() {
  const all = [...jobs.values()];
  const running = all.filter((j) => j.status === 'running').length;
  const queued = all.filter((j) => j.status === 'queued').length;
  $('#sbStatus').textContent = running
    ? `Decompiling${queued ? ` · ${queued} waiting` : ''}…`
    : all.length ? `${all.filter((j) => j.status === 'done').length} of ${all.length} done` : 'Ready';
}

// ------------------------------------------------------------ jobs

function addFiles(paths) {
  if (!paths?.length) return;
  $('#jobs .jobs-empty')?.remove();
  for (const file of paths) {
    const id = String(nextId++);
    const job = { id, file, name: isLink(file) ? linkName(file) : basename(file), status: 'queued', logs: [], result: null };
    job.el = renderJob(job);
    $('#jobs').prepend(job.el);
    jobs.set(id, job);
    api.enqueue(id, file);
  }
  updateStatusBar();
}

function renderJob(job) {
  const el = document.createElement('div');
  el.className = 'job queued';
  const ext = isLink(job.file) ? 'WEB' : extOf(job.name).toUpperCase() || 'FILE';
  el.innerHTML = `
    <div class="job-line"><span class="tag">${esc(ext)}</span><span class="job-name" title="${esc(job.file)}">${esc(job.name)}</span><span class="job-state">${icon('dot')}</span></div>
    <div class="job-status">Waiting…</div>
    <div class="progress indeterminate"><div></div></div>
    <div class="job-actions">
      <button class="tool subtle" data-act="cancel">${icon('stop')}Cancel</button>
      <button class="tool subtle hidden" data-act="folder">${icon('folder')}Folder</button>
      <button class="tool subtle hidden" data-act="zip">${icon('download')}ZIP</button>
      <button class="tool subtle" data-act="log">${icon('log')}Log</button>
    </div>
    <pre class="job-log hidden"></pre>`;
  el.addEventListener('click', (e) => {
    if (e.target.closest('.job-log')) return;
    const act = e.target.closest('button')?.dataset.act;
    if (act === 'folder') api.openPath(job.result.outDir);
    else if (act === 'zip') exportZip(job);
    else if (act === 'log') el.querySelector('.job-log').classList.toggle('hidden');
    else if (act === 'cancel') api.cancelJob(job.id);
    else if (job.result) openJob(job);
  });
  return el;
}

function setJobState(job) {
  const el = job.el;
  el.className = `job ${job.status}${activeJob === job ? ' active' : ''}`;
  const names = { done: 'check', error: 'x', cancelled: 'x' };
  el.querySelector('.job-state').innerHTML = icon(names[job.status] || 'dot');
  const done = job.status === 'done';
  el.querySelector('[data-act=cancel]').classList.toggle('hidden', !(job.status === 'running' || job.status === 'queued'));
  el.querySelector('[data-act=folder]').classList.toggle('hidden', !done);
  el.querySelector('[data-act=zip]').classList.toggle('hidden', !done);
}

function onJobEvent(ev) {
  const job = jobs.get(ev.id);
  if (!job) return;
  const el = job.el;
  const statusEl = el.querySelector('.job-status');
  const bar = el.querySelector('.progress');

  if (ev.status) {
    job.status = ev.status;
    setJobState(job);
    if (ev.status === 'running') statusEl.textContent = 'Starting…';
    if (ev.status === 'cancelled') statusEl.textContent = 'Cancelled';
  }
  if (ev.detected) {
    const tag = el.querySelector('.tag');
    tag.textContent = TAG_NAMES[ev.detected.engine] || ev.detected.label;
    tag.className = `tag ${ev.detected.engine}`;
  }
  if (ev.log) {
    job.logs.push(ev.log);
    if (job.logs.length > 600) job.logs.splice(0, job.logs.length - 500);
    const logEl = el.querySelector('.job-log');
    logEl.textContent = job.logs.join('\n');
    logEl.scrollTop = logEl.scrollHeight;
    if (!ev.quiet && job.status === 'running') statusEl.textContent = ev.log;
  }
  if (typeof ev.progress === 'number' && ev.progress >= 0) {
    bar.classList.remove('indeterminate');
    bar.firstElementChild.style.width = ev.progress + '%';
  } else if (ev.log && job.status === 'running') {
    bar.classList.add('indeterminate');
    bar.firstElementChild.style.width = '';
  }

  if (ev.status === 'done') {
    job.result = ev.result;
    statusEl.textContent = `${ev.result.files.toLocaleString()} files · ${ENGINE_NAMES[ev.result.engine] || ev.result.engineName}`;
    showJobBuild(job);
    if (!activeJob) openJob(job);
    toast(`${job.name} decompiled`);
    if (aiConfig?.autoReconstruct && aiConfig.hasKey) {
      if (activeJob === job) showAiPane(true);
      aiSend(job.result.outDir, 'reconstruct', '');
    }
  }
  if (ev.status === 'error') {
    statusEl.textContent = ev.error;
    job.logs.push('ERROR: ' + ev.error);
    el.querySelector('.job-log').textContent = job.logs.join('\n');
  }
  if (ev.status) updateStatusBar();
}

async function exportZip(job) {
  const p = await api.exportZip(job.result.outDir);
  if (p) toast('Saved ' + basename(p));
}

// ------------------------------------------------------------ rebuild status

/** { text, cls, icon } describing whether the output builds again. */
function buildInfo(b) {
  if (!b) return null;
  if (b.kind === 'dotnet') {
    if (!b.checked) return { text: 'Build not checked', cls: '', icon: 'dot' };
    if (b.ok) return { text: 'Builds', cls: 'ok', icon: 'check' };
    return { text: `${b.errors} build error${b.errors === 1 ? '' : 's'}`, cls: 'fail', icon: 'x' };
  }
  if (b.kind === 'java') {
    if (!b.complete) return { text: 'Rebuilt JAR incomplete', cls: 'fail', icon: 'x' };
    return { text: `Rebuilt · ${b.fromSource.toLocaleString()}/${b.total.toLocaleString()} classes from source`, cls: b.fromSource ? 'ok' : 'fail', icon: 'check' };
  }
  if (b.kind === 'android') return { text: 'Android Studio project', cls: '', icon: 'box' };
  if (b.kind === 'native') {
    if (b.errors !== undefined) return b.ok ? { text: 'Resources compile', cls: 'ok', icon: 'check' } : { text: 'Resource errors', cls: 'fail', icon: 'x' };
    if (!b.checked) return { text: `GUI resources: ${b.resources}`, cls: '', icon: 'dot' };
    return b.ok ? { text: `GUI rebuilds · ${b.resources} resources`, cls: 'ok', icon: 'check' } : { text: 'GUI partly rebuilds', cls: 'fail', icon: 'x' };
  }
  return null;
}

function showJobBuild(job) {
  const info = buildInfo(job.result?.build);
  let el = job.el.querySelector('.job-build');
  if (!info) return el?.remove();
  if (!el) {
    el = document.createElement('div');
    job.el.querySelector('.job-status').after(el);
  }
  el.className = `job-build ${info.cls}`;
  el.textContent = info.text;
}

function showViewerBuild(job) {
  const b = job.result.build;
  const info = buildInfo(b);
  const chip = $('#vBuild');
  chip.classList.toggle('hidden', !info);
  if (info) {
    chip.className = `status-chip ${info.cls}`;
    chip.innerHTML = icon(info.icon) + esc(info.text);
  }
  $('#vRebuild').classList.toggle('hidden', !b || b.kind === 'android');
  $('#vProgram').classList.toggle('hidden', !b?.outputs?.length);
}

function reportFile() {
  return fileList.includes('BUILD.md') ? 'BUILD.md' : fileList.includes('README.md') ? 'README.md' : null;
}

function openReport() {
  const rep = reportFile();
  if (rep) openFile(rep, document.querySelector(`#tree .node[data-path="${CSS.escape(rep)}"]`));
}

async function rebuild() {
  const job = activeJob;
  if (!job?.result?.build) return;
  const btn = $('#vRebuild');
  btn.disabled = true;
  const chip = $('#vBuild');
  chip.className = 'status-chip busy';
  chip.innerHTML = icon('refresh') + 'Building…';
  chip.classList.remove('hidden');
  $('#sbStatus').textContent = `Rebuilding ${job.name}…`;
  try {
    const { build, files } = await api.rebuild(job.result.outDir);
    job.result.build = build;
    job.result.files = files;
    toast(build.ok ? 'Build succeeded' : `Build finished with ${build.errors} problem(s)`);
  } catch (e) {
    toast(cleanError(e));
  } finally {
    btn.disabled = false;
    showJobBuild(job);
    updateStatusBar();
    if (activeJob === job) {
      showViewerBuild(job);
      fileList = await api.listFiles(job.result.outDir);
      renderTree();
      if (!currentFile || currentFile === 'BUILD.md') openReport();
    }
  }
}

api.onRebuildLog(({ outDir, log }) => {
  for (const job of jobs.values()) {
    if (job.result?.outDir !== outDir) continue;
    job.logs.push(log);
    job.el.querySelector('.job-log').textContent = job.logs.join('\n');
    $('#sbStatus').textContent = log;
  }
});

// ------------------------------------------------------------ viewer

async function openJob(job) {
  activeJob = job;
  jobs.forEach((j) => j.el.classList.toggle('active', j === job));
  $('#viewerEmpty').classList.add('hidden');
  $('#viewerMain').classList.remove('hidden');
  $('#vName').textContent = job.name;
  $('#tbContext').textContent = job.name;
  $('#vBadge').textContent = TAG_NAMES[job.result.engine] || job.result.label;
  $('#vBadge').className = `tag ${job.result.engine}`;
  $('#vCount').textContent = `${ENGINE_NAMES[job.result.engine] || ''} · ${job.result.files.toLocaleString()} files`;
  showViewerBuild(job);
  $('#filter').value = '';
  showMessage('Select a file in the tree.');
  $('#crumb').textContent = 'No file selected';
  currentFile = null;
  setCodeButtons(false);
  $('#tree').innerHTML = '<div class="tree-note">Loading…</div>';
  renderAi();
  fileList = await api.listFiles(job.result.outDir);
  if (activeJob !== job) return;
  renderTree();
  // Show the overview first: the build report, or Ghidra's README for native code.
  if (appSettings.autoReadme !== false) openReport();
}

function buildTree(paths) {
  const root = { dirs: new Map(), files: [] };
  for (const p of paths) {
    const parts = p.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node.dirs.has(parts[i])) node.dirs.set(parts[i], { dirs: new Map(), files: [] });
      node = node.dirs.get(parts[i]);
    }
    node.files.push(p);
  }
  return root;
}

function renderTree() {
  const tree = $('#tree');
  tree.innerHTML = '';
  const root = buildTree(fileList);
  renderDir(root, tree, '');
  // Expand the top level when there are only a few folders (e.g. "src", or a project folder).
  if (root.dirs.size <= 3) tree.querySelectorAll(':scope > .dir > .node').forEach((n) => n.click());
}

function renderDir(node, container, prefix) {
  const dirNames = [...node.dirs.keys()].sort((a, b) => a.localeCompare(b));
  for (const name of dirNames) {
    // Collapse single-child chains like com/example/app into one row.
    let label = name;
    let dir = node.dirs.get(name);
    let full = prefix + name;
    while (dir.files.length === 0 && dir.dirs.size === 1) {
      const [childName, child] = dir.dirs.entries().next().value;
      label += '/' + childName;
      full += '/' + childName;
      dir = child;
    }
    const wrap = document.createElement('div');
    wrap.className = 'dir';
    const row = document.createElement('div');
    row.className = 'node';
    row.innerHTML = `<span class="twisty">${icon('chevron')}</span>${icon('folder', 'fi dir')}<span class="label">${esc(label)}</span>`;
    const kids = document.createElement('div');
    kids.className = 'children hidden';
    let rendered = false;
    row.addEventListener('click', () => {
      if (!rendered) { renderDir(dir, kids, full + '/'); rendered = true; }
      const open = kids.classList.toggle('hidden') === false;
      row.classList.toggle('open', open);
      row.querySelector('.fi').outerHTML = icon(open ? 'folderOpen' : 'folder', 'fi dir');
    });
    wrap.append(row, kids);
    container.append(wrap);
  }
  const files = [...node.files].sort((a, b) => basename(a).localeCompare(basename(b)));
  for (const p of files) container.append(fileRow(p, basename(p)));
}

function fileRow(path, label, sub) {
  const row = document.createElement('div');
  row.className = 'node file';
  row.dataset.path = path;
  const tint = FILE_TINT[extOf(path)];
  row.innerHTML = `<span class="twisty"></span>${icon('file', 'fi')}<span class="label">${esc(label)}</span>${
    sub ? `<span class="sub">${esc(sub)}</span>` : ''}`;
  if (tint) row.querySelector('.fi').style.color = tint;
  row.addEventListener('click', () => openFile(path, row));
  if (path === currentFile) row.classList.add('selected');
  return row;
}

function applyFilter() {
  const q = $('#filter').value.trim().toLowerCase();
  if (!q) return renderTree();
  const tree = $('#tree');
  tree.innerHTML = '';
  const hits = [];
  for (const p of fileList) {
    if (p.toLowerCase().includes(q)) {
      hits.push(p);
      if (hits.length >= 500) break;
    }
  }
  // Rank file-name matches above folder matches.
  hits.sort((a, b) => (basename(b).toLowerCase().includes(q) ? 1 : 0) - (basename(a).toLowerCase().includes(q) ? 1 : 0));
  if (!hits.length) tree.innerHTML = '<div class="tree-note">No matching files</div>';
  for (const p of hits) {
    const dir = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '';
    tree.append(fileRow(p, basename(p), dir));
  }
  if (hits.length >= 500) tree.insertAdjacentHTML('beforeend', '<div class="tree-note">Showing the first 500 matches</div>');
}

function showMessage(msg) {
  $('#gutter').textContent = '';
  $('#code').querySelector('code').innerHTML = `<div class="code-msg">${esc(msg)}</div>`;
}

function setCodeButtons(on) {
  $('#copyBtn').disabled = !on;
  $('#revealBtn').disabled = !on;
}

async function openFile(path, row) {
  document.querySelectorAll('#tree .node.selected').forEach((n) => n.classList.remove('selected'));
  row?.classList.add('selected');
  currentFile = path;
  $('#crumb').textContent = path;
  const job = activeJob;
  let res;
  try { res = await api.readFile(job.result.outDir, path); } catch (e) { return showMessage(cleanError(e)); }
  if (currentFile !== path || activeJob !== job) return;
  $('#revealBtn').disabled = false;
  if (res.binary) {
    $('#copyBtn').disabled = true;
    return showMessage(`Binary file (${fmtSize(res.size)}). Use “Show in folder” to open it.`);
  }
  $('#copyBtn').disabled = false;
  const text = res.text;
  const lines = text.split('\n').length;
  $('#gutter').textContent = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
  const codeEl = $('#code').querySelector('code');
  // Headers from class-dump are Objective-C, not C.
  const lang = extOf(path) === 'h' && /^@(interface|protocol) /m.test(text) ? 'objectivec' : LANGS[extOf(path)];
  if (text.length < 400000 && lang && hljs.getLanguage(lang)) {
    codeEl.innerHTML = hljs.highlight(text, { language: lang, ignoreIllegals: true }).value;
  } else {
    codeEl.textContent = text;
  }
  if (res.truncated) codeEl.insertAdjacentHTML('beforeend', '\n\n<span class="code-msg">File truncated: too large to display. Open it from the folder.</span>');
  $('#codeScroll').scrollTo(0, 0);
}

// ------------------------------------------------------------ drag & drop

let dragDepth = 0;
const hasFiles = (e) => [...(e.dataTransfer?.types || [])].some((t) => t === 'Files' || t === 'text/uri-list');

window.addEventListener('dragenter', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  if (dragDepth++ === 0) {
    document.body.classList.add('dragging');
    $('#dropOverlay').classList.remove('hidden');
  }
});
window.addEventListener('dragover', (e) => {
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
});
window.addEventListener('dragleave', (e) => {
  if (!hasFiles(e)) return;
  if (--dragDepth <= 0) endDrag();
});
window.addEventListener('drop', (e) => {
  e.preventDefault();
  endDrag();
  const paths = [...(e.dataTransfer?.files || [])].map((f) => api.pathForFile(f)).filter(Boolean);
  if (!paths.length) {
    // A link dragged from a browser's address bar or a page.
    const links = (e.dataTransfer?.getData('text/uri-list') || e.dataTransfer?.getData('text/plain') || '')
      .split(/\r?\n/).filter((l) => l && !l.startsWith('#')).map(toLink).filter(Boolean);
    return addFiles([...new Set(links)]);
  }
  addFiles(paths);
});

// Paste a website link anywhere (outside text boxes) to download it.
window.addEventListener('paste', (e) => {
  if (e.target.closest?.('input, textarea')) return;
  const link = toLink(e.clipboardData?.getData('text/plain'));
  if (link) { e.preventDefault(); addFiles([link]); }
});

$('#urlForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const link = toLink($('#urlInput').value);
  if (!link) return toast('Enter a website address, for example https://example.com');
  $('#urlInput').value = '';
  addFiles([link]);
});
$('#urlPages').addEventListener('change', () => api.setSettings({ webMaxPages: Number($('#urlPages').value) }));
function endDrag() {
  dragDepth = 0;
  document.body.classList.remove('dragging');
  $('#dropOverlay').classList.add('hidden');
}

// ------------------------------------------------------------ wiring

async function browse() {
  addFiles(await api.pickFiles());
}

$('#dropzone').addEventListener('click', browse);
$('#dropzone').addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && browse());
$('#openBtn').addEventListener('click', browse);
$('#emptyBrowse').addEventListener('click', browse);
window.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key.toLowerCase() === 'o') { e.preventDefault(); browse(); }
  if (e.ctrlKey && e.key.toLowerCase() === 'p' && activeJob) { e.preventDefault(); $('#filter').focus(); $('#filter').select(); }
  if (e.key === 'Escape' && document.activeElement === $('#filter')) { $('#filter').value = ''; applyFilter(); }
  if (e.ctrlKey && e.key.toLowerCase() === 'i' && activeJob) { e.preventDefault(); showAiPane($('#aiPane').classList.contains('hidden')); }
});

function showOutputRoot(p) {
  $('#outputPath').textContent = p;
  $('#outputPath').title = `Open ${p}`;
}
$('#outputPath').addEventListener('click', () => api.openOutputRoot());
$('#changeOutput').addEventListener('click', async () => showOutputRoot(await api.chooseOutput()));
$('#clearDone').addEventListener('click', () => {
  for (const [id, job] of jobs) {
    if (['done', 'error', 'cancelled'].includes(job.status) && job !== activeJob) {
      job.el.remove();
      jobs.delete(id);
    }
  }
  if (!jobs.size) $('#jobs').innerHTML = '<div class="jobs-empty">No files yet</div>';
  updateStatusBar();
});

let filterTimer;
$('#filter').addEventListener('input', () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyFilter, 120);
});
$('#vOpen').addEventListener('click', () => activeJob && api.openPath(activeJob.result.outDir));
$('#vZip').addEventListener('click', () => activeJob && exportZip(activeJob));
$('#vRebuild').addEventListener('click', rebuild);
$('#vBuild').addEventListener('click', openReport);
$('#vProgram').addEventListener('click', () => {
  const out = activeJob?.result?.build?.outputs?.[0];
  if (out) api.showFile(activeJob.result.outDir, out);
});
$('#copyBtn').addEventListener('click', async () => {
  await api.copyText($('#code').innerText);
  toast('Copied to clipboard');
});
$('#revealBtn').addEventListener('click', () => currentFile && api.showFile(activeJob.result.outDir, currentFile));

api.onJobEvent(onJobEvent);
api.onAddFiles(addFiles);
// ------------------------------------------------------------ settings page

let appSettings = {};
let savedTimer;

function setTheme(t) {
  document.documentElement.dataset.theme = t === 'light' ? 'light' : 'dark';
  $('#hljsDark').disabled = t === 'light';
  $('#hljsLight').disabled = t !== 'light';
}

function applyViewSettings() {
  document.documentElement.style.setProperty('--code-size', `${appSettings.fontSize || 13}px`);
  document.body.classList.toggle('wrap-lines', !!appSettings.wrapLines);
}

function syncPagesSelect(n) {
  const opts = [...$('#urlPages').options].map((o) => Number(o.value));
  $('#urlPages').value = String(opts.reduce((a, b) => (Math.abs(b - n) < Math.abs(a - n) ? b : a)));
}

async function loadSettings() {
  appSettings = await api.getSettings();
  setTheme(appSettings.effectiveTheme);
  applyViewSettings();
  showOutputRoot(appSettings.outputRoot);
  syncPagesSelect(appSettings.webMaxPages);
}

function flashSaved(text = 'Saved') {
  const el = $('#setSaved');
  el.textContent = '✓ ' + text;
  el.classList.add('show');
  clearTimeout(savedTimer);
  savedTimer = setTimeout(() => el.classList.remove('show'), 1600);
}

/** Puts the current values into the settings controls. */
function fillSettings() {
  for (const el of document.querySelectorAll('[data-set]')) {
    const v = appSettings[el.dataset.set];
    if (el.type === 'checkbox') el.checked = !!v;
    else el.value = v ?? '';
  }
  for (const group of document.querySelectorAll('[data-set-radio]')) {
    const v = appSettings[group.dataset.setRadio];
    for (const b of group.querySelectorAll('button')) b.setAttribute('aria-checked', String(b.dataset.value === v));
  }
  $('#setFontVal').textContent = `${appSettings.fontSize} px`;
  $('#setOutPath').textContent = appSettings.outputRoot || '';
  const v = appSettings.versions || {};
  $('#setVersion').textContent = `Version ${appSettings.version} · Electron ${v.electron} · Chromium ${v.chrome} · Node ${v.node}`;
}

async function saveSetting(key, value) {
  const saved = await api.setSettings({ [key]: value });
  appSettings = { ...appSettings, ...saved, aiKeyEnc: undefined };
  fillSettings(); // shows clamped values (e.g. a number out of range)
  applyViewSettings();
  if (key === 'webMaxPages') syncPagesSelect(appSettings.webMaxPages);
  flashSaved();
}

for (const el of document.querySelectorAll('[data-set]')) {
  const numeric = el.type === 'number' || el.type === 'range';
  if (el.type === 'range') {
    el.addEventListener('input', () => {
      $('#setFontVal').textContent = `${el.value} px`;
      document.documentElement.style.setProperty('--code-size', `${el.value}px`);
    });
  }
  el.addEventListener('change', () => saveSetting(el.dataset.set, el.type === 'checkbox' ? el.checked : numeric ? Number(el.value) : el.value));
}
for (const group of document.querySelectorAll('[data-set-radio]')) {
  group.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-value]');
    if (b) saveSetting(group.dataset.setRadio, b.dataset.value);
  });
}

async function renderTools() {
  let list = [];
  try { list = await api.toolStatus(); } catch { /* not ready */ }
  const total = list.reduce((s, t) => s + (t.installed ? t.size : 0), 0);
  $('#setTools').innerHTML = list.map((t) => `
    <div class="set-row tool-row">
      <div class="set-text">
        <div class="set-label">${esc(t.name)}<span class="tool-state ${t.installed ? 'on' : ''}">${t.installed ? 'Installed' : 'Not downloaded'}</span></div>
        <div class="set-desc">${esc(t.used)}${t.installed ? ` · ${fmtSize(t.size)}` : ''}</div>
      </div>
      <div class="set-ctl">${t.installed ? `<button class="tool" data-remove="${esc(t.key)}">Remove</button>` : ''}</div>
    </div>`).join('');
  $('#setToolsTotal').textContent = total ? `${fmtSize(total)} in total` : '';
}

$('#setTools').addEventListener('click', async (e) => {
  const key = e.target.closest('[data-remove]')?.dataset.remove;
  if (!key) return;
  try {
    await api.removeTool(key);
    flashSaved('Removed');
  } catch (err) { toast(cleanError(err)); }
  renderTools();
});
$('#setToolsOpen').addEventListener('click', () => api.openToolsDir());
$('#setOutOpen').addEventListener('click', () => api.openOutputRoot());
$('#setOutChange').addEventListener('click', async () => {
  appSettings.outputRoot = await api.chooseOutput();
  showOutputRoot(appSettings.outputRoot);
  fillSettings();
});

function showSection(sec, scroll = true) {
  for (const t of document.querySelectorAll('.set-tab')) t.classList.toggle('active', t.dataset.sec === sec);
  if (scroll) document.querySelector(`.set-sec[data-sec="${sec}"]`)?.scrollIntoView({ block: 'start' });
}

async function openSettings(sec = 'general') {
  $('#settingsView').classList.remove('hidden');
  appSettings = { ...appSettings, ...(await api.getSettings()) };
  fillSettings();
  showSection(sec);
  loadAiConfig();
  renderTools();
}

function closeSettings() {
  $('#settingsView').classList.add('hidden');
}

$('#settingsBtn').addEventListener('click', () => openSettings());
$('#setClose').addEventListener('click', closeSettings);
document.querySelector('.set-nav').addEventListener('click', (e) => {
  const tab = e.target.closest('.set-tab');
  if (tab) showSection(tab.dataset.sec);
});
// Highlight the section being read while scrolling.
$('#setBody').addEventListener('scroll', () => {
  const top = $('#setBody').getBoundingClientRect().top + 90;
  let current = 'general';
  for (const s of document.querySelectorAll('.set-sec')) if (s.getBoundingClientRect().top <= top) current = s.dataset.sec;
  showSection(current, false);
});
window.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === ',') { e.preventDefault(); openSettings(); }
  else if (e.key === 'Escape' && !$('#settingsView').classList.contains('hidden')) { e.preventDefault(); closeSettings(); }
});

api.onTheme(setTheme);
loadSettings();

// ------------------------------------------------------------ AI assistant

let aiConfig = null;
const aiChats = new Map(); // output folder -> { items, busy, status, totalCost }

function chatFor(outDir) {
  if (!aiChats.has(outDir)) aiChats.set(outDir, { items: [], busy: false, status: '', totalCost: 0 });
  return aiChats.get(outDir);
}

async function loadAiConfig() {
  aiConfig = await api.aiConfig();
  const sel = $('#aiModel');
  sel.innerHTML = aiConfig.models.map((m) => `<option value="${esc(m.id)}">${esc(m.name)} (${esc(m.price)})</option>`).join('');
  sel.value = aiConfig.model;
  $('#aiAuto').checked = aiConfig.autoReconstruct;
  const pages = [...$('#urlPages').options].map((o) => Number(o.value));
  $('#urlPages').value = String(pages.reduce((a, b) => (Math.abs(b - aiConfig.webMaxPages) < Math.abs(a - aiConfig.webMaxPages) ? b : a)));
  $('#aiKeyState').textContent = aiConfig.keyFromEnv ? 'Using ANTHROPIC_API_KEY from the environment.' : aiConfig.savedKey ? 'A key is saved (it is used instead of the sign-in).' : '';
  $('#aiKeyRemove').classList.toggle('hidden', !aiConfig.savedKey);
  const ls = $('#aiLoginState');
  ls.textContent = aiConfig.profile ? `Signed in (profile “${aiConfig.profile}”).` : aiConfig.hasKey ? 'Not signed in (an API key is in use).' : 'Not signed in.';
  ls.className = `set-desc ${aiConfig.profile ? 'ok' : aiConfig.hasKey ? '' : 'bad'}`;
  $('#aiLogin').classList.toggle('hidden', !!aiConfig.profile);
  $('#aiLogout').classList.toggle('hidden', !aiConfig.profile);
  $('#aiSignedOut').classList.toggle('hidden', aiConfig.hasKey);
}

function showAiPane(on) {
  $('#aiPane').classList.toggle('hidden', !on);
  if (!on) return;
  renderAi();
  $('#aiInput').focus();
}

// --- minimal Markdown: code fences, headings, lists, tables, `code`, **bold**, _italic_

function mdInline(s) {
  return esc(s)
    .replace(/`([^`\n]+)`/g, (_m, c) => {
      const rel = c.replace(/^\.?\//, '');
      return fileList.includes(rel) ? `<code class="ai-file" data-path="${esc(rel)}">${c}</code>` : `<code>${c}</code>`;
    })
    .replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>')
    .replace(/(^|[\s(])_([^_\n]+)_(?=[\s).,!?:]|$)/g, '$1<i>$2</i>');
}

function md(src) {
  const out = [];
  const lines = src.split('\n');
  let list = null;
  let para = [];
  const flushPara = () => { if (para.length) out.push(`<p>${para.map(mdInline).join('<br>')}</p>`); para = []; };
  const flushList = () => { if (list) out.push(`</${list}>`); list = null; };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = /^\s*```(\w*)/.exec(line);
    if (fence) {
      flushPara(); flushList();
      const code = [];
      for (i++; i < lines.length && !/^\s*```/.test(lines[i]); i++) code.push(lines[i]);
      const text = code.join('\n');
      const lang = fence[1] && hljs.getLanguage(fence[1]) ? fence[1] : null;
      out.push(`<pre><code class="hljs">${lang && text.length < 60000 ? hljs.highlight(text, { language: lang, ignoreIllegals: true }).value : esc(text)}</code></pre>`);
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) { flushPara(); flushList(); out.push(`<h${h[1].length + 1}>${mdInline(h[2])}</h${h[1].length + 1}>`); continue; }
    if (/^\s*\|.*\|\s*$/.test(line)) {
      flushPara(); flushList();
      const rows = [];
      for (; i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i]); i++) rows.push(lines[i]);
      i--;
      const cells = (r) => r.trim().slice(1, -1).split('|').map((c) => c.trim());
      const body = rows.filter((r) => !/^\s*\|[\s:|-]+\|\s*$/.test(r));
      out.push('<table>' + body.map((r, k) => `<tr>${cells(r).map((c) => (k === 0 ? `<th>${mdInline(c)}</th>` : `<td>${mdInline(c)}</td>`)).join('')}</tr>`).join('') + '</table>');
      continue;
    }
    const li = /^\s*(?:([-*])|(\d+)\.)\s+(.*)$/.exec(line);
    if (li) {
      flushPara();
      const kind = li[1] ? 'ul' : 'ol';
      if (list !== kind) { flushList(); out.push(`<${kind}>`); list = kind; }
      out.push(`<li>${mdInline(li[3])}</li>`);
      continue;
    }
    if (!line.trim()) { flushPara(); flushList(); continue; }
    flushList();
    para.push(line);
  }
  flushPara(); flushList();
  return out.join('');
}

function renderParts(parts) {
  const html = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.type === 'text') { html.push(md(p.text)); continue; }
    // Runs of steps are shortened to the last few.
    const run = [];
    while (i < parts.length && parts[i].type !== 'text') run.push(parts[i++]);
    i--;
    const shown = run.length > 5 ? run.slice(-4) : run;
    if (run.length > shown.length) html.push(`<div class="ai-step">${icon('dot')}${run.length - shown.length} earlier steps</div>`);
    for (const s of shown) {
      html.push(s.type === 'file'
        ? `<div class="ai-step">${icon('file')}<span class="ai-file" data-path="${esc(s.rel)}">${esc(s.rel)}</span></div>`
        : `<div class="ai-step">${icon('chevron')}${esc(s.label)}</div>`);
    }
  }
  return html.join('');
}

let aiFrame = 0;
function renderAi() {
  if (aiFrame) return;
  aiFrame = requestAnimationFrame(() => {
    aiFrame = 0;
    if (!activeJob || $('#aiPane').classList.contains('hidden')) return;
    const chat = chatFor(activeJob.result.outDir);
    const box = $('#aiMessages');
    const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
    box.innerHTML = chat.items.length ? chat.items.map((it) => {
      if (it.role === 'user') return `<div class="ai-msg user">${esc(it.text)}</div>`;
      if (it.role === 'error') return `<div class="ai-msg error">${esc(it.text)}</div>`;
      return `<div class="ai-msg assistant">${renderParts(it.parts)}</div>`;
    }).join('') : `<div class="ai-empty"><b>Reconstruct program</b> reads the decompiled output and writes clean, commented source code into the <code>ai/</code> folder.<br><br>Or ask anything: what the program does, how a function works, where a string is used…</div>`;
    if (stick) box.scrollTop = box.scrollHeight;
    $('#aiStatus').textContent = chat.busy ? chat.status || 'Working…' : '';
    $('#aiStop').classList.toggle('hidden', !chat.busy);
    $('#aiSendBtn').disabled = chat.busy;
    for (const b of ['#aiReconstruct', '#aiExplain', '#aiRewrite']) $(b).disabled = chat.busy;
    $('#aiCost').textContent = chat.totalCost ? `This conversation: ~$${chat.totalCost.toFixed(chat.totalCost < 1 ? 3 : 2)}` : '';
  });
}

async function aiSend(outDir, mode, text) {
  if (!aiConfig) await loadAiConfig();
  if (!aiConfig.hasKey) {
    openSettings('ai');
    return toast('Sign in or add an API key first');
  }
  const chat = chatFor(outDir);
  if (chat.busy) return toast('The assistant is still working on this folder');
  const shown = mode === 'reconstruct' ? 'Reconstruct this program as clean source code.' + (text ? '\n' + text : '') : text;
  chat.items.push({ role: 'user', text: shown }, { role: 'assistant', parts: [] });
  chat.busy = true;
  chat.status = 'Starting…';
  renderAi();
  const file = activeJob?.result.outDir === outDir && mode !== 'reconstruct' ? currentFile : null;
  try {
    await api.aiSend(outDir, { mode, text, currentFile: file });
  } catch (e) {
    chat.busy = false;
    chat.items.push({ role: 'error', text: cleanError(e) });
    renderAi();
  }
}

let treeRefresh = 0;
async function refreshTree(outDir) {
  if (activeJob?.result.outDir !== outDir) return;
  fileList = await api.listFiles(outDir);
  if (activeJob?.result.outDir !== outDir) return;
  if ($('#filter').value.trim()) applyFilter(); else renderTree();
  activeJob.result.files = fileList.length;
  $('#vCount').textContent = `${ENGINE_NAMES[activeJob.result.engine] || ''} · ${fileList.length.toLocaleString()} files`;
}

api.onAiEvent((ev) => {
  const chat = chatFor(ev.outDir);
  let last = chat.items[chat.items.length - 1];
  if (!last || last.role !== 'assistant') chat.items.push((last = { role: 'assistant', parts: [] }));
  const parts = last.parts;
  if (ev.type === 'text') {
    const tail = parts[parts.length - 1];
    if (tail?.type === 'text') tail.text += ev.delta;
    else parts.push({ type: 'text', text: ev.delta });
    chat.status = 'Writing…';
  } else if (ev.type === 'tool') {
    parts.push({ type: 'step', label: ev.label });
    chat.status = ev.label + '…';
  } else if (ev.type === 'file') {
    parts.push({ type: 'file', rel: ev.rel });
    if (activeJob?.result.outDir === ev.outDir && !fileList.includes(ev.rel)) fileList.push(ev.rel);
    // Show new files in the tree now and then, not on every write (the tree re-renders collapsed).
    clearTimeout(treeRefresh);
    treeRefresh = setTimeout(() => refreshTree(ev.outDir), 4000);
  } else if (ev.type === 'status') {
    chat.status = ev.text;
  } else if (ev.type === 'done' || ev.type === 'error') {
    chat.busy = false;
    chat.status = '';
    if (ev.type === 'error') chat.items.push({ role: 'error', text: ev.message });
    else {
      chat.totalCost = ev.totalCost || chat.totalCost;
      if (ev.stopped) parts.push({ type: 'step', label: 'Stopped' });
    }
    clearTimeout(treeRefresh);
    refreshTree(ev.outDir);
    if (ev.type === 'done' && !ev.stopped && activeJob?.result.outDir !== ev.outDir) toast('AI assistant finished');
  }
  if (activeJob?.result.outDir === ev.outDir) renderAi();
});

function sendFromInput() {
  const text = $('#aiInput').value.trim();
  if (!text || !activeJob) return;
  $('#aiInput').value = '';
  aiSend(activeJob.result.outDir, 'chat', text);
}

$('#vAi').addEventListener('click', () => showAiPane($('#aiPane').classList.contains('hidden')));
$('#aiClose').addEventListener('click', () => showAiPane(false));
$('#aiGear').addEventListener('click', () => openSettings('ai'));
$('#aiSetup').addEventListener('click', () => openSettings('ai'));
$('#aiKeyLink').addEventListener('click', () => api.appAction('api-keys'));
$('#aiKeySave').addEventListener('click', async () => {
  if (!$('#aiKey').value.trim()) return $('#aiKey').focus();
  try {
    await api.aiSetKey($('#aiKey').value);
    $('#aiKey').value = '';
    await loadAiConfig();
    flashSaved('API key saved');
  } catch (e) { toast(cleanError(e)); }
});
$('#aiLogin').addEventListener('click', async () => {
  const btn = $('#aiLogin');
  btn.disabled = true;
  $('#aiLoginState').textContent = 'Finish signing in in your browser…';
  $('#aiLoginState').className = 'set-desc';
  try {
    await api.aiLogin();
    await loadAiConfig();
    toast('Signed in to Anthropic');
  } catch (e) {
    $('#aiLoginState').textContent = cleanError(e);
    $('#aiLoginState').className = 'set-desc bad';
  } finally {
    btn.disabled = false;
  }
});
$('#aiLogout').addEventListener('click', async () => {
  try { await api.aiLogout(); } catch (e) { toast(cleanError(e)); }
  await loadAiConfig();
});
$('#aiKeyRemove').addEventListener('click', async () => {
  await api.aiSetKey('');
  await loadAiConfig();
});
api.onAiLoginLog((msg) => {
  if (msg && /download/i.test(msg)) $('#aiLoginState').textContent = msg;
});
$('#aiKey').addEventListener('keydown', (e) => e.key === 'Enter' && $('#aiKeySave').click());
$('#aiModel').addEventListener('change', async () => {
  await api.setSettings({ aiModel: $('#aiModel').value });
  aiConfig.model = $('#aiModel').value;
  flashSaved();
});
$('#aiAuto').addEventListener('change', async () => {
  await api.setSettings({ aiAutoReconstruct: $('#aiAuto').checked });
  aiConfig.autoReconstruct = $('#aiAuto').checked;
  flashSaved();
});
$('#aiNew').addEventListener('click', async () => {
  if (!activeJob) return;
  try {
    await api.aiReset(activeJob.result.outDir);
    aiChats.delete(activeJob.result.outDir);
    renderAi();
  } catch (e) { toast(cleanError(e)); }
});
$('#aiStop').addEventListener('click', () => activeJob && api.aiStop(activeJob.result.outDir));
$('#aiSendBtn').addEventListener('click', sendFromInput);
$('#aiInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendFromInput(); }
});
$('#aiReconstruct').addEventListener('click', () => activeJob && aiSend(activeJob.result.outDir, 'reconstruct', ''));
$('#aiExplain').addEventListener('click', () => {
  if (!activeJob) return;
  if (!currentFile) return toast('Open a file first');
  aiSend(activeJob.result.outDir, 'chat', `Explain what ${currentFile} does: its purpose, how it works step by step, and anything notable (APIs, strings, data it uses).`);
});
$('#aiRewrite').addEventListener('click', () => {
  if (!activeJob) return;
  if (!currentFile) return toast('Open a file first');
  aiSend(activeJob.result.outDir, 'chat', `Rewrite ${currentFile} as clean, readable source with meaningful names, recovered types and comments, keeping its behaviour identical. Save it under ai/ at the same relative path, then summarise what you renamed and what is uncertain.`);
});
$('#aiMessages').addEventListener('click', (e) => {
  const link = e.target.closest('.ai-file');
  if (!link || !activeJob) return;
  const rel = link.dataset.path;
  openFile(rel, document.querySelector(`#tree .node[data-path="${CSS.escape(rel)}"]`));
});

loadAiConfig();
