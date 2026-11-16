// Websites: give a URL, get back everything the browser receives.
//  site/<host>/...      the pages and every asset (HTML, JS, CSS, images, fonts, media, JSON), with links
//                       rewritten so the copy opens offline
//  snapshot/<host>/...  each page as it looked after its JavaScript ran (scripts removed: a static view)
//  sources/...          the original source files (TypeScript, JSX, Vue, SCSS…) recovered from source maps
//  beautified/<host>/.. minified JS / CSS / HTML re-indented
//  resources.csv        every URL with its status, type, size and local file
// Pages are loaded in a real (hidden) browser when main.js passes `opts.capture`, which also catches what
// JavaScript loads later (code-split chunks, lazy images, API calls). Without it, a plain HTTP crawl is used.
// Server-side code (PHP, databases, API logic) never reaches the browser, so no tool can download it.
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const MAX_RESOURCES = 5000;
const MAX_TOTAL = 800 * 1024 * 1024;
const MAX_FILE = 100 * 1024 * 1024;
const MAX_BEAUTIFY = 3 * 1024 * 1024;
const FETCH_TIMEOUT = 30000;
const CONCURRENCY = 6;

const MIME_EXT = {
  'text/html': '.html', 'application/xhtml+xml': '.html', 'text/css': '.css', 'text/javascript': '.js',
  'application/javascript': '.js', 'application/x-javascript': '.js', 'application/json': '.json',
  'application/manifest+json': '.webmanifest', 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif',
  'image/webp': '.webp', 'image/avif': '.avif', 'image/svg+xml': '.svg', 'image/x-icon': '.ico',
  'image/vnd.microsoft.icon': '.ico', 'font/woff2': '.woff2', 'font/woff': '.woff', 'font/ttf': '.ttf',
  'font/otf': '.otf', 'application/font-woff': '.woff', 'video/mp4': '.mp4', 'video/webm': '.webm',
  'audio/mpeg': '.mp3', 'application/wasm': '.wasm', 'text/plain': '.txt', 'application/xml': '.xml', 'text/xml': '.xml',
};
const PAGE_SKIP = /\.(png|jpe?g|gif|webp|avif|svg|ico|css|js|mjs|json|xml|pdf|zip|rar|7z|gz|exe|dmg|msi|mp4|webm|mp3|wav|ogg|woff2?|ttf|otf|eot|apk|iso)$/i;

const sha = (s, n = 8) => crypto.createHash('sha1').update(s).digest('hex').slice(0, n);
const stripHash = (u) => { const x = new URL(u); x.hash = ''; return x.href; };
const isHttp = (u) => /^https?:$/.test(u.protocol);
const decodeEntities = (s) => s.replace(/&amp;/g, '&').replace(/&#x2F;/gi, '/').replace(/&#47;/g, '/').replace(/&quot;/g, '"').replace(/&#39;/g, "'");

function kindOf(r) {
  const m = (r.mime || '').split(';')[0].trim().toLowerCase();
  if (m === 'text/html' || m === 'application/xhtml+xml') return 'html';
  if (m === 'text/css') return 'css';
  if (/javascript|ecmascript/.test(m)) return 'js';
  if (/json/.test(m)) return 'json';
  if (m.startsWith('image/')) return 'image';
  if (m.startsWith('font/') || /font|woff/.test(m)) return 'font';
  if (m.startsWith('video/') || m.startsWith('audio/')) return 'media';
  const ext = path.extname(new URL(r.url).pathname).toLowerCase();
  if (/^\.(html?|php|aspx?|jsp)$/.test(ext)) return 'html';
  if (ext === '.css') return 'css';
  if (/^\.(m?js|cjs)$/.test(ext)) return 'js';
  if (ext === '.json' || ext === '.map') return 'json';
  return 'other';
}

// ---------------------------------------------------------------- reference extraction

const ATTR_RE = /(\s(?:src|href|poster|data-src|data-original|data-lazy-src|data-bg|data-background|background|action)\s*=\s*)("([^"]*)"|'([^']*)'|([^\s>"']+))/gi;
const SRCSET_RE = /(\s(?:srcset|data-srcset|imagesrcset)\s*=\s*)("([^"]*)"|'([^']*)')/gi;
const CSS_URL_RE = /url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi;
const CSS_IMPORT_RE = /@import\s+(['"])([^'"]+)\1/gi;

function baseOf(html, pageUrl) {
  const m = /<base\s[^>]*href\s*=\s*["']([^"']+)["']/i.exec(html);
  try { return m ? new URL(decodeEntities(m[1]), pageUrl).href : pageUrl; } catch { return pageUrl; }
}

function resolve(ref, base) {
  ref = decodeEntities(ref.trim());
  if (!ref || /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(ref)) return null;
  try {
    const u = new URL(ref, base);
    return isHttp(u) ? u : null;
  } catch { return null; }
}

/** URLs an HTML page refers to: { assets, pages } (absolute, without #hash). */
function htmlRefs(html, pageUrl) {
  const base = baseOf(html, pageUrl);
  const assets = new Set();
  const pages = new Set();
  // <a href> are pages; <link href> and the other attributes are assets.
  for (const tag of html.matchAll(/<(a|link|script|img|source|video|audio|iframe|embed|object|input|track|image|use|meta)\b[^>]*>/gi)) {
    const name = tag[1].toLowerCase();
    const t = tag[0];
    for (const m of t.matchAll(ATTR_RE)) {
      const u = resolve(m[3] ?? m[4] ?? m[5] ?? '', base);
      if (!u) continue;
      if (name === 'a' || (name === 'link' && /rel\s*=\s*["']?(alternate|canonical|next|prev)/i.test(t))) pages.add(stripHash(u.href));
      else if (name !== 'iframe' || !PAGE_SKIP.test(u.pathname)) assets.add(stripHash(u.href));
    }
    for (const m of t.matchAll(SRCSET_RE)) {
      for (const part of (m[3] ?? m[4]).split(',')) {
        const u = resolve(part.trim().split(/\s+/)[0] || '', base);
        if (u) assets.add(stripHash(u.href));
      }
    }
    if (name === 'meta' && /property\s*=\s*["']og:image/i.test(t)) {
      const c = /content\s*=\s*["']([^"']+)/i.exec(t);
      const u = c && resolve(c[1], base);
      if (u) assets.add(stripHash(u.href));
    }
  }
  for (const u of cssRefs(html, base)) assets.add(u);
  return { assets: [...assets], pages: [...pages] };
}

function cssRefs(css, base) {
  const out = new Set();
  for (const re of [CSS_URL_RE, CSS_IMPORT_RE]) {
    for (const m of css.matchAll(re)) {
      const u = resolve(m[2], base);
      if (u) out.add(stripHash(u.href));
    }
  }
  return [...out];
}

// ---------------------------------------------------------------- robots.txt

async function loadRobots(origin, signal) {
  const rules = [];
  try {
    const res = await fetch(origin + '/robots.txt', { headers: { 'User-Agent': UA }, signal: AbortSignal.any([signal || new AbortController().signal, AbortSignal.timeout(10000)]) });
    if (!res.ok) return () => true;
    let applies = false;
    let lastWasAgent = false;
    for (const raw of (await res.text()).split(/\r?\n/)) {
      const line = raw.replace(/#.*/, '').trim();
      const m = /^([\w-]+)\s*:\s*(.*)$/.exec(line);
      if (!m) continue;
      const key = m[1].toLowerCase();
      if (key === 'user-agent') {
        if (!lastWasAgent) applies = false;
        if (m[2].trim() === '*') applies = true;
        lastWasAgent = true;
        continue;
      }
      lastWasAgent = false;
      if (applies && (key === 'disallow' || key === 'allow') && m[2]) rules.push({ allow: key === 'allow', path: m[2].trim() });
    }
  } catch { return () => true; }
  const toRe = (p) => new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\\\$$/, '$'));
  const compiled = rules.map((r) => ({ ...r, re: toRe(r.path), len: r.path.length }));
  return (url) => {
    const u = new URL(url);
    const p = u.pathname + u.search;
    let best = null;
    for (const r of compiled) if (r.re.test(p) && (!best || r.len > best.len || (r.len === best.len && r.allow))) best = r;
    return !best || best.allow;
  };
}

// ---------------------------------------------------------------- fetching

class Store {
  constructor() {
    this.map = new Map(); // url (no hash) -> { url, status, mime, headers, body, source }
    this.alias = new Map(); // redirected-from url -> final url
    this.total = 0;
  }
  get(url) {
    const k = stripHash(url);
    return this.map.get(k) || this.map.get(this.alias.get(k));
  }
  has(url) { return !!this.get(url); }
  add(r) {
    if (!r.body || this.map.size >= MAX_RESOURCES || this.total + r.body.length > MAX_TOTAL || r.body.length > MAX_FILE) return false;
    const k = stripHash(r.url);
    if (this.map.has(k)) return false;
    this.map.set(k, { ...r, url: k });
    this.total += r.body.length;
    return true;
  }
}

async function fetchOne(url, signal) {
  const res = await fetch(url, {
    headers: { 'User-Agent': UA, Accept: '*/*' },
    redirect: 'follow',
    signal: AbortSignal.any([signal || new AbortController().signal, AbortSignal.timeout(FETCH_TIMEOUT)]),
  });
  const len = Number(res.headers.get('content-length')) || 0;
  if (len > MAX_FILE) { res.body?.cancel(); throw new Error('too large'); }
  const body = Buffer.from(await res.arrayBuffer());
  return { url: res.url || url, requested: url, status: res.status, mime: res.headers.get('content-type') || '', headers: Object.fromEntries(res.headers), body, source: 'fetch' };
}

/** Fetches URLs not in the store yet, a few at a time. */
async function fetchMissing(store, urls, signal, log) {
  const todo = [...new Set(urls)].filter((u) => !store.has(u) && !store.failed?.has(u));
  store.failed ||= new Set();
  let i = 0;
  let got = 0;
  const worker = async () => {
    while (i < todo.length) {
      if (signal?.aborted) return;
      const u = todo[i++];
      try {
        const r = await fetchOne(u, signal);
        if (r.status >= 200 && r.status < 300) {
          if (stripHash(r.url) !== stripHash(u)) store.alias.set(stripHash(u), stripHash(r.url));
          if (store.add(r)) got++;
        } else store.failed.add(u);
      } catch { store.failed.add(u); }
      if (todo.length > 20 && i % 25 === 0) log(`Downloading assets ${Math.min(i, todo.length)} / ${todo.length}`, { quiet: true });
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return got;
}

/** Plain HTTP crawl (used when no browser capture is available). */
async function staticCrawl(startUrl, { maxPages, shouldCrawl, signal, log }) {
  const store = new Store();
  const pages = [];
  const queue = [startUrl];
  const seen = new Set([stripHash(startUrl)]);
  const origin = new URL(startUrl).origin;
  while (queue.length && pages.length < maxPages) {
    if (signal?.aborted) break;
    const url = queue.shift();
    log(`Loading ${url}`);
    let r;
    try { r = await fetchOne(url, signal); } catch (e) { log(`Could not load ${url}: ${e.message}`, { warn: true }); continue; }
    if (stripHash(r.url) !== stripHash(url)) store.alias.set(stripHash(url), stripHash(r.url));
    store.add(r);
    if (kindOf(r) !== 'html') continue;
    const html = r.body.toString('utf8');
    pages.push({ url: r.url, html: null, title: (/<title[^>]*>([^<]*)/i.exec(html) || [])[1]?.trim() || '' });
    const refs = htmlRefs(html, r.url);
    for (const p of refs.pages) {
      const u = new URL(p);
      if (u.origin !== origin || PAGE_SKIP.test(u.pathname) || seen.has(p) || !shouldCrawl(p)) continue;
      seen.add(p);
      queue.push(p);
    }
    await fetchMissing(store, refs.assets, signal, log);
  }
  return { store, pages };
}

// ---------------------------------------------------------------- local paths and rewriting

const WIN_BAD = /[<>:"|?*\x00-\x1f]/g;
const RESERVED = /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i;

function safeSegment(s) {
  let out = s.replace(WIN_BAD, '_').replace(/[. ]+$/, '_');
  if (RESERVED.test(out)) out = '_' + out;
  if (out.length > 120) out = out.slice(0, 100) + '_' + sha(out);
  return out || '_';
}

/** Assigns every stored URL a unique relative file path under site/. */
function assignPaths(store) {
  const paths = new Map();
  const used = new Set();
  for (const r of store.map.values()) {
    const u = new URL(r.url);
    const host = safeSegment(u.host.replace(':', '_'));
    let p;
    try { p = decodeURIComponent(u.pathname); } catch { p = u.pathname; }
    let segs = p.split('/').filter((s) => s && s !== '.' && s !== '..').map(safeSegment);
    const kind = kindOf(r);
    let file = p.endsWith('/') || !segs.length ? 'index' : segs.pop();
    let ext = path.extname(file);
    if (kind === 'html' && !/^\.html?$/i.test(ext)) { file += '.html'; ext = '.html'; }
    else if (!ext) {
      ext = MIME_EXT[(r.mime || '').split(';')[0].trim().toLowerCase()] || '';
      file += ext;
    }
    if (u.search) file = file.slice(0, file.length - ext.length) + '_' + sha(u.search) + ext;
    let rel = [host, ...segs, file].join('/');
    if (used.has(rel.toLowerCase())) rel = rel.slice(0, rel.length - ext.length) + '_' + sha(r.url) + ext;
    used.add(rel.toLowerCase());
    paths.set(r.url, rel);
  }
  return paths;
}

function relLink(fromRel, toRel) {
  const r = path.posix.relative(path.posix.dirname(fromRel), toRel);
  return r.split('/').map(encodeURIComponent).join('/');
}

function makeRewriter(store, paths) {
  // Returns the local link for `ref` (relative to the file at `fromRel`), or an absolute URL.
  return (ref, base, fromRel, keepIfUnknown) => {
    const raw = ref.trim();
    if (!raw || /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(raw)) return ref;
    let u;
    try { u = new URL(decodeEntities(raw), base); } catch { return ref; }
    if (!isHttp(u)) return ref;
    const hit = store.get(u.href);
    if (hit) return relLink(fromRel, 'site/' + paths.get(hit.url)) + u.hash;
    return keepIfUnknown ? ref : u.href;
  };
}

function rewriteCss(css, base, fromRel, link) {
  return css
    .replace(CSS_URL_RE, (m, q, ref) => `url(${q}${link(ref, base, fromRel)}${q})`)
    .replace(CSS_IMPORT_RE, (m, q, ref) => `@import ${q}${link(ref, base, fromRel)}${q}`);
}

function rewriteHtml(html, pageUrl, fromRel, link) {
  const base = baseOf(html, pageUrl);
  return html
    .replace(/<base\s[^>]*>/gi, '')
    .replace(/(<(?:a|link|script|img|source|video|audio|iframe|embed|object|input|track|image|use|form|body|table|td)\b)([^>]*)>/gi, (m, open, attrs) =>
      open + attrs
        // Subresource integrity and CORS attributes would block the local files.
        .replace(/\s(integrity|crossorigin)(\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?(?=[\s/]|$)/gi, '')
        .replace(ATTR_RE, (a, pre, _q, d, s, bare) => {
          const ref = d ?? s ?? bare ?? '';
          const q = d !== undefined ? '"' : s !== undefined ? "'" : '"';
          return `${pre}${q}${link(ref, base, fromRel)}${q}`;
        })
        .replace(SRCSET_RE, (a, pre, _q, d, s) => {
          const q = d !== undefined ? '"' : "'";
          const v = (d ?? s).split(',').map((part) => {
            const [u, ...rest] = part.trim().split(/\s+/);
            return [link(u || '', base, fromRel), ...rest].join(' ');
          }).join(', ');
          return `${pre}${q}${v}${q}`;
        }) + '>')
    .replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, css, b) => a + rewriteCss(css, base, fromRel, link) + b)
    .replace(/(\sstyle\s*=\s*)("([^"]*)"|'([^']*)')/gi, (m, pre, _q, d, s) => {
      const q = d !== undefined ? '"' : "'";
      return `${pre}${q}${rewriteCss(d ?? s, base, fromRel, link)}${q}`;
    });
}

// ---------------------------------------------------------------- source maps

function mapUrlOf(r) {
  const header = r.headers?.sourcemap || r.headers?.['x-sourcemap'];
  if (header) return header;
  const tail = r.body.subarray(Math.max(0, r.body.length - 4096)).toString('utf8');
  const m = /[#@]\s*sourceMappingURL\s*=\s*([^\s*'"]+)\s*(?:\*\/)?\s*$/.exec(tail.trimEnd());
  if (m) return m[1];
  // Inline maps can be large: look at the whole file only if the tail didn't contain it.
  const all = /[#@]\s*sourceMappingURL\s*=\s*(data:[^\s*'"]+)/.exec(r.body.toString('utf8'));
  return all ? all[1] : null;
}

function cleanSourcePath(src, root) {
  let s = (root && !/^[a-z]+:/i.test(src) ? root.replace(/\/?$/, '/') : '') + src;
  s = s.replace(/^webpack:\/\/\/?/i, '').replace(/^[a-z][\w+.-]*:\/\/\/?/i, '').replace(/^[a-z][\w+.-]*:/i, '').replace(/[?#].*$/, '');
  const out = [];
  for (const seg of s.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(safeSegment(seg));
  }
  if (out[0] === '~') out[0] = 'node_modules';
  return out.join('/') || 'unknown';
}

async function recoverSources(store, outDir, signal, log, { probe = true } = {}) {
  const written = new Map(); // rel -> content hash
  let maps = 0;
  let files = 0;
  let appFiles = 0;
  let hidden = 0;
  let fetchedSources = 0;

  // 1. Which source map belongs to which file: declared (comment / header / inline), or — when nothing is
  //    declared — probed at <file>.map, where build tools put it even when the comment was stripped.
  const jobs = []; // { mapUrl, inline, probed }
  const seen = new Set();
  for (const r of [...store.map.values()]) {
    const kind = kindOf(r);
    if (kind !== 'js' && kind !== 'css') continue;
    const ref = mapUrlOf(r);
    if (ref && /^data:/i.test(ref)) { jobs.push({ inline: ref }); continue; }
    let mapUrl;
    let probed = false;
    if (ref) { try { mapUrl = new URL(ref, r.url).href; } catch { continue; } }
    else if (probe) {
      const u = new URL(r.url);
      u.search = '';
      u.hash = '';
      mapUrl = u.href + '.map';
      probed = true;
    } else continue;
    if (seen.has(mapUrl)) continue;
    seen.add(mapUrl);
    jobs.push({ mapUrl, probed });
  }
  const toFetch = jobs.filter((j) => j.mapUrl && !store.has(j.mapUrl)).slice(0, 1500);
  if (toFetch.length) log(`Looking for ${toFetch.length} source map${toFetch.length === 1 ? '' : 's'}…`, { quiet: true });
  await mapPool(toFetch, CONCURRENCY, async (j) => {
    if (signal?.aborted) return;
    const f = await fetchOne(j.mapUrl, signal).catch(() => null);
    if (!f || f.status !== 200) return;
    const head = f.body.subarray(0, 200).toString('utf8').trimStart();
    if (!/^(\)\]\}'|\{)/.test(head)) return; // an HTML error page, not a map
    store.add({ ...f, url: j.mapUrl });
  });

  // 2. Parse the maps; sources listed without their content are downloaded next to them.
  const parsed = [];
  const missing = [];
  for (const j of jobs) {
    let json;
    try {
      if (j.inline) {
        const comma = j.inline.indexOf(',');
        const meta = j.inline.slice(5, comma);
        const data = j.inline.slice(comma + 1);
        json = JSON.parse(/;base64/i.test(meta) ? Buffer.from(data, 'base64').toString('utf8') : decodeURIComponent(data));
      } else {
        const m = store.get(j.mapUrl);
        if (!m) continue;
        json = JSON.parse(m.body.toString('utf8').replace(/^\)\]\}'[^\n]*\n/, ''));
      }
    } catch { continue; }
    if (!json || (!json.sources && !json.sections)) continue;
    if (j.probed) hidden++;
    for (const sm of json.sections ? json.sections.map((s) => s.map).filter(Boolean) : [json]) {
      maps++;
      const sources = sm.sources || [];
      const contents = (sm.sourcesContent || []).slice();
      for (let i = 0; i < sources.length; i++) {
        if (typeof contents[i] === 'string' || !j.mapUrl || missing.length >= 2000) continue;
        try {
          const u = new URL((sm.sourceRoot ? sm.sourceRoot.replace(/\/?$/, '/') : '') + sources[i], j.mapUrl);
          if (/^https?:$/.test(u.protocol)) missing.push({ contents, i, url: u.href });
        } catch { /* webpack:// and other virtual paths */ }
      }
      parsed.push({ sm, contents });
    }
  }
  if (missing.length) {
    log(`Downloading ${missing.length} original source files listed by the source maps…`, { quiet: true });
    await mapPool(missing, CONCURRENCY, async (m) => {
      if (signal?.aborted) return;
      const f = await fetchOne(m.url, signal).catch(() => null);
      if (!f || f.status !== 200 || /text\/html/i.test(f.mime) || f.body.length > MAX_FILE) return;
      m.contents[m.i] = f.body.toString('utf8');
      fetchedSources++;
    });
  }

  // 3. Write every source file once.
  for (const { sm, contents } of parsed) {
    const sources = sm.sources || [];
    for (let i = 0; i < sources.length; i++) {
      const content = contents[i];
      if (typeof content !== 'string') continue;
      let rel = cleanSourcePath(sources[i], sm.sourceRoot);
      const h = sha(content, 12);
      if (written.has(rel)) {
        if (written.get(rel) === h) continue;
        const ext = path.posix.extname(rel);
        rel = rel.slice(0, rel.length - ext.length) + '.' + h.slice(0, 6) + ext;
        if (written.has(rel)) continue;
      }
      written.set(rel, h);
      const dest = path.join(outDir, 'sources', ...rel.split('/'));
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      await fsp.writeFile(dest, content);
      files++;
      if (!/(^|\/)node_modules\//.test(rel) && !/^(webpack|vite)\//.test(rel)) appFiles++;
    }
  }
  if (maps) {
    log(`Source maps: ${maps} found${hidden ? ` (${hidden} not linked from their files)` : ''}, ${files.toLocaleString('en')} original source files recovered (${appFiles.toLocaleString('en')} outside node_modules)${fetchedSources ? `, ${fetchedSources} downloaded separately` : ''}`);
  }
  return { maps, files, appFiles, hidden };
}

async function mapPool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

// ---------------------------------------------------------------- beautify

function looksMinified(text) {
  if (text.length < 2000) return false;
  const lines = text.split('\n').length;
  return text.length / lines > 250;
}

async function beautifyAll(store, paths, outDir, log) {
  let beautify;
  try { beautify = require('js-beautify'); } catch { return 0; }
  let n = 0;
  for (const r of store.map.values()) {
    const kind = kindOf(r);
    if (!['js', 'css', 'html', 'json'].includes(kind) || r.body.length > MAX_BEAUTIFY || /\.map$/i.test(new URL(r.url).pathname)) continue;
    const text = r.body.toString('utf8');
    if (!looksMinified(text)) continue;
    let out;
    try {
      if (kind === 'js') out = beautify.js(text, { indent_size: 2, max_preserve_newlines: 2 });
      else if (kind === 'css') out = beautify.css(text, { indent_size: 2 });
      else if (kind === 'html') out = beautify.html(text, { indent_size: 2, max_preserve_newlines: 1 });
      else out = JSON.stringify(JSON.parse(text), null, 2);
    } catch { continue; }
    const dest = path.join(outDir, 'beautified', ...paths.get(r.url).split('/'));
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await fsp.writeFile(dest, out);
    n++;
  }
  if (n) log(`Re-indented ${n} minified files into beautified/`);
  return n;
}

// ---------------------------------------------------------------- technology hints

const TECH = [
  ['Next.js', /\/_next\/|__NEXT_DATA__/], ['Nuxt', /\/_nuxt\/|__NUXT__/], ['Gatsby', /___gatsby/],
  ['Remix', /__remixContext/], ['Astro', /astro-island|\/_astro\//], ['SvelteKit', /__sveltekit|\/_app\/immutable\//],
  ['Angular', /ng-version=|ng-app/], ['React', /react-dom|data-reactroot|__REACT_DEVTOOLS|_reactRootContainer|react\.production/],
  ['Vue', /data-v-[0-9a-f]{6,}|vue\.runtime|__VUE__/], ['Svelte', /svelte-[a-z0-9]{6}/], ['Preact', /preact/],
  ['jQuery', /jquery[.-]/i], ['Bootstrap', /bootstrap(\.min)?\.(css|js)/], ['Tailwind CSS', /tailwind|--tw-/],
  ['webpack', /webpackChunk|__webpack_require__/], ['Vite', /\/@vite\/|vite\/modulepreload/],
  ['WordPress', /wp-content|wp-includes/], ['Shopify', /cdn\.shopify\.com|Shopify\.theme/], ['Wix', /wixstatic|_wixCssImports/],
  ['Squarespace', /squarespace/], ['Webflow', /webflow/], ['Drupal', /drupal/i], ['Joomla', /joomla/i],
  ['Google Analytics / Tag Manager', /googletagmanager|google-analytics/], ['Cloudflare', /cdn-cgi|cloudflare/],
  ['Three.js', /three(\.module)?(\.min)?\.js|THREE\.WebGLRenderer/], ['Unity WebGL', /UnityLoader|\.unityweb|createUnityInstance/],
];

function detectTech(store) {
  const found = new Set();
  const servers = new Set();
  for (const r of store.map.values()) {
    const kind = kindOf(r);
    const sample = r.url + ' ' + (kind === 'html' || kind === 'js' ? r.body.subarray(0, 400000).toString('utf8') : '');
    for (const [name, re] of TECH) if (re.test(sample)) found.add(name);
    if (kind === 'html') {
      if (r.headers?.server) servers.add(`Server: ${r.headers.server}`);
      if (r.headers?.['x-powered-by']) servers.add(`X-Powered-By: ${r.headers['x-powered-by']}`);
      const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i.exec(r.body.toString('utf8'));
      if (gen) servers.add(`Generator: ${gen[1]}`);
    }
  }
  return { tech: [...found], servers: [...servers] };
}

// ---------------------------------------------------------------- main

function fmtBytes(n) {
  if (n >= 2 ** 20) return (n / 2 ** 20).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}

/**
 * opts.capture(url, { maxPages, shouldCrawl, signal, log }) → { resources: [...], pages: [{ url, html, title }] }
 * comes from main.js (a hidden browser window). opts.maxPages limits how many pages of the site are visited.
 */
async function decompileWebsite(_tools, url, outDir, log, opts = {}) {
  const { signal } = opts;
  const maxPages = Math.max(1, Math.min(1000, Number(opts.maxPages) || 20));
  const start = new URL(url);
  const robots = await loadRobots(start.origin, signal);
  const shouldCrawl = (u) => robots(u);
  if (!robots(start.href)) log('robots.txt asks crawlers to skip this page; only this page is loaded, no others.', { warn: true });

  let store;
  let pages;
  if (opts.capture) {
    log(`Opening ${start.href} in a hidden browser (up to ${maxPages} page${maxPages === 1 ? '' : 's'})…`);
    const cap = await opts.capture(start.href, { maxPages, shouldCrawl, signal, log });
    store = new Store();
    for (const [from, to] of cap.redirects || []) store.alias.set(stripHash(from), stripHash(to));
    for (const r of cap.resources) {
      if (r.status >= 200 && r.status < 300) store.add({ ...r, source: 'browser' });
    }
    pages = cap.pages;
  } else {
    ({ store, pages } = await staticCrawl(start.href, { maxPages, shouldCrawl, signal, log }));
  }
  if (!store.map.size) throw new Error('Nothing could be downloaded from this address. Check the link and your connection.');
  if (signal?.aborted) throw Object.assign(new Error('Cancelled'), { cancelled: true });

  // Second pass: things pages and stylesheets refer to that the browser didn't load (other image sizes,
  // fonts for other weights, background images of hidden elements, CSS @imports).
  for (let round = 0; round < 3; round++) {
    const want = [];
    for (const r of store.map.values()) {
      const kind = kindOf(r);
      if (kind === 'html') want.push(...htmlRefs(r.body.toString('utf8'), r.url).assets);
      else if (kind === 'css') want.push(...cssRefs(r.body.toString('utf8'), r.url));
    }
    for (const p of pages) if (p.html) want.push(...htmlRefs(p.html, p.url).assets);
    const missing = want.filter((u) => !store.has(u));
    if (!missing.length) break;
    log(`Downloading ${missing.length} more referenced assets…`);
    if (!(await fetchMissing(store, missing, signal, log))) break;
  }

  const sources = await recoverSources(store, outDir, signal, log, { probe: opts.originalSources !== false });
  const paths = assignPaths(store);
  const link = makeRewriter(store, paths);

  log(`Saving ${store.map.size.toLocaleString('en')} files…`);
  const csv = ['url,status,type,size,file'];
  const counts = {};
  for (const r of store.map.values()) {
    const rel = paths.get(r.url);
    const kind = kindOf(r);
    counts[kind] = counts[kind] || { n: 0, size: 0 };
    counts[kind].n++;
    counts[kind].size += r.body.length;
    let body = r.body;
    if (kind === 'html') body = rewriteHtml(r.body.toString('utf8'), r.url, 'site/' + rel, link);
    else if (kind === 'css') body = rewriteCss(r.body.toString('utf8'), r.url, 'site/' + rel, link);
    const dest = path.join(outDir, 'site', ...rel.split('/'));
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await fsp.writeFile(dest, body);
    csv.push(`"${r.url.replace(/"/g, '""')}",${r.status},${(r.mime || '').split(';')[0]},${r.body.length},site/${rel}`);
  }
  await fsp.writeFile(path.join(outDir, 'resources.csv'), csv.join('\n') + '\n');

  // Rendered pages: what the user saw, frozen (scripts removed so it doesn't render twice).
  let snapshots = 0;
  for (const p of pages) {
    if (!p.html) continue;
    const hit = store.get(p.url);
    const rel = hit ? paths.get(hit.url) : `${safeSegment(new URL(p.url).host)}/page_${sha(p.url)}.html`;
    const html = rewriteHtml(p.html.replace(/<script\b[\s\S]*?<\/script>/gi, '').replace(/<link[^>]+rel=["']?(modulepreload|preload)["']?[^>]*as=["']?script[^>]*>/gi, ''), p.url, 'snapshot/' + rel, link);
    const dest = path.join(outDir, 'snapshot', ...rel.split('/'));
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await fsp.writeFile(dest, html.replace(/^/, `<!-- Snapshot of ${p.url} after its scripts ran. Scripts removed. -->\n`));
    snapshots++;
  }

  const beautified = await beautifyAll(store, paths, outDir, log);
  const { tech, servers } = detectTech(store);
  const hosts = {};
  for (const r of store.map.values()) { const h = new URL(r.url).host; hosts[h] = (hosts[h] || 0) + 1; }
  const firstPage = store.get(pages[0]?.url || start.href);
  const entry = firstPage ? paths.get(firstPage.url) : null;

  const order = ['html', 'js', 'css', 'json', 'image', 'font', 'media', 'other'];
  const names = { html: 'Pages (HTML)', js: 'JavaScript', css: 'Stylesheets', json: 'JSON / API data', image: 'Images', font: 'Fonts', media: 'Video / audio', other: 'Other' };
  const md = [
    `# ${start.host}`, '',
    `Website downloaded from ${start.href} — ${pages.length} page${pages.length === 1 ? '' : 's'} visited, ${store.map.size.toLocaleString('en')} files, ${fmtBytes(store.total)}.`, '',
    entry ? `**Open offline:** \`site/${entry}\`${snapshots ? ` · rendered view: \`snapshot/${entry}\`` : ''}` : '', '',
    '## What was downloaded', '',
    '| Type | Files | Size |', '|---|---|---|',
    ...order.filter((k) => counts[k]).map((k) => `| ${names[k]} | ${counts[k].n.toLocaleString('en')} | ${fmtBytes(counts[k].size)} |`), '',
    '## Folders', '',
    '- `site/` — every file exactly as the server sent it, under its host name, with links rewritten to the local copies.',
    snapshots ? '- `snapshot/` — each page as it looked after its JavaScript ran, with scripts removed (a static view that always opens).' : null,
    sources.files ? `- \`sources/\` — **original source code** recovered from ${sources.maps} source map${sources.maps === 1 ? '' : 's'}: ${sources.files.toLocaleString('en')} files (${sources.appFiles.toLocaleString('en')} of the site's own code; the rest are libraries under node_modules).` : '- No source maps were published, so the JavaScript is only available in its built (bundled / minified) form.',
    beautified ? `- \`beautified/\` — ${beautified} minified JS / CSS / HTML files re-indented for reading.` : null,
    '- `resources.csv` — every URL with status, type, size and local file.', '',
    tech.length || servers.length ? '## Built with' : null, tech.length || servers.length ? '' : null,
    ...tech.map((t) => `- ${t}`), ...servers.map((s) => `- ${s}`), tech.length || servers.length ? '' : null,
    '## Pages', '', ...pages.map((p) => `- ${p.title ? `${p.title} — ` : ''}${p.url}`), '',
    '## Hosts', '', ...Object.entries(hosts).sort((a, b) => b[1] - a[1]).map(([h, n]) => `- ${h}: ${n} file${n === 1 ? '' : 's'}`), '',
    '## Limits', '',
    '- Only what the server sends to a browser can be downloaded. Server-side code (PHP, Node, databases, API logic) never leaves the server.',
    '- Opening `site/` from disk: pages and styles work; apps that load code by absolute path (`/assets/…`) or call their API need the site to be served from a web server (for example `npx serve site/<host>`).',
    '- Pages behind a login and content loaded only after clicks are not included.', '',
    'Open the **AI assistant** to explain how the site works or rebuild it as a clean project.', '',
  ].filter((l) => l !== null);
  await fsp.writeFile(path.join(outDir, 'README.md'), md.join('\n'));
  log(`${pages.length} page${pages.length === 1 ? '' : 's'}, ${store.map.size.toLocaleString('en')} files${sources.files ? `, ${sources.files.toLocaleString('en')} original sources` : ''}`);
}

module.exports = { decompileWebsite, htmlRefs, cssRefs, cleanSourcePath, rewriteHtml, isUrl: (s) => /^https?:\/\/[^\s]+$/i.test(String(s)) };
