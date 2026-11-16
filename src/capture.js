// Loads web pages in a hidden, sandboxed browser window (Electron main process only) and records every
// response it receives through the DevTools protocol: the documents, scripts (including chunks loaded later),
// styles, images, fonts, media and API calls. Each capture uses its own in-memory session, so nothing is
// shared with the app or kept afterwards; downloads, pop-ups and permission requests are refused.
const { BrowserWindow, session } = require('electron');

const PAGE_TIMEOUT = 60000;
const IDLE_MS = 1500;
const SKIP_PAGE = /\.(png|jpe?g|gif|webp|avif|svg|ico|css|js|mjs|json|xml|pdf|zip|rar|7z|gz|exe|dmg|msi|mp4|webm|mp3|wav|ogg|woff2?|ttf|otf|eot|apk|iso)$/i;
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function withTimeout(p, ms, fallback) {
  return Promise.race([p, delay(ms).then(() => fallback)]);
}

/**
 * capture(url, { maxPages, shouldCrawl(url) → bool, signal, log })
 *   → { pages: [{ url, html, title }], resources: [{ url, status, mime, headers, body }], redirects: [[from, to]] }
 */
async function capture(startUrl, { maxPages = 20, shouldCrawl = () => true, signal, log = () => {} } = {}) {
  const ses = session.fromPartition(`dropdecompiler-capture-${Date.now()}-${Math.random().toString(36).slice(2)}`, { cache: false });
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  ses.setPermissionCheckHandler(() => false);
  ses.on('will-download', (e) => e.preventDefault());
  // A plain Chrome user agent (without "Electron/…" and the app name), so sites serve their normal pages.
  ses.setUserAgent(ses.getUserAgent().replace(/\s*Electron\/\S+/, '').replace(/\s*drop-?decompiler\/\S+/i, ''));

  const win = new BrowserWindow({
    show: false,
    width: 1440,
    height: 900,
    webPreferences: { session: ses, sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false, spellcheck: false },
  });
  const wc = win.webContents;
  wc.setAudioMuted(true);
  wc.setWindowOpenHandler(() => ({ action: 'deny' }));
  wc.on('will-prevent-unload', (e) => e.preventDefault());

  const resources = new Map(); // url -> resource
  const responses = new Map(); // requestId -> response info
  const redirects = [];
  const inflight = new Set();
  const bodies = [];
  let lastActivity = Date.now();
  const dbg = wc.debugger;

  const onMessage = (_e, method, p) => {
    if (method === 'Network.requestWillBeSent') {
      inflight.add(p.requestId);
      lastActivity = Date.now();
      if (p.redirectResponse) redirects.push([p.redirectResponse.url, p.request.url]);
    } else if (method === 'Network.responseReceived') {
      const r = p.response;
      responses.set(p.requestId, { url: r.url, status: r.status, mime: r.mimeType, headers: lowerKeys(r.headers), type: p.type });
    } else if (method === 'Network.loadingFinished') {
      inflight.delete(p.requestId);
      lastActivity = Date.now();
      const r = responses.get(p.requestId);
      if (!r || !/^https?:/i.test(r.url) || resources.has(r.url)) return;
      bodies.push(dbg.sendCommand('Network.getResponseBody', { requestId: p.requestId })
        .then((b) => { resources.set(r.url, { ...r, body: Buffer.from(b.body, b.base64Encoded ? 'base64' : 'utf8') }); })
        .catch(() => {}));
    } else if (method === 'Network.loadingFailed') {
      inflight.delete(p.requestId);
      lastActivity = Date.now();
    }
  };

  const abort = () => { if (!win.isDestroyed()) win.destroy(); };
  signal?.addEventListener('abort', abort, { once: true });

  async function waitIdle(maxMs) {
    const until = Date.now() + maxMs;
    while (Date.now() < until && !signal?.aborted && !win.isDestroyed()) {
      if (inflight.size === 0 && Date.now() - lastActivity > IDLE_MS) return;
      await delay(250);
    }
  }

  const pages = [];
  try {
    // The DevTools protocol only answers once the window has a document, so start from a blank page.
    await withTimeout(wc.loadURL('about:blank').catch(() => {}), 10000);
    dbg.attach('1.3');
    dbg.on('message', onMessage);
    const ok = await withTimeout(dbg.sendCommand('Network.enable', { maxTotalBufferSize: 400 * 1024 * 1024, maxResourceBufferSize: 100 * 1024 * 1024 }).then(() => true), 15000, false);
    if (!ok) throw new Error('The built-in browser did not start network capture.');
    await withTimeout(dbg.sendCommand('Network.setCacheDisabled', { cacheDisabled: true }).catch(() => {}), 5000);

    const origin = new URL(startUrl).origin;
    const queue = [startUrl];
    const seen = new Set([startUrl.replace(/#.*$/, '')]);
    while (queue.length && pages.length < maxPages) {
      if (signal?.aborted) break;
      const url = queue.shift();
      log(`Loading page ${pages.length + 1}${maxPages > 1 ? ` / ${maxPages}` : ''}: ${url}`, { progress: Math.floor((pages.length * 90) / maxPages) });
      await withTimeout(wc.loadURL(url).catch(() => {}), PAGE_TIMEOUT);
      await waitIdle(30000);
      // Scroll through the page so lazy-loaded images and sections load too.
      await withTimeout(wc.executeJavaScript(`(async () => {
        const h = () => Math.min(document.documentElement.scrollHeight, 40000);
        for (let y = 0; y < h(); y += innerHeight * 0.8) { scrollTo(0, y); await new Promise((r) => setTimeout(r, 200)); }
        scrollTo(0, 0);
      })()`, true).catch(() => {}), 20000);
      await waitIdle(15000);
      const info = await withTimeout(wc.executeJavaScript(`({
        html: (document.doctype ? new XMLSerializer().serializeToString(document.doctype) + '\\n' : '') + document.documentElement.outerHTML,
        title: document.title,
        url: location.href,
        links: [...document.querySelectorAll('a[href]')].map((a) => a.href),
      })`, true).catch(() => null), 15000, null);
      if (!info) continue;
      pages.push({ url: info.url, html: info.html, title: info.title });
      for (const raw of info.links || []) {
        let u;
        try { u = new URL(raw); } catch { continue; }
        u.hash = '';
        const href = u.href;
        if (u.origin !== origin || SKIP_PAGE.test(u.pathname) || seen.has(href) || !shouldCrawl(href)) continue;
        seen.add(href);
        queue.push(href);
      }
    }
    await Promise.all(bodies);
  } finally {
    signal?.removeEventListener('abort', abort);
    try { dbg.detach(); } catch { /* already detached */ }
    if (!win.isDestroyed()) win.destroy();
    ses.clearStorageData().catch(() => {});
  }
  if (signal?.aborted) throw Object.assign(new Error('Cancelled'), { cancelled: true });
  log(`Browser captured ${resources.size.toLocaleString('en')} responses from ${pages.length} page${pages.length === 1 ? '' : 's'}`);
  return { pages, resources: [...resources.values()], redirects };
}

function lowerKeys(h) {
  const o = {};
  for (const [k, v] of Object.entries(h || {})) o[k.toLowerCase()] = String(v);
  return o;
}

module.exports = { capture };
