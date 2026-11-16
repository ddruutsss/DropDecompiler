// iOS apps (.ipa): unpacks the bundle and decompiles everything in it.
//   headers/<image>/   Objective-C headers of every class, category and protocol (class-dump format)
//   swift/<image>/     Swift interfaces: classes, structs, enums, protocols with their stored properties
//   code/              Ghidra pseudo-C of the app's executable, functions named from its ObjC/Swift metadata
//   app/               every bundle file; binary plists, .strings and compiled nibs decoded to readable text
//   info/              Info.plist, entitlements, provisioning profile, linked libraries, URLs, possible secrets
//   react-native/, web-app/, dotnet/  code of cross-platform frameworks
//   README.md          an analysis report: identity, signing, permissions, capabilities, security, SDKs
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const AdmZip = require('adm-zip');
const plist = require('./plist');
const { MachO, isMachO } = require('./macho');
const objc = require('./objc');
const swift = require('./swift');
const { nibText } = require('./nib');
const { analyzeFrameworks } = require('./frameworks');

const IS_WIN = process.platform === 'win32';

// ---------------------------------------------------------------- helpers

function extract(archive, dest) {
  return new Promise((resolve) => {
    fs.mkdirSync(dest, { recursive: true });
    const tar = IS_WIN ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
    const child = spawn(tar, ['-xf', archive, '-C', dest], { windowsHide: true });
    child.on('error', () => resolve(false));
    child.on('close', (code) => resolve(code === 0));
  }).then((ok) => { if (!ok) new AdmZip(archive).extractAllTo(dest, true); });
}

async function walk(dir, base = dir, out = []) {
  for (const e of await fsp.readdir(dir, { withFileTypes: true })) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) await walk(abs, base, out);
    else if (e.isFile()) out.push({ abs, rel: path.relative(base, abs).split(path.sep).join('/') });
  }
  return out;
}

async function head(file, n = 16) {
  const fh = await fsp.open(file, 'r');
  try { const b = Buffer.alloc(n); const { bytesRead } = await fh.read(b, 0, n, 0); return b.subarray(0, bytesRead); } finally { await fh.close(); }
}

const readPlist = async (file) => { try { return plist.parse(await fsp.readFile(file)); } catch { return null; } };
const fmtBytes = (n) => (n >= 2 ** 20 ? `${(n / 2 ** 20).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
const safe = (s) => s.replace(/[<>:"|?*\x00-\x1f]/g, '_');

/** Is this zip an iOS app (Payload/X.app/ or a zipped X.app/)? */
function isIpa(file, names) {
  if (/\.ipa$/i.test(file)) return true;
  return names.some((n) => /^(Payload\/)?[^/]+\.app\/Info\.plist$/i.test(n));
}

// ---------------------------------------------------------------- knowledge

const PERMISSIONS = {
  NSCameraUsageDescription: 'Camera', NSMicrophoneUsageDescription: 'Microphone', NSPhotoLibraryUsageDescription: 'Photo library',
  NSPhotoLibraryAddUsageDescription: 'Save to photo library', NSLocationWhenInUseUsageDescription: 'Location (while using the app)',
  NSLocationAlwaysAndWhenInUseUsageDescription: 'Location (always)', NSLocationAlwaysUsageDescription: 'Location (always, legacy)',
  NSLocationUsageDescription: 'Location', NSContactsUsageDescription: 'Contacts', NSCalendarsUsageDescription: 'Calendars',
  NSCalendarsFullAccessUsageDescription: 'Calendars (full access)', NSRemindersUsageDescription: 'Reminders',
  NSBluetoothAlwaysUsageDescription: 'Bluetooth', NSBluetoothPeripheralUsageDescription: 'Bluetooth (legacy)', NSFaceIDUsageDescription: 'Face ID',
  NSMotionUsageDescription: 'Motion & fitness', NSHealthShareUsageDescription: 'Health (read)', NSHealthUpdateUsageDescription: 'Health (write)',
  NSSpeechRecognitionUsageDescription: 'Speech recognition', NSUserTrackingUsageDescription: 'Tracking across apps (ATT / IDFA)',
  NSLocalNetworkUsageDescription: 'Local network', NSAppleMusicUsageDescription: 'Media & Apple Music', NSSiriUsageDescription: 'Siri',
  NSHomeKitUsageDescription: 'HomeKit', NSNearbyInteractionUsageDescription: 'Nearby Interaction (UWB)', NFCReaderUsageDescription: 'NFC',
  NSFocusStatusUsageDescription: 'Focus status', NSSensorKitUsageDescription: 'SensorKit', NSIdentityUsageDescription: 'Identity documents',
};

// Third-party SDKs: [name, pattern over frameworks / Swift modules / ObjC class names / linked libraries]
const SDKS = [
  ['Firebase', /^(FIR(?!CLS)|Firebase)/], ['Firebase Crashlytics', /^(FIRCLS|FirebaseCrashlytics|Crashlytics)/], ['Google Mobile Ads (AdMob)', /^(GAD|GoogleMobileAds)/],
  ['Google Sign-In', /^(GID|GoogleSignIn)/], ['Google Analytics', /^(GAI|GoogleAnalytics)/], ['Facebook SDK', /^(FBSDK|FBAEM|FacebookCore|FBSDKCoreKit)/],
  ['Alamofire', /^Alamofire/], ['AFNetworking', /^AF(HTTP|URL|Network)/], ['Kingfisher', /^Kingfisher/], ['SDWebImage', /^SDWebImage|^SDImage/],
  ['Nuke', /^Nuke(UI)?$/], ['Realm', /^(RLM|Realm)/], ['GRDB', /^GRDB/], ['SQLite.swift', /^SQLite$/], ['Sentry', /^Sentry/], ['Bugsnag', /^Bugsnag/],
  ['Datadog', /^Datadog/], ['New Relic', /^(NewRelic|NRMA)/], ['Instabug', /^Instabug/], ['Mixpanel', /^Mixpanel/], ['Amplitude', /^Amplitude/],
  ['Segment', /^(SEG|Segment)/], ['AppsFlyer', /^AppsFlyer/], ['Adjust', /^(ADJ|Adjust)/], ['Branch', /^(BNC|Branch)/], ['OneSignal', /^OneSignal/],
  ['Braze', /^(ABK|Appboy|Braze)/], ['Airship', /^(UA[A-Z]|AirshipKit|Airship)/], ['Intercom', /^Intercom/], ['Zendesk', /^(ZD|Zendesk)/],
  ['Stripe', /^(STP|Stripe)/], ['Braintree', /^(BT[A-Z]|Braintree)/], ['PayPal', /^PayPal/], ['RevenueCat', /^(RC[A-Z]|RevenueCat)/],
  ['Lottie', /^Lottie/], ['SnapKit', /^SnapKit/], ['RxSwift', /^Rx(Swift|Cocoa|Relay)/], ['PromiseKit', /^PromiseKit/], ['Moya', /^Moya/],
  ['Apollo GraphQL', /^Apollo/], ['Socket.IO', /^SocketIO/], ['Starscream', /^Starscream/], ['SwiftyJSON', /^SwiftyJSON/],
  ['Realm Swift', /^RealmSwift/], ['Charts', /^(DGCharts|Charts)$/], ['IQKeyboardManager', /^IQKeyboardManager/], ['ZIPFoundation', /^ZIPFoundation/],
  ['SwiftSoup', /^SwiftSoup/], ['Sparkle', /^SU[A-Z].*Updater|^Sparkle/], ['Unity Ads', /^UnityAds/], ['AppLovin', /^(ALSdk|AppLovin)/],
  ['ironSource', /^(IronSource|ISN)/], ['Vungle', /^Vungle/], ['Chartboost', /^Chartboost/], ['Pendo', /^Pendo/], ['Smartlook', /^Smartlook/],
  ['Microsoft App Center', /^(MSAC|AppCenter)/], ['Auth0', /^Auth0/], ['Okta', /^Okta/], ['MSAL (Microsoft login)', /^MSAL/], ['Agora', /^Agora/],
  ['Twilio', /^Twilio/], ['Mapbox', /^(MGL|Mapbox)/], ['Google Maps', /^(GMS|GoogleMaps)/], ['OpenSSL', /^(ssl|crypto|openssl)(\.|$)/i],
];

const SECRETS = [
  ['AWS access key', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['Firebase database', /\b[a-z0-9-]+\.firebaseio\.com\b/g],
  ['Stripe live key', /\b(sk|rk|pk)_live_[0-9a-zA-Z]{20,}\b/g],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g],
  ['Private key', /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g],
  ['OpenAI key', /\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b/g],
  ['Anthropic key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g],
  ['Twilio account', /\bAC[0-9a-f]{32}\b/g],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
];

const mask = (s) => (s.length <= 12 ? s : `${s.slice(0, 8)}…${s.slice(-4)}`);

function scanText(text, where, found, urls) {
  for (const [kind, re] of SECRETS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const key = kind + m[0];
      if (!found.has(key) && found.size < 200) found.set(key, { kind, value: m[0], where });
    }
  }
  if (urls) for (const m of text.matchAll(/\b(https?|wss?):\/\/[A-Za-z0-9.-]+(:\d+)?(\/[\x21-\x7e]*)?/g)) if (urls.size < 5000) urls.add(m[0].replace(/[)"'>\]\\,;]+$/, ''));
}

/** Printable ASCII runs of a binary (for URL / secret scanning). */
function binaryText(buf) {
  const parts = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = buf[i];
    const printable = c >= 0x20 && c < 0x7f;
    if (printable && start < 0) start = i;
    else if (!printable && start >= 0) { if (i - start >= 8) parts.push(buf.toString('latin1', start, i)); start = -1; }
  }
  return parts.join('\n');
}

// ---------------------------------------------------------------- one Mach-O image

/**
 * Class-dump and Swift interface of one Mach-O image into outDir/headers/<image> and outDir/swift/<image>.
 * Returns { macho, objc: summary, swift: summary, methods } (methods = implementation addresses with names).
 */
async function dumpImage(buf, image, outDir, log = () => {}) {
  const m = MachO.open(buf);
  const res = { macho: m, objc: null, swift: null, methods: [] };
  if (m.encrypted) return res;
  let sw = null;
  try { sw = swift.swiftInterface(m, image); } catch (e) { log(`${image}: Swift metadata could not be read (${e.message})`, { warn: true }); }
  try {
    const cd = objc.classDump(m, image, { swiftFields: sw?.fieldsByType });
    if (Object.keys(cd.files).length) {
      const dir = path.join(outDir, 'headers', safe(image));
      await fsp.mkdir(dir, { recursive: true });
      for (const [name, text] of Object.entries(cd.files)) await fsp.writeFile(path.join(dir, name), text);
      res.objc = cd.summary;
      res.methods = cd.methods;
    }
  } catch (e) { log(`${image}: Objective-C metadata could not be read (${e.message})`, { warn: true }); }
  try {
    if (sw) {
      const dir = path.join(outDir, 'swift', safe(image));
      await fsp.mkdir(dir, { recursive: true });
      for (const [name, text] of Object.entries(sw.files)) await fsp.writeFile(path.join(dir, name), text);
      res.swift = { module: sw.module, modules: sw.modules, ...sw.counts };
    }
  } catch (e) { log(`${image}: Swift metadata could not be read (${e.message})`, { warn: true }); }
  // Functions identified by the Swift metadata: type metadata accessors and class vtable entries.
  try {
    const known = new Set(res.methods.map((x) => x.addr));
    for (const f of swift.swiftFunctions(m)) if (!known.has(f.addr)) { res.methods.push(f); known.add(f.addr); }
  } catch { /* no Swift metadata */ }
  return res;
}

/** Lines "address<TAB>class<TAB>name" for the Ghidra export script (see applyNames there). */
function namesFile(methods) {
  return methods.map((x) => `${x.addr.toString(16)}\t${x.cls.replace(/\t/g, ' ')}\t${x.kind === '+' ? '+' : ''}${x.sel}`).join('\n') + '\n';
}

// ---------------------------------------------------------------- main

/**
 * opts.native(binary, outDir, namesFile) runs Ghidra (core.js); opts.dotnet(dll, outDir) runs ILSpy;
 * opts.iosCode === false skips Ghidra.
 */
async function decompileIpa(_tools, file, outDir, log, opts = {}) {
  const { signal } = opts;
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'dropdecomp-ipa-'));
  try {
    log('Unpacking the app…');
    await extract(file, path.join(tmp, 'x'));
    const all = await walk(path.join(tmp, 'x'));
    const infoEntry = all.find((f) => /^(Payload\/)?[^/]+\.app\/Info\.plist$/i.test(f.rel));
    if (!infoEntry) throw new Error('This archive has no Payload/<App>.app: it is not an iOS app.');
    const appRoot = infoEntry.rel.slice(0, -'Info.plist'.length); // "Payload/X.app/"
    const files = all.filter((f) => f.rel.startsWith(appRoot)).map((f) => ({ abs: f.abs, rel: f.rel.slice(appRoot.length) }));
    const info = (await readPlist(infoEntry.abs)) || {};
    const appName = info.CFBundleDisplayName || info.CFBundleName || path.basename(appRoot, '.app/');
    log(`${appName} ${info.CFBundleShortVersionString || ''} (${info.CFBundleIdentifier || '?'}): ${files.length.toLocaleString('en')} files`);

    // ---- 1. bundle files, decoded
    let decoded = 0;
    let nibs = 0;
    const secrets = new Map();
    for (const f of files) {
      if (signal?.aborted) throw Object.assign(new Error('Cancelled'), { cancelled: true });
      const dest = path.join(outDir, 'app', ...f.rel.split('/'));
      await fsp.mkdir(path.dirname(dest), { recursive: true });
      const h = await head(f.abs);
      try {
        if (h.toString('latin1', 0, 8) === 'bplist00') {
          const v = plist.parse(await fsp.readFile(f.abs));
          const asStrings = /\.strings$/i.test(f.rel) && v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).every((x) => typeof x === 'string');
          await fsp.writeFile(dest, asStrings ? plist.toStrings(v) : plist.toXml(v));
          decoded++;
          continue;
        }
        if (/\.strings$/i.test(f.rel) && h[0] === 0xff && h[1] === 0xfe) {
          await fsp.writeFile(dest, (await fsp.readFile(f.abs)).subarray(2).toString('utf16le'));
          decoded++;
          continue;
        }
        if (h.toString('latin1', 0, 10) === 'NIBArchive') {
          await fsp.copyFile(f.abs, dest);
          const text = nibText(await fsp.readFile(f.abs), f.rel);
          if (text) { await fsp.writeFile(dest + '.txt', text); nibs++; }
          continue;
        }
      } catch { /* not decodable: copied as is below */ }
      await fsp.copyFile(f.abs, dest);
      if (/\.(json|plist|xml|js|txt|cfg|conf|html)$/i.test(f.rel) && (await fsp.stat(f.abs)).size < 4e6) {
        scanText(await fsp.readFile(f.abs, 'utf8').catch(() => ''), `app/${f.rel}`, secrets, null);
      }
    }
    log(`Bundle saved in app/: ${decoded} binary plists and .strings decoded${nibs ? `, ${nibs} interface files (nib) decoded` : ''}`);

    // ---- 2. Mach-O images: the app, its frameworks and its extensions
    const exe = info.CFBundleExecutable || path.basename(appRoot, '.app/');
    const imageFiles = [];
    for (const f of files) {
      const isMain = f.rel === exe;
      const fw = /^(Frameworks\/[^/]+\.framework)\/([^/]+)$/.exec(f.rel);
      const ext = /^(PlugIns|Extensions)\/([^/]+\.appex)\/([^/]+)$/.exec(f.rel);
      const dylib = /^Frameworks\/[^/]+\.dylib$/i.test(f.rel);
      if (!isMain && !(fw && fw[2] === path.basename(fw[1], '.framework')) && !ext && !dylib) continue;
      if (!isMachO(await head(f.abs, 8))) continue;
      const name = isMain ? exe : fw ? path.basename(fw[1]) : ext ? ext[2] : path.basename(f.rel);
      imageFiles.push({ ...f, name, kind: isMain ? 'app' : fw || dylib ? 'framework' : 'extension' });
    }
    const images = [];
    let main = null;
    for (const img of imageFiles) {
      if (signal?.aborted) throw Object.assign(new Error('Cancelled'), { cancelled: true });
      const buf = await fsp.readFile(img.abs);
      let r;
      try { r = await dumpImage(buf, img.name, outDir, log); } catch (e) { log(`${img.name}: ${e.message}`, { warn: true }); continue; }
      const entry = { ...img, ...r, size: buf.length };
      if (img.kind === 'framework') {
        const fwInfo = await readPlist(path.join(path.dirname(img.abs), 'Info.plist'));
        entry.version = fwInfo?.CFBundleShortVersionString;
        entry.bundleId = fwInfo?.CFBundleIdentifier;
      }
      if (img.kind === 'extension') {
        const exInfo = await readPlist(path.join(path.dirname(img.abs), 'Info.plist'));
        entry.bundleId = exInfo?.CFBundleIdentifier;
        entry.point = exInfo?.NSExtension?.NSExtensionPointIdentifier || exInfo?.EXAppExtensionAttributes?.EXExtensionPointIdentifier;
      }
      if (img.kind === 'app') {
        main = entry;
        const urls = new Set();
        scanText(binaryText(buf), `${img.name} (executable)`, secrets, urls);
        entry.urls = [...urls].sort();
      }
      images.push(entry);
      const what = [r.objc && `${r.objc.classes} ObjC classes`, r.swift && `${r.swift.total} Swift types`].filter(Boolean).join(', ');
      log(`${img.name}: ${r.macho.encrypted ? 'ENCRYPTED (FairPlay)' : what || 'no Objective-C/Swift metadata'}`, { quiet: img.kind !== 'app' });
    }
    if (!main) throw new Error(`The app executable "${exe}" was not found in the bundle.`);

    // ---- 3. info/
    const infoDir = path.join(outDir, 'info');
    await fsp.mkdir(infoDir, { recursive: true });
    await fsp.writeFile(path.join(infoDir, 'Info.plist'), plist.toXml(info));
    const sig = main.macho.signature() || {};
    let entitlements = null;
    if (sig.entitlements) {
      await fsp.writeFile(path.join(infoDir, 'entitlements.plist'), sig.entitlements);
      try { entitlements = plist.parseXml(sig.entitlements); } catch { /* malformed */ }
    }
    let profile = null;
    const prov = files.find((f) => f.rel === 'embedded.mobileprovision');
    if (prov) {
      const xml = plist.provisioningPlist(await fsp.readFile(prov.abs));
      if (xml) {
        try {
          profile = plist.parseXml(xml);
          const clean = { ...profile, DeveloperCertificates: `(${(profile.DeveloperCertificates || []).length} certificates)`, 'DER-Encoded-Profile': undefined };
          delete clean['DER-Encoded-Profile'];
          await fsp.writeFile(path.join(infoDir, 'provisioning-profile.plist'), plist.toXml(clean));
          entitlements ||= profile.Entitlements;
        } catch { /* malformed */ }
      }
    }
    await fsp.writeFile(path.join(infoDir, 'linked-libraries.txt'), main.macho.dylibs.map((d) => `${d.name}  (${d.kind}, ${d.current})`).join('\n') + '\n');
    if (main.urls?.length) await fsp.writeFile(path.join(infoDir, 'urls.txt'), main.urls.join('\n') + '\n');
    if (secrets.size) {
      await fsp.writeFile(path.join(infoDir, 'possible-secrets.txt'),
        [...secrets.values()].map((s) => `${s.kind}\t${s.value}\t${s.where}`).join('\n') + '\n');
    }

    // ---- 4. cross-platform frameworks
    const fw = await analyzeFrameworks(files, outDir, { log, signal, dotnet: opts.dotnet });

    // ---- 5. the app's code with Ghidra
    let codeNote = null;
    if (main.macho.encrypted) {
      codeNote = 'skipped: the executable is encrypted';
    } else if (opts.iosCode === false) {
      codeNote = 'turned off in Settings';
    } else if (opts.native) {
      const names = path.join(tmp, 'names.txt');
      const methods = images.filter((i) => i === main).flatMap((i) => i.methods);
      await fsp.writeFile(names, namesFile(methods));
      log(`Decompiling ${exe} with Ghidra (${fmtBytes(main.size)}; big apps take a while)…`);
      try {
        await opts.native(main.abs, path.join(outDir, 'code'), methods.length ? names : null);
        codeNote = 'done';
      } catch (e) {
        if (e.cancelled) throw e;
        codeNote = `failed: ${e.message.split('\n')[0]}`;
        log(`Ghidra could not decompile ${exe}: ${e.message.split('\n')[0]}`, { warn: true });
      }
    }

    // ---- 6. report
    await fsp.writeFile(path.join(outDir, 'README.md'), report({ info, appName, main, images, entitlements, profile, sig, fw, secrets, codeNote, files, decoded, nibs }));
    const enc = images.filter((i) => i.macho.encrypted).length;
    if (enc) log(`${enc} binar${enc === 1 ? 'y is' : 'ies are'} FairPlay-encrypted: only metadata and resources could be extracted. See README.md.`, { warn: true });
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

// ---------------------------------------------------------------- report

function report({ info, appName, main, images, entitlements, profile, sig, fw, secrets, codeNote, files, decoded, nibs }) {
  const m = main.macho;
  const L = [];
  const row = (k, v) => v !== undefined && v !== null && v !== '' && L.push(`| ${k} | ${esc(v)} |`);
  L.push(`# ${appName}`, '');
  if (m.encrypted) {
    L.push('> **This app is encrypted (FairPlay DRM, App Store build).** Its code can\'t be read until it is decrypted on a device that the app was installed on (for example with a jailbroken device and a decryption tool), so headers, Swift interfaces and pseudo-C are missing. Resources, Info.plist, entitlements and the report below are complete.', '');
  }
  const families = (info.UIDeviceFamily || []).map((x) => ({ 1: 'iPhone', 2: 'iPad', 3: 'Apple TV', 4: 'Apple Watch', 6: 'Mac (Catalyst)', 7: 'Vision Pro' }[x] || x)).join(', ');
  const langs = [main.swift && `Swift (${main.swift.classes + main.swift.structs + main.swift.enums} types in module ${main.swift.module})`,
    main.objc && main.objc.classes - main.objc.swiftClasses > 0 && `Objective-C (${main.objc.classes - main.objc.swiftClasses} classes)`].filter(Boolean).join(' + ');
  L.push('| | |', '|---|---|');
  row('Bundle ID', info.CFBundleIdentifier);
  row('Version', `${info.CFBundleShortVersionString || '?'} (build ${info.CFBundleVersion || '?'})`);
  row('Minimum iOS', info.MinimumOSVersion || m.build?.minos);
  row('Devices', families);
  row('Built with', [info.DTXcode && `Xcode ${String(info.DTXcode).replace(/^(\d+)(\d)(\d)$/, '$1.$2.$3').replace(/\.0$/, '')}`, info.DTSDKName && `SDK ${info.DTSDKName}`, info.BuildMachineOSBuild && `on macOS build ${info.BuildMachineOSBuild}`].filter(Boolean).join(', '));
  row('Executable', `${main.name}: ${m.slices?.join(', ') || m.cpu}, ${fmtBytes(main.size)}${m.encrypted ? ', **encrypted**' : ''}`);
  row('Languages', langs);
  row('Signed by', [sig.teamId && `team ${sig.teamId}`, sig.identifier && `as ${sig.identifier}`].filter(Boolean).join(' '));
  if (profile) {
    const type = profile.ProvisionsAllDevices ? 'Enterprise (in-house)' : profile.ProvisionedDevices ? (profile.Entitlements?.['get-task-allow'] ? 'Development' : 'Ad Hoc') : 'App Store';
    row('Provisioning', `${type}: “${profile.Name}”, ${profile.TeamName || ''} (${(profile.TeamIdentifier || []).join(', ')}), expires ${profile.ExpirationDate instanceof Date ? profile.ExpirationDate.toISOString().slice(0, 10) : '?'}${profile.ProvisionedDevices ? `, ${profile.ProvisionedDevices.length} devices` : ''}`);
  }
  row('Bundle', `${files.length.toLocaleString('en')} files, ${images.filter((i) => i.kind === 'framework').length} embedded frameworks, ${images.filter((i) => i.kind === 'extension').length} extensions`);
  if (fw.detected.length) row('Cross-platform', fw.detected.join(', '));
  L.push('');

  L.push('## In this folder', '');
  const own = main.swift ? `\`swift/${main.name}/${main.swift.module}.swift\`` : null;
  if (main.objc) L.push(`- \`headers/${main.name}/\`: Objective-C headers of ${main.objc.classes} classes${main.objc.swiftClasses ? ` (${main.objc.swiftClasses} of them Swift classes visible to Objective-C)` : ''}, ${main.objc.categories} categories and ${main.objc.protocols} protocols, with every method's implementation address. \`_CLASSES.txt\` lists the class hierarchy.`);
  if (main.swift) L.push(`- \`swift/${main.name}/\`: Swift interfaces, one file per module. The app's own code is ${own}: ${main.swift.classes} classes, ${main.swift.structs} structs, ${main.swift.enums} enums, ${main.swift.protocols} protocols with their stored properties, cases and conformances.${main.swift.modules.length ? ` Swift packages compiled into the app: ${main.swift.modules.join(', ')}.` : ''}`);
  L.push(`- \`code/\`: ${codeNote === 'done' ? `pseudo-C of every function of ${main.name} (Ghidra). Objective-C methods are named \`Class::selector\`, matching the IMP addresses in the headers.` : `Ghidra pseudo-C: ${codeNote || 'not run'}.`}`);
  L.push(`- \`app/\`: every file of the bundle. ${decoded} binary plists and \`.strings\` were converted to readable text${nibs ? `, and ${nibs} compiled interface files have a decoded \`.nib.txt\` next to them` : ''}.`);
  L.push('- `info/`: Info.plist, entitlements, provisioning profile, linked libraries' + (main.urls?.length ? ', URLs found in the executable' : '') + (secrets.size ? ', **possible secrets**' : '') + '.');
  const frameworksWithCode = images.filter((i) => i.kind !== 'app' && (i.objc || i.swift));
  if (frameworksWithCode.length) L.push(`- Frameworks and extensions have their own \`headers/<name>/\` and \`swift/<name>/\` folders (${frameworksWithCode.length}).`);
  L.push('');
  if (fw.notes.length) L.push('## Cross-platform code', '', ...fw.notes, '');

  // Permissions
  const perms = Object.keys(info).filter((k) => /UsageDescription$/.test(k));
  if (perms.length) {
    L.push('## Permissions the app can ask for', '', '| Permission | Reason shown to the user |', '|---|---|');
    for (const k of perms.sort()) L.push(`| ${PERMISSIONS[k] || k.replace(/^NS|UsageDescription$/g, '').replace(/([a-z])([A-Z])/g, '$1 $2')} | ${esc(info[k])} |`);
    L.push('');
  }

  // Capabilities
  if (entitlements) {
    L.push('## Capabilities (entitlements)', '');
    const e = entitlements;
    const list = (v) => (Array.isArray(v) ? v.join(', ') : String(v));
    if (e['get-task-allow']) L.push('- ⚠ **get-task-allow**: the app can be attached to by a debugger (development signing).');
    if (e['aps-environment']) L.push(`- Push notifications (${e['aps-environment']})`);
    if (e['com.apple.developer.associated-domains']) L.push(`- Associated domains (universal links, password autofill): ${list(e['com.apple.developer.associated-domains'])}`);
    if (e['com.apple.security.application-groups']) L.push(`- App groups (data shared with other apps/extensions): ${list(e['com.apple.security.application-groups'])}`);
    if (e['keychain-access-groups']) L.push(`- Keychain groups: ${list(e['keychain-access-groups'])}`);
    if (e['com.apple.developer.icloud-services']) L.push(`- iCloud: ${list(e['com.apple.developer.icloud-services'])}${e['com.apple.developer.icloud-container-identifiers'] ? ` (${list(e['com.apple.developer.icloud-container-identifiers'])})` : ''}`);
    const other = Object.keys(e).filter((k) => !['get-task-allow', 'aps-environment', 'com.apple.developer.associated-domains', 'com.apple.security.application-groups', 'keychain-access-groups', 'com.apple.developer.icloud-services', 'com.apple.developer.icloud-container-identifiers', 'application-identifier', 'com.apple.developer.team-identifier'].includes(k));
    if (other.length) L.push(`- Other: ${other.map((k) => `\`${k}\``).join(', ')}`);
    L.push('');
  }

  // Entry points and network
  const schemes = (info.CFBundleURLTypes || []).flatMap((t) => t.CFBundleURLSchemes || []);
  const queried = info.LSApplicationQueriesSchemes || [];
  const ats = info.NSAppTransportSecurity || {};
  const atsNotes = [];
  if (ats.NSAllowsArbitraryLoads) atsNotes.push('⚠ **NSAllowsArbitraryLoads**: plain HTTP and invalid TLS are allowed for every host');
  if (ats.NSAllowsArbitraryLoadsInWebContent) atsNotes.push('plain HTTP allowed in web views');
  if (ats.NSAllowsLocalNetworking) atsNotes.push('plain HTTP allowed on the local network');
  for (const [d, cfg] of Object.entries(ats.NSExceptionDomains || {})) {
    if (cfg.NSExceptionAllowsInsecureHTTPLoads || cfg.NSTemporaryExceptionAllowsInsecureHTTPLoads) atsNotes.push(`plain HTTP allowed for \`${d}\`${cfg.NSIncludesSubdomains ? ' and subdomains' : ''}`);
  }
  if (schemes.length || queried.length || atsNotes.length || main.urls?.length || info.UIBackgroundModes) {
    L.push('## Entry points and network', '');
    if (schemes.length) L.push(`- **URL schemes** (deep links into the app): ${schemes.map((s) => `\`${s}://\``).join(', ')}`);
    if (queried.length) L.push(`- Other apps it checks for: ${queried.map((s) => `\`${s}\``).join(', ')}`);
    if (info.UIBackgroundModes) L.push(`- Background modes: ${[].concat(info.UIBackgroundModes).join(', ')}`);
    L.push(`- App Transport Security: ${atsNotes.length ? atsNotes.join('; ') : 'default (HTTPS required)'}`);
    if (main.urls?.length) {
      const hosts = {};
      for (const u of main.urls) { try { const h = new URL(u).host; hosts[h] = (hosts[h] || 0) + 1; } catch { /* partial */ } }
      const top = Object.entries(hosts).sort((a, b) => b[1] - a[1]).slice(0, 25).map(([h]) => `\`${h}\``);
      L.push(`- ${main.urls.length} URLs in the executable (\`info/urls.txt\`), hosts: ${top.join(', ')}`);
    }
    L.push('');
  }
  if (secrets.size) {
    L.push('## Possible secrets', '', 'Strings that look like credentials (check them: some are public by design, like Firebase config or publishable keys). Full values in `info/possible-secrets.txt`.', '');
    for (const s of [...secrets.values()].slice(0, 40)) L.push(`- ${s.kind}: \`${mask(s.value)}\` in ${s.where}`);
    L.push('');
  }

  // SDKs
  const names = [
    ...images.map((i) => i.name.replace(/\.(framework|appex|dylib)$/, '')),
    ...(main.swift?.modules || []),
    ...((main.objc && objcClassNames(main)) || []),
    ...m.dylibs.filter((d) => !/^\/(System|usr)\//.test(d.name)).map((d) => path.basename(d.name)), // not Apple's own (e.g. Swift Charts)
  ];
  const sdks = SDKS.filter(([, re]) => names.some((n) => re.test(n))).map(([n]) => n);
  if (sdks.length) L.push('## Third-party SDKs', '', sdks.join(' · '), '');

  // Frameworks and extensions
  const fws = images.filter((i) => i.kind === 'framework');
  if (fws.length) {
    L.push('## Embedded frameworks', '', '| Framework | Version | Code |', '|---|---|---|');
    for (const f of fws) L.push(`| ${f.name} | ${f.version || ''} | ${f.macho.encrypted ? 'encrypted' : [f.objc && `${f.objc.classes} ObjC classes`, f.swift && `${f.swift.total} Swift types`].filter(Boolean).join(', ') || 'C / C++'} |`);
    L.push('');
  }
  const exts = images.filter((i) => i.kind === 'extension');
  if (exts.length) {
    L.push('## App extensions', '');
    for (const x of exts) L.push(`- ${x.name}: ${x.point || 'extension'}${x.bundleId ? ` (${x.bundleId})` : ''}`);
    L.push('');
  }
  const system = m.dylibs.filter((d) => d.name.startsWith('/System/')).map((d) => path.basename(d.name)).sort();
  if (system.length) L.push('## Apple frameworks used', '', system.join(', '), '');

  L.push('## How faithful is this?', '',
    '- **Exact**: class, method, property, ivar, protocol and Swift type names; Swift stored properties and enum cases with their types; method type signatures; strings, plists, entitlements and resources.',
    '- **Reconstructed**: method bodies. Swift and Objective-C compile to machine code, so `code/` holds Ghidra\'s C-like reading of it; local variable names and comments are gone.',
    '- Open the **AI assistant** to rebuild Swift/Objective-C source from the headers, interfaces and pseudo-C together.', '');
  return L.join('\n');
}

function objcClassNames(main) {
  try { return objc.dump(main.macho).classes.map((c) => c.name); } catch { return []; }
}

module.exports = { decompileIpa, isIpa, dumpImage, namesFile };
