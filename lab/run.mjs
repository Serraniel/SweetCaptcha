// The attacker lab. It runs the real binary and real Chromium against each attacker
// tier, and fails when an expected outcome changes. It is a regression suite for
// the detection rules and the source of the dated figures in docs/LAB_RESULTS.md.
//
// A headless, CDP-driven browser cannot stand in for a real person, so passing here
// says nothing about false positives on people. That needs testing on real devices.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const out = join(here, 'out');
mkdirSync(out, { recursive: true });
const BASE = 'http://localhost:18080';
const TLS_BASE = 'https://localhost:18443';
const executablePath = process.env.LAB_CHROMIUM || undefined;
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // The lab's own self-signed certificate.
process.removeAllListeners('warning');

const secrets = {
  lab_standard: 'lab-standard-secret-value',
  lab_strict: 'lab-strict-secret-value',
  lab_stepup: 'lab-stepup-secret-value',
  lab_puzzle: 'lab-puzzle-secret-value',
};

function buildAndStart() {
  if (!existsSync(join(out, 'cert.pem'))) {
    const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', join(out, 'key.pem'), '-out', join(out, 'cert.pem'), '-days', '30', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
    if (r.status !== 0) throw new Error('openssl failed');
  }
  const b = spawnSync('go', ['build', '-o', join(out, 'sweetcaptcha'), './cmd/sweetcaptcha'], { cwd: root, stdio: 'inherit' });
  if (b.status !== 0) throw new Error('go build failed');
  const proc = spawn(join(out, 'sweetcaptcha'), ['serve', '--config', 'lab/config.yaml'], { cwd: root, stdio: 'ignore' });
  return proc;
}

async function waitReady() {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${BASE}/healthz`)).ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
}

const CHROME_UA = (major) => `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;

async function verify(token, key, base = BASE) {
  const r = await fetch(`${base}/v1/siteverify`, {
    method: 'POST',
    body: new URLSearchParams({ secret: secrets[key], response: token }),
  });
  return r.json();
}

// Reads the outcome the way a user would see it, then asks the server for reasons.
async function outcome(page, key, timeout = 45000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (page.url().includes('/demo/verify')) {
      const data = JSON.parse(await page.locator('#result').textContent());
      return { result: data.success ? 'pass' : 'rejected', via: data.via, score: data.score, reasons: data.reasons ?? [] };
    }
    for (const f of page.frames()) {
      if (!f.url().includes('/v1/frame')) continue;
      if (await f.locator('.modal h1').count().catch(() => 0)) return { result: 'puzzle', reasons: [] };
      const mark = await f.locator('.mark.bad').count().catch(() => 0);
      if (mark) return { result: 'deny', reasons: [] };
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { result: 'timeout', reasons: [] };
}

function bezierPath(x0, y0, x1, y1, steps) {
  const cx = (x0 + x1) / 2 + (Math.random() - 0.5) * 200;
  const cy = (y0 + y1) / 2 + (Math.random() - 0.5) * 200;
  const pts = [];
  for (let i = 1; i <= steps; i++) {
    const s = i / steps;
    const t = s * s * (3 - 2 * s);
    pts.push([
      (1 - t) ** 2 * x0 + 2 * (1 - t) * t * cx + t ** 2 * x1 + Math.random() * 1.5,
      (1 - t) ** 2 * y0 + 2 * (1 - t) * t * cy + t ** 2 * y1 + Math.random() * 1.5,
    ]);
  }
  return pts;
}

async function moveLikePerson(page, from, to) {
  for (const [x, y] of bezierPath(from[0], from[1], to[0], to[1], 28 + Math.floor(Math.random() * 18))) {
    await page.mouse.move(x, y);
    await page.waitForTimeout(6 + Math.random() * 18);
  }
}

async function centre(locator) {
  const b = await locator.boundingBox();
  return [b.x + b.width / 2, b.y + b.height / 2];
}

async function agentStyleForm(page) {
  await page.waitForTimeout(600);
  await page.locator('#name').fill('Automated Agent');
  await page.locator('#send').click();
}

async function humanStyleForm(page) {
  await page.waitForTimeout(800);
  const field = await centre(page.locator('#name'));
  await moveLikePerson(page, [40, 40], field);
  await page.mouse.down();
  await page.mouse.up();
  await page.keyboard.type('Lab Person', { delay: 90 + Math.random() * 60 });
  await page.waitForTimeout(250);
  await moveLikePerson(page, field, await centre(page.locator('#send')));
  await page.waitForTimeout(150);
  await page.mouse.down();
  await page.mouse.up();
}

async function withBrowser(opts, fn) {
  // Full Chromium in new headless mode. Playwright's default headless shell is a
  // different, far more detectable browser.
  const browser = await chromium.launch({ headless: true, executablePath, channel: executablePath ? undefined : 'chromium', ...opts });
  try {
    return await fn(browser);
  } finally {
    await browser.close();
  }
}

const results = [];

async function scenario(name, tier, expect, fn) {
  const started = Date.now();
  let res;
  try {
    res = await fn();
  } catch (e) {
    res = { result: 'error', reasons: [], error: String(e.message ?? e).split('\n')[0] };
  }
  const allowed = Array.isArray(expect) ? expect : [expect];
  const ok = allowed.includes(res.result);
  results.push({ name, tier, expected: allowed.join(' or '), ok, ms: Date.now() - started, ...res });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${res.result}${res.via ? ` via ${res.via}` : ''}${res.score !== undefined ? ` score ${res.score}` : ''}${res.reasons?.length ? ` [${res.reasons.join(',')}]` : ''}${res.error ? ` (${res.error})` : ''}`);
}

function solveSha256(pow) {
  const salt = Buffer.from(pow.salt, 'base64');
  const nonces = [];
  for (let i = 0; i < pow.count; i++) {
    const buf = Buffer.alloc(24);
    salt.copy(buf);
    buf.writeUInt32BE(i, 16);
    for (let n = 0; ; n++) {
      buf.writeUInt32BE(n, 20);
      const h = createHash('sha256').update(buf).digest();
      if (h.readUInt32BE(0) >>> (32 - pow.bits) === 0) {
        nonces.push(n);
        break;
      }
    }
  }
  return nonces;
}

const browserHeaders = (ua) => ({
  'Content-Type': 'application/json',
  'User-Agent': ua,
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
});

async function httpBot(ua, makeSignals, base = BASE, key = 'lab_standard') {
  const headers = browserHeaders(ua);
  const ch = await (await fetch(`${base}/v1/challenge`, {
    method: 'POST', headers, body: JSON.stringify({ sitekey: key, hostname: 'localhost' }),
  })).json();
  const body = { c: ch.c, nonces: solveSha256(ch.pow), signals: makeSignals?.(ch.collect?.nonce) };
  const res = await (await fetch(`${base}/v1/submit`, { method: 'POST', headers, body: JSON.stringify(body) })).json();
  if (res.status === 'pass') {
    const v = await verify(res.token, key, base);
    return { result: v.success ? 'pass' : 'rejected', via: v.via, score: v.score, reasons: v.reasons ?? [] };
  }
  return { result: res.status, reasons: [] };
}

function keyed(nonce, value) {
  return createHash('sha256').update(`${nonce}:${value}`).digest('hex').slice(0, 16);
}

function forgedSignals(ua, major) {
  return (nonce) => {
    const h = { ua: keyed(nonce, ua), platform: 'x', langs: 'x', cores: 'x', tz: 'x' };
    return {
      v: 1, secure: true, auto: { webdriver: false, artefacts: [] }, tamper: [], hash: h, worker: h, iframe: h,
      engine: { family: 'v8', evalLen: 33 }, uach: { chromiumMajor: major, mobile: false, platform: 'Linux' },
      device: { platform: 'Linux x86_64', touch: 0, pointer: 'fine', langs: 2, gpu: 'intel', gpuApi: 'opengl', canvasStable: true },
      trap: false, cdp: false,
      beh: { mode: 'mouse', moves: 60, clicks: 1, noApproach: 0, straightness: 0.8, speedCv: 0.7, dirChanges: 5, keys: 8, keyMedianMs: 120, keyCv: 0.4 },
    };
  };
}

// Records reads of device properties and storage in every frame. Installed in the
// page's own world, so it sees exactly what scripts on the page do.
const INSTRUMENT = () => {
  const reads = [];
  window.__labReads = reads;
  // Only count calls made by this service's scripts. Playwright's own injected
  // helpers run in the same world and install input listeners of their own.
  const ours = () => /\/v1\/(assets|api\.js)|\/(recaptcha\/api|1\/api|turnstile\/v0\/api)\.js/.test(new Error().stack ?? '');
  const note = (entry) => { if (ours()) reads.push(entry); };
  const watch = (proto, label, names) => {
    for (const name of names) {
      const d = proto && Object.getOwnPropertyDescriptor(proto, name);
      if (!d) continue;
      const wrap = d.get ? { get() { note(`${label}.${name}`); return d.get.call(this); } }
        : typeof d.value === 'function' ? { value(...a) { note(`${label}.${name}`); return d.value.apply(this, a); } } : null;
      if (wrap) Object.defineProperty(proto, name, { ...d, ...wrap });
    }
  };
  watch(Navigator.prototype, 'navigator', ['userAgent', 'platform', 'languages', 'language', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints', 'webdriver', 'plugins', 'vendor', 'userAgentData', 'permissions', 'connection', 'getBattery', 'mediaDevices']);
  watch(Screen.prototype, 'screen', ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth']);
  watch(HTMLCanvasElement.prototype, 'canvas', ['getContext', 'toDataURL', 'toBlob']);
  watch(Document.prototype, 'document', ['cookie']);
  watch(Storage.prototype, 'storage', ['getItem', 'setItem']);
  watch(Window.prototype ?? {}, 'window', ['localStorage', 'sessionStorage', 'indexedDB']);
  watch(Intl.DateTimeFormat.prototype, 'intl', ['resolvedOptions']);
  watch(window, 'window', ['matchMedia', 'outerWidth', 'outerHeight', 'localStorage', 'sessionStorage', 'indexedDB']);
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, ...rest) {
    if (/^(pointer|mouse|key|touch|wheel|scroll|device|paste|input)/.test(type)) note(`listen.${type}`);
    return add.call(this, type, ...rest);
  };
};

// Runs the audit against a site. It is also pointed at a standard site, where it must
// find reads: otherwise a clean strict result would prove nothing.
async function audit(key) {
  return withBrowser({}, async (browser) => {
    const ctx = await browser.newContext();
    await ctx.addInitScript(INSTRUMENT);
    const page = await ctx.newPage();
    const requests = [];
    page.on('request', (r) => requests.push(r));
    await page.goto(`${BASE}/demo/?provider=native&k=${key}`);
    await page.locator('#send').click();
    await outcome(page, key);
    // Reads are gathered in a fresh load, since the form navigation discards them.
    const page2 = await ctx.newPage();
    const requests2 = [];
    page2.on('request', (r) => requests2.push(r));
    await page2.goto(`${BASE}/demo/?provider=native&k=${key}`);
    await page2.waitForTimeout(2500);
    const frame = page2.frames().find((f) => f.url().includes('/v1/frame'));
    const findings = [];
    for (const f of [page2.mainFrame(), frame]) {
      findings.push(...(await f.evaluate(() => window.__labReads ?? [])));
    }
    if (key === 'lab_strict' && !(await page2.locator('#sc-response').inputValue())) findings.push('no token');
    const urls = [...requests, ...requests2].map((r) => new URL(r.url()));
    for (const u of urls) {
      if (u.origin !== BASE && u.protocol !== 'data:') findings.push(`third-party request: ${u.origin}`);
      if (/signals/.test(u.pathname)) findings.push(`collector loaded: ${u.pathname}`);
    }
    const submits = requests2.filter((r) => r.url().endsWith('/v1/submit'));
    for (const s of submits) {
      const keys = Object.keys(JSON.parse(s.postData()));
      if (keys.some((k) => k !== 'c' && k !== 'nonces')) findings.push(`extra submit field: ${keys}`);
    }
    if ((await ctx.cookies()).length) findings.push('cookies set');
    const stored = await frame.evaluate(() => {
      // Storage is read here with the instrumented getters bypassed by length only.
      return [localStorage.length, sessionStorage.length];
    }).catch(() => [0, 0]);
    if (stored[0] || stored[1]) findings.push('storage used');
    return { result: findings.length ? 'violation' : 'clean', reasons: [...new Set(findings)] };
  });
}

async function providerForms() {
  return withBrowser({}, async (browser) => {
    const reasons = [];
    for (const [provider, field] of [['native', 'sc-response'], ['recaptcha', 'g-recaptcha-response'], ['hcaptcha', 'h-captcha-response'], ['turnstile', 'cf-turnstile-response']]) {
      const page = await browser.newPage();
      await page.goto(`${BASE}/demo/?provider=${provider}&k=lab_strict`);
      await page.waitForFunction((n) => document.querySelector(`input[name="${n}"]`)?.value, field, { timeout: 15000 });
      await page.locator('#send').click();
      await page.waitForURL('**/demo/verify');
      const r = JSON.parse(await page.locator('#result').textContent());
      if (!r.success) reasons.push(`${provider}: ${JSON.stringify(r)}`);
      await page.close();
    }
    return { result: reasons.length ? 'failed' : 'pass', reasons };
  });
}

async function programmaticApis() {
  return withBrowser({}, async (browser) => {
    const reasons = [];
    const page = await browser.newPage();
    await page.goto(`${BASE}/demo/?provider=recaptcha&k=lab_strict`);
    await page.waitForFunction(() => window.grecaptcha);
    const v3 = await page.evaluate(() => new Promise((res, rej) => {
      grecaptcha.ready(() => grecaptcha.execute('lab_strict', { action: 'login' }).then(res, rej));
    }));
    const v = await verify(v3, 'lab_strict');
    if (!v.success || v.action !== 'login') reasons.push(`recaptcha v3: ${JSON.stringify(v)}`);
    await page.close();

    const p2 = await browser.newPage();
    await p2.goto(`${BASE}/demo/?provider=turnstile&k=lab_strict`);
    await p2.waitForFunction(() => window.turnstile);
    const ts = await p2.evaluate(() => new Promise((res, rej) => {
      const d = document.createElement('div');
      document.body.append(d);
      turnstile.render(d, { sitekey: 'lab_strict', action: 'signup', cData: 'abc', callback: res, 'error-callback': rej, 'response-field': false });
    }));
    const tv = await (await fetch(`${BASE}/turnstile/v0/siteverify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: secrets.lab_strict, response: ts }),
    })).json();
    if (!tv.success || tv.action !== 'signup' || tv.cdata !== 'abc') reasons.push(`turnstile: ${JSON.stringify(tv)}`);
    await p2.close();

    const p3 = await browser.newPage();
    await p3.goto(`${BASE}/demo/?provider=hcaptcha&k=lab_strict`);
    await p3.waitForFunction(() => window.hcaptcha);
    const h = await p3.evaluate(() => {
      const d = document.createElement('div');
      document.body.append(d);
      const id = hcaptcha.render(d, { sitekey: 'lab_strict', size: 'invisible' });
      return hcaptcha.execute(id, { async: true });
    });
    const hv = await verify(h.response, 'lab_strict');
    if (!hv.success) reasons.push(`hcaptcha: ${JSON.stringify(hv)}`);
    await p3.close();
    return { result: reasons.length ? 'failed' : 'pass', reasons };
  });
}


async function chromiumMajor() {
  return withBrowser({}, async (browser) => Number(browser.version().split('.')[0]));
}

async function run() {
  const major = await chromiumMajor();
  const ua = CHROME_UA(major);

  // Clients with no browser at all.
  await scenario('HTTP client naming itself', 'HTTP client', 'deny', () => httpBot('python-requests/2.32', null));
  await scenario('HTTP client claiming Chrome, no signals', 'HTTP client', 'puzzle', () => httpBot(ua, null));
  await scenario('HTTP client with a fully forged signal document', 'Forged protocol', 'pass', () => httpBot(ua, forgedSignals(ua, major)));
  await scenario('Same forgery, native TLS: handshake exposes it', 'Forged protocol', 'stepup', () => httpBot(ua, forgedSignals(ua, major), TLS_BASE));

  // Browser automation at increasing levels of effort.
  await scenario('Stock Playwright, headless', 'Stock automation', 'deny', () => withBrowser({}, async (b) => {
    const page = await b.newPage();
    await page.goto(`${BASE}/demo/?k=lab_standard`);
    await agentStyleForm(page);
    return outcome(page, 'lab_standard');
  }));
  await scenario('Automation flag hidden, UA spoofed, agent-style input', 'Default agent', 'puzzle', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await agentStyleForm(page);
      const r = await outcome(page, 'lab_standard');
      return r.via === 'stepup' ? { ...r, result: 'stepup-pass' } : r;
    }));
  await scenario('Script patches webdriver and languages', 'JS-patched stealth', ['puzzle', 'deny'], () => withBrowser({}, async (b) => {
    const ctx = await b.newContext({ userAgent: ua });
    await ctx.addInitScript(() => {
      Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => false, configurable: true });
      Object.defineProperty(Navigator.prototype, 'languages', { get: () => ['en-US', 'en'], configurable: true });
    });
    const page = await ctx.newPage();
    await page.goto(`${BASE}/demo/?k=lab_standard`);
    await agentStyleForm(page);
    const r = await outcome(page, 'lab_standard');
    return r.via === 'stepup' ? { ...r, result: 'stepup-pass' } : r;
  }));
  await scenario('Flag hidden, UA spoofed, humanised pointer and typing', 'Humanised browser', ['pass', 'stepup-pass'], () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_standard');
      return r.via === 'stepup' ? { ...r, result: 'stepup-pass' } : r;
    }));

  // Mechanics.
  await scenario('Strict mode: no device reads, storage, or third parties', 'Privacy', 'clean', () => audit('lab_strict'));
  await scenario('Audit control: the same audit does find reads on a standard site', 'Privacy', 'violation', async () => {
    const r = await audit('lab_standard');
    return { result: r.result, reasons: [] };
  });
  await scenario('Strict mode: all four provider form flows', 'Compatibility', 'pass', providerForms);
  await scenario('reCAPTCHA v3, Turnstile and hCaptcha JavaScript APIs', 'Compatibility', 'pass', programmaticApis);
  await scenario('Browser scrypt verified by the server', 'Mechanics', 'pass', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_stepup`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_stepup');
      return r.via === 'stepup' ? r : { ...r, result: 'unexpected-' + r.result };
    }));
  await scenario('Puzzle interface, then the wait path', 'Mechanics', 'pass', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua, viewport: { width: 900, height: 760 } });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_puzzle`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_puzzle');
      if (r.result !== 'puzzle') return r;
      await page.screenshot({ path: join(out, 'puzzle.png') });
      const frame = page.frames().find((f) => f.url().includes('/v1/frame'));
      await frame.getByRole('button', { name: /wait instead/ }).click();
      await page.waitForURL('**/demo/verify', { timeout: 60000 });
      const after = await outcome(page, 'lab_puzzle');
      return after.via === 'wait' ? after : { ...after, result: 'unexpected-' + after.result };
    }));
  await scenario('Frame refuses a host not on the allow list', 'Mechanics', 'blocked', () => withBrowser({}, async (b) => {
    const page = await b.newPage();
    const denied = new Promise((res) => {
      page.on('console', (m) => { if (/frame-ancestors/.test(m.text())) res(true); });
    });
    await page.goto(`http://127.0.0.1:18080/demo/?k=lab_standard`);
    const seen = await Promise.race([denied, new Promise((r) => setTimeout(() => r(false), 4000))]);
    return { result: seen ? 'blocked' : 'loaded', reasons: [] };
  }));
  await scenario('Real browser TLS handshake is not flagged', 'Mechanics', 'clean', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua, ignoreHTTPSErrors: true });
      const page = await ctx.newPage();
      await page.goto(`${TLS_BASE}/demo/?k=lab_standard`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_standard');
      const bad = (r.reasons ?? []).filter((x) => x.startsWith('net_tls'));
      return { ...r, result: r.result === 'pass' && !bad.length ? 'clean' : `flagged-${r.result}` };
    }));

  return { major };
}

function report(major) {
  const date = new Date().toISOString().slice(0, 10);
  const lines = [
    '# Lab results', '',
    `Run on ${date} against Chromium ${major}, by \`npm run lab\` in \`lab/\`. This file is generated.`, '',
    'These are outcomes against one browser on one machine. They show how the rules behave against each tool, not how often real attacks succeed, and they contain no test with real people. See the limits in the README.', '',
    '| Scenario | Tier | Outcome | Expected | Reason codes |', '|---|---|---|---|---|',
  ];
  for (const r of results) {
    const reasons = (r.reasons ?? []).map((x) => `\`${x}\``).join(' ');
    lines.push(`| ${r.name} | ${r.tier} | ${r.result}${r.via ? ` (${r.via}, score ${r.score})` : ''} | ${r.expected} | ${reasons.replaceAll('|', '/')} |`);
  }
  lines.push('');
  writeFileSync(process.env.LAB_REPORT ?? join(out, 'results.md'), lines.join('\n'));
}

const server = buildAndStart();
let failed = true;
try {
  await waitReady();
  const { major } = await run();
  report(major);
  failed = results.some((r) => !r.ok);
} finally {
  server.kill();
}
console.log(failed ? '\nLab failed.' : '\nLab passed.');
process.exit(failed ? 1 : 0);
