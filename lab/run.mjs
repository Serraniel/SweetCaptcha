// The attacker lab. It runs the real binary and real Chromium against each attacker
// tier, and fails when an expected outcome changes. It is a regression suite for
// the detection rules and the source of the dated figures in docs/LAB_RESULTS.md.
//
// A headless, CDP-driven browser cannot stand in for a real person, so passing here
// says nothing about false positives on people. That needs testing on real devices.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { BASE, CHROME_UA, TLS_BASE, agentStyleForm, bezierPath, buildAndStart, centre, executablePath, here, humanClickCheckbox, humanStyleForm, moveLikePerson, out, outcome, results, root, scenario, secrets, verify, waitReady, widgetFrame } from './lib.mjs';

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
      trap: false,
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
  await scenario('Same forgery, native TLS: handshake exposes it', 'Forged protocol', 'interact', () => httpBot(ua, forgedSignals(ua, major), TLS_BASE));

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
  await scenario('Flag hidden, UA spoofed, humanised pointer and typing', 'Humanised browser', ['pass', 'checkbox-pass'], () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_standard');
      return r.via === 'checkbox' ? { ...r, result: 'checkbox-pass' } : r;
    }));
  await scenario('Agent waits, then clicks the checkbox directly', 'Default agent', 'puzzle', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await widgetFrame(page).locator('button.check').waitFor({ timeout: 15000 });
      await widgetFrame(page).locator('button.check').click();
      return outcome(page, 'lab_standard');
    }));
  await scenario('Visitor who does not move, then ticks the checkbox', 'Humanised browser', 'checkbox-pass', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await humanClickCheckbox(page);
      let r = await outcome(page, 'lab_standard');
      if (r.result === 'checkbox') r = await outcome(page, 'lab_standard');
      // The token is in the form now; send it the way a person would.
      await page.locator('#send').click();
      r = await outcome(page, 'lab_standard');
      return r.via === 'checkbox' ? { ...r, result: 'checkbox-pass' } : r;
    }));

  // Settings real people use, which must not lock them out.
  await scenario('Compatibility: JIT disabled, humanised input', 'Compatibility', ['pass', 'checkbox-pass'], () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled', '--js-flags=--jitless'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_standard', 90000);
      return r.via === 'checkbox' ? { ...r, result: 'checkbox-pass' } : r;
    }));
  // A user-agent switcher makes Chromium claim to be Firefox. The engine then
  // contradicts the claim, which is hard evidence: such visitors get a task, and
  // the help page tells them to turn the switcher off for the site.
  await scenario('Compatibility: user-agent switcher claiming Firefox', 'Compatibility', 'puzzle', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_standard`);
      await humanStyleForm(page);
      return outcome(page, 'lab_standard');
    }));

  await scenario('Network memory: a clean visitor after three forged requests from the same network', 'Mechanics', 'remembered', async () => {
    for (let i = 0; i < 3; i++) await httpBot(ua, null, BASE, 'lab_netmem');
    const r = await httpBot(ua, forgedSignals(ua, major), BASE, 'lab_netmem');
    const hit = (r.reasons ?? []).includes('net_recent_failures');
    return { ...r, result: hit && r.result !== 'deny' ? 'remembered' : `missed-${r.result}` };
  });

  // Mechanics.
  await scenario('Strict mode: no device reads, storage, or third parties', 'Privacy', 'clean', () => audit('lab_strict'));
  await scenario('Audit control: the same audit does find reads on a standard site', 'Privacy', 'violation', async () => {
    const r = await audit('lab_standard');
    return { result: r.result, reasons: [] };
  });
  await scenario('Strict mode: all four provider form flows', 'Compatibility', 'pass', providerForms);
  await scenario('Base proof of work: time to token in strict mode, this machine', 'Mechanics', 'fast', () => withBrowser({}, async (b) => {
    const times = [];
    for (let i = 0; i < 5; i++) {
      const page = await b.newPage();
      const started = Date.now();
      await page.goto(`${BASE}/demo/?k=lab_strict`);
      await page.waitForFunction(() => document.querySelector('input[name="sc-response"]')?.value, null, { timeout: 15000 });
      times.push(Date.now() - started);
      await page.close();
    }
    times.sort((a, b) => a - b);
    const median = times[2];
    // Target: about 0.2 s of work on a desktop, plus page and frame load.
    return { result: median < 1500 ? 'fast' : 'slow', reasons: [`median ${median} ms`, `max ${times[4]} ms`] };
  }));
  await scenario('reCAPTCHA v3, Turnstile and hCaptcha JavaScript APIs', 'Compatibility', 'pass', programmaticApis);
  await scenario('Checkbox step, with scrypt proof of work in the browser', 'Mechanics', 'pass', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_stepup`);
      await humanStyleForm(page);
      const first = await outcome(page, 'lab_stepup');
      if (first.result !== 'checkbox') return { ...first, result: 'unexpected-' + first.result };
      const send = await centre(page.locator('#send'));
      await humanClickCheckbox(page, send);
      const r = await outcome(page, 'lab_stepup');
      return r.via === 'checkbox' ? r : { ...r, result: 'unexpected-' + r.result };
    }));
  await scenario('Puzzle interface, then the wait path', 'Mechanics', 'pass', () => withBrowser(
    { args: ['--disable-blink-features=AutomationControlled'] }, async (b) => {
      const ctx = await b.newContext({ userAgent: ua, viewport: { width: 900, height: 760 } });
      const page = await ctx.newPage();
      await page.goto(`${BASE}/demo/?k=lab_puzzle`);
      await humanStyleForm(page);
      const r = await outcome(page, 'lab_puzzle');
      if (r.result !== 'puzzle') return r;
      const frame = page.frames().find((f) => f.url().includes('/v1/frame'));
      // Sending the form opens the pending task as a popup at the widget.
      await frame.locator('dialog .modal-head').waitFor({ timeout: 5000 }).catch(() => { throw new Error('task did not open on send'); });
      await page.screenshot({ path: join(out, 'puzzle.png') });
      // The popup must stay inside a small viewport.
      await page.setViewportSize({ width: 360, height: 480 });
      await page.waitForTimeout(200);
      const box = await page.locator('iframe').boundingBox();
      if (box.x < 0 || box.y < 0 || box.x + box.width > 360 || box.y + box.height > 480) {
        return { result: 'popup-outside-viewport', reasons: [JSON.stringify(box)] };
      }
      await page.setViewportSize({ width: 900, height: 760 });
      // Escape closes the task and leaves the checkbox. Ticking it reopens the task.
      await page.keyboard.press('Escape');
      await frame.locator('button.check').waitFor({ timeout: 5000 }).catch(() => { throw new Error('Escape did not close the task'); });
      if (await frame.locator('dialog').count()) return { result: 'dialog-not-closed', reasons: [] };
      // A click elsewhere on the page must also close it.
      await humanClickCheckbox(page, await centre(page.locator('#send')));
      await frame.locator('dialog .modal-head').waitFor({ timeout: 5000 }).catch(() => { throw new Error('ticking did not reopen the task'); });
      // The popup is placed by the host page after a message from the frame.
      await page.waitForFunction(() => document.querySelector('iframe')?.style.position === 'fixed');
      await page.mouse.click(5, 5);
      await frame.locator('button.check').waitFor({ timeout: 5000 }).catch(() => { throw new Error('outside click did not close the task'); });
      await humanClickCheckbox(page, await centre(page.locator('#send')));
      await frame.locator('dialog .modal-head').waitFor({ timeout: 5000 }).catch(() => { throw new Error('second reopen failed'); });
      await frame.getByRole('button', { name: /can't do this task/ }).click();
      // Closing the task cancelled the held submission, so send again once verified.
      await page.waitForFunction(() => document.querySelector('input[name="sc-response"]')?.value, null, { timeout: 60000 });
      await page.locator('#send').click();
      await page.waitForURL('**/demo/verify', { timeout: 10000 });
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
