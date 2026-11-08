// Shared lab helpers: the server under test, outcome detection and input styles.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const here = dirname(fileURLToPath(import.meta.url));
export const root = join(here, '..');
export const out = join(here, 'out');
mkdirSync(out, { recursive: true });
export const BASE = 'http://localhost:18080';
export const TLS_BASE = 'https://localhost:18443';
export const executablePath = process.env.LAB_CHROMIUM || undefined;
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // The lab's own self-signed certificate.
process.removeAllListeners('warning');

export const secrets = {
  lab_standard: 'lab-standard-secret-value',
  lab_strict: 'lab-strict-secret-value',
  lab_stepup: 'lab-stepup-secret-value',
  lab_puzzle: 'lab-puzzle-secret-value',
  lab_netmem: 'lab-netmem-secret-value',
};

export function buildAndStart() {
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

export async function waitReady() {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${BASE}/healthz`)).ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
}

export const CHROME_UA = (major) => `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;

export async function verify(token, key, base = BASE) {
  const r = await fetch(`${base}/v1/siteverify`, {
    method: 'POST',
    body: new URLSearchParams({ secret: secrets[key], response: token }),
  });
  return r.json();
}

// Reads the outcome the way a user would see it, then asks the server for reasons.
export async function outcome(page, key, timeout = 45000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (page.url().includes('/demo/verify')) {
      const data = JSON.parse(await page.locator('#result').textContent());
      return { result: data.success ? 'pass' : 'rejected', via: data.via, score: data.score, reasons: data.reasons ?? [] };
    }
    for (const f of page.frames()) {
      if (!f.url().includes('/v1/frame')) continue;
      if (await f.locator('.modal h1').count().catch(() => 0)) return { result: 'puzzle', reasons: [] };
      if (await f.locator('button.check:not([data-task])').count().catch(() => 0)) return { result: 'checkbox', reasons: [] };
      if (await f.locator('button.check[data-task]').count().catch(() => 0)) return { result: 'puzzle', reasons: [] };
      const mark = await f.locator('.mark.bad').count().catch(() => 0);
      if (mark) return { result: 'deny', reasons: [] };
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { result: 'timeout', reasons: [] };
}

export function bezierPath(x0, y0, x1, y1, steps) {
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

export async function moveLikePerson(page, from, to) {
  for (const [x, y] of bezierPath(from[0], from[1], to[0], to[1], 28 + Math.floor(Math.random() * 18))) {
    await page.mouse.move(x, y);
    await page.waitForTimeout(6 + Math.random() * 18);
  }
}

export async function centre(locator) {
  const b = await locator.boundingBox();
  return [b.x + b.width / 2, b.y + b.height / 2];
}

export async function agentStyleForm(page) {
  await page.waitForTimeout(600);
  await page.locator('#name').fill('Automated Agent');
  await page.locator('#send').click();
}

export async function humanStyleForm(page) {
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

export function widgetFrame(page) {
  return page.frames().find((f) => f.url().includes('/v1/frame'));
}

// Moves to the checkbox over a curved path, then clicks, as a person would.
export async function humanClickCheckbox(page, from = [60, 60]) {
  const box = widgetFrame(page).locator('button.check');
  await box.waitFor();
  await moveLikePerson(page, from, await centre(box));
  await page.waitForTimeout(120);
  await page.mouse.down();
  await page.mouse.up();
}

export const results = [];

export async function scenario(name, tier, expect, fn) {
  const started = Date.now();
  let res;
  try {
    res = await fn();
  } catch (e) {
    res = { result: 'error', reasons: [], error: String(e.message ?? e).split('\n')[0] };
  }
  const allowed = Array.isArray(expect) ? expect : [expect];
  const ok = allowed.includes('report') ? res.result !== 'error' : allowed.includes(res.result);
  results.push({ name, tier, expected: allowed.join(' or '), ok, ms: Date.now() - started, ...res });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${res.result}${res.via ? ` via ${res.via}` : ''}${res.score !== undefined ? ` score ${res.score}` : ''}${res.reasons?.length ? ` [${res.reasons.join(',')}]` : ''}${res.error ? ` (${res.error})` : ''}`);
}
