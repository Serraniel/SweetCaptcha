// Compares proof-of-work solve times: the browser widget (4 workers) against a
// native Go solver (one thread), per default level. Writes docs/BENCHMARKS.md
// when LAB_REPORT points there.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { BASE, buildAndStart, executablePath, out, root, waitReady } from './lib.mjs';

const levels = [
  { name: 'Base', key: 'lab_bench_base', bench: 'base', work: '14 bits × 48, SHA-256' },
  { name: 'Checkbox step', key: 'lab_bench_checkbox', bench: 'checkbox', work: '16 bits × 48, SHA-256' },
  { name: 'Wait path (work only)', key: 'lab_bench_wait', bench: 'wait', work: '18 bits × 48, SHA-256' },
  { name: 'scrypt option', key: 'lab_bench_scrypt', bench: 'scrypt', work: '4 bits × 16, scrypt N=1024' },
];
const RUNS = 5;

function nativeTimes() {
  const raw = execFileSync('go', ['test', '-run', 'x', '-bench', 'BenchmarkSolveNative', '-benchtime', '10x', './internal/pow'], { cwd: root }).toString();
  const times = {};
  for (const m of raw.matchAll(/BenchmarkSolveNative\/(\w+)-\d+\s+\d+\s+(\d+) ns\/op/g)) times[m[1]] = Number(m[2]) / 1e6;
  return times;
}

async function browserTimes(browser, key) {
  const times = [];
  for (let i = 0; i < RUNS; i++) {
    const page = await browser.newPage();
    let issued = 0;
    const done = new Promise((res) => {
      page.on('response', (r) => { if (r.url().endsWith('/v1/challenge')) issued = Date.now(); });
      page.on('request', (r) => { if (r.url().endsWith('/v1/submit')) res(Date.now() - issued); });
    });
    await page.goto(`${BASE}/demo/?k=${key}`);
    times.push(await Promise.race([done, new Promise((r) => setTimeout(() => r(NaN), 120000))]));
    await page.close();
  }
  return times.sort((a, b) => a - b)[Math.floor(RUNS / 2)];
}

const server = buildAndStart();
try {
  await waitReady();
  const native = nativeTimes();
  const browser = await chromium.launch({ headless: true, executablePath, channel: executablePath ? undefined : 'chromium' });
  const major = browser.version().split('.')[0];
  const rows = [];
  for (const l of levels) {
    const ms = await browserTimes(browser, l.key);
    const n = native[l.bench];
    rows.push(`| ${l.name} | ${l.work} | ${Math.round(ms)} ms | ${n.toFixed(0)} ms | ${(ms / n).toFixed(1)}× |`);
    console.log(rows.at(-1));
  }
  await browser.close();
  const date = new Date().toISOString().slice(0, 10);
  const md = [
    '# Proof-of-work benchmarks', '',
    `Run on ${date} by \`npm run bench\` in \`lab/\`, Chromium ${major}, on one desktop machine. This file is generated.`, '',
    'Browser: the widget with 4 workers, median of 5 runs, measured from the challenge reply to the submit request. Native: the Go solver on one thread, as an attacker would start, median of 10. A native solver on all cores, or on a GPU, is faster again, and phones are slower; neither is measured here.', '',
    '| Level | Work | Browser, 4 workers | Native, 1 thread | Browser ÷ native |', '|---|---|---|---|---|',
    ...rows, '',
  ].join('\n');
  writeFileSync(process.env.LAB_REPORT ?? join(out, 'benchmarks.md'), md);
} finally {
  server.kill();
}
