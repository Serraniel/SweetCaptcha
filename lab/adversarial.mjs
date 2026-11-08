// Adversarial lab: maintained evasion tools against the standard site. It reports
// what happens and does not fail on outcomes, because these tools change faster
// than any fixed expectation. Run it with `npm run adversarial`, or weekly in CI.
//
// Every tool here runs headless on one machine. Real attackers also run headful
// browsers, residential proxies and AI agents; see docs/THREAT_MODEL.md.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { chromium as patchright } from 'patchright';
import { addExtra } from 'puppeteer-extra';
import puppeteerCore from 'puppeteer-core';
import Stealth from 'puppeteer-extra-plugin-stealth';
import { chromium as rebrowser } from 'rebrowser-playwright-core';
import {
  BASE, CHROME_UA, agentStyleForm, bezierPath, buildAndStart, executablePath, humanStyleForm, out, outcome, results, scenario, waitReady,
} from './lib.mjs';

const KEY = 'lab_standard';

// Playwright-compatible forks share one flow.
async function playwrightFlow(engine, style, opts = {}) {
  const browser = await engine.launch({ headless: true, executablePath, ...opts });
  try {
    const major = browser.version().split('.')[0];
    const ctx = await browser.newContext({ userAgent: CHROME_UA(major) });
    const page = await ctx.newPage();
    await page.goto(`${BASE}/demo/?k=${KEY}`);
    await (style === 'human' ? humanStyleForm(page) : agentStyleForm(page));
    return await outcome(page, KEY);
  } finally {
    await browser.close();
  }
}

// Puppeteer has its own API, so outcome detection is repeated here.
async function puppeteerFlow(style) {
  const puppeteer = addExtra(puppeteerCore);
  puppeteer.use(Stealth());
  const browser = await puppeteer.launch({ headless: true, executablePath });
  try {
    const page = await browser.newPage();
    await page.goto(`${BASE}/demo/?k=${KEY}`);
    await new Promise((r) => setTimeout(r, 700));
    const field = await (await page.$('#name')).boundingBox();
    const send = await (await page.$('#send')).boundingBox();
    if (style === 'human') {
      let from = [40, 40];
      for (const box of [field, send]) {
        const to = [box.x + box.width / 2, box.y + box.height / 2];
        for (const [x, y] of bezierPath(from[0], from[1], to[0], to[1], 30)) {
          await page.mouse.move(x, y);
          await new Promise((r) => setTimeout(r, 10 + Math.random() * 15));
        }
        await page.mouse.down();
        await page.mouse.up();
        if (box === field) await page.keyboard.type('Lab Person', { delay: 110 });
        from = to;
      }
    } else {
      await page.type('#name', 'Automated Agent');
      await page.click('#send');
    }
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
      if (page.url().includes('/demo/verify')) {
        const data = JSON.parse(await page.$eval('#result', (e) => e.textContent));
        return { result: data.success ? 'pass' : 'rejected', via: data.via, score: data.score, reasons: data.reasons ?? [] };
      }
      const frame = page.frames().find((f) => f.url().includes('/v1/frame'));
      if (frame) {
        if (await frame.$('.modal h1, button.check[data-task]')) return { result: 'puzzle', reasons: [] };
        if (await frame.$('.mark.bad')) return { result: 'deny', reasons: [] };
        if (await frame.$('button.check:not([data-task])')) return { result: 'checkbox', reasons: [] };
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    return { result: 'timeout', reasons: [] };
  } finally {
    await browser.close();
  }
}

const REPORT = 'report';

async function run() {
  for (const style of ['agent', 'human']) {
    const label = style === 'human' ? 'humanised input' : 'agent-style input';
    await scenario(`Patchright, ${label}`, 'Maintained stealth fork', REPORT, () => playwrightFlow(patchright, style));
    await scenario(`rebrowser-playwright, ${label}`, 'Maintained stealth fork', REPORT, () => playwrightFlow(rebrowser, style,
      { args: ['--disable-blink-features=AutomationControlled'] }));
    await scenario(`puppeteer-extra stealth, ${label}`, 'Classic stealth plugin', REPORT, () => puppeteerFlow(style));
  }
}

function report() {
  const date = new Date().toISOString().slice(0, 10);
  const lines = [
    '# Adversarial results', '',
    `Run on ${date} by \`npm run adversarial\` in \`lab/\`. This file is generated.`, '',
    'Maintained evasion tools against the standard site, headless on one machine, with a spoofed user agent. These are observations, not expectations: the tools change often. "Pass" means the tool got a token without a task.', '',
    '| Tool and input | Tier | Outcome | Reason codes |', '|---|---|---|---|',
  ];
  for (const r of results) {
    const reasons = (r.reasons ?? []).map((x) => `\`${x}\``).join(' ');
    lines.push(`| ${r.name} | ${r.tier} | ${r.result}${r.via ? ` (${r.via}, score ${r.score})` : ''}${r.error ? ` (${r.error})` : ''} | ${reasons} |`);
  }
  lines.push('');
  writeFileSync(process.env.LAB_REPORT ?? join(out, 'adversarial.md'), lines.join('\n'));
}

const server = buildAndStart();
try {
  await waitReady();
  await run();
  report();
} finally {
  server.kill();
}
// Outcomes are reported, not asserted. Only a crashed run fails.
process.exit(results.some((r) => r.result === 'error') ? 1 : 0);
