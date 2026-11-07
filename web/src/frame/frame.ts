// Runs inside the iframe on the captcha host. It ships in every edition and reads
// no device properties itself. In standard mode the server's reply names a
// separate collector script, which is only then loaded.
import './frame.css';
import type { PowParams } from '../shared/pow.ts';
import type { HostMessage } from '../shared/protocol.ts';
import { strings } from './i18n.ts';

const q = new URLSearchParams(location.search);
const siteKey = q.get('k') ?? '';
const hostname = q.get('h') ?? '';
const parentOrigin = q.get('o') ?? '';
const t = strings(q.get('l') ?? '');
const theme = q.get('t');
if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
if (q.get('s') === 'compact') document.body.classList.add('compact');
document.documentElement.lang = t === strings('de') ? 'de' : 'en';

const root = document.getElementById('root')!;
const workerUrl = document.documentElement.dataset.worker!;

declare global {
  interface Window {
    __sweetcaptchaCollect?: (nonce: string, workerUrl: string, page: { behaviour: unknown; artefacts: unknown }) => Promise<unknown>;
  }
}

function send(type: string, extra: Record<string, unknown> = {}): void {
  parent.postMessage({ sc: 1, type, ...extra }, parentOrigin);
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls = '', text = ''): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text) n.textContent = text;
  return n;
}

function badge(state: 'busy' | 'ok' | 'bad', message: string, action?: { label: string; run: () => void }, link?: { label: string; href: string }): void {
  const box = el('div', 'badge');
  const icon = el('div', 'icon');
  if (state === 'busy') icon.append(el('div', 'spin'));
  else icon.append(el('div', state === 'ok' ? 'mark' : 'mark bad', state === 'ok' ? '✓' : '!'));
  const text = el('div', 'text');
  const status = el('div', 'status', message);
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  text.append(status);
  if (action) {
    const b = el('button', 'link', action.label);
    b.type = 'button';
    b.addEventListener('click', action.run);
    text.append(b);
  } else if (link) {
    const a = el('a', '', link.label);
    a.href = link.href;
    a.target = '_blank';
    a.rel = 'noopener';
    text.append(a);
  } else {
    text.append(el('div', 'brand', t.brand));
  }
  box.append(icon, text);
  root.replaceChildren(box);
}

interface ChallengeReply {
  c?: string;
  pow?: PowParams;
  mode?: string;
  status?: string;
  token?: string;
  ttl?: number;
  error?: string;
  collect?: { nonce: string; worker: string; frame: string; frameSri: string; page: string; pageSri: string };
}

interface PuzzlePublic {
  family: string;
  images: string[];
  options?: number;
  columns?: number;
  rows?: number;
  markers?: number;
}

interface SubmitReply {
  status: 'pass' | 'stepup' | 'puzzle' | 'deny' | 'retry';
  token?: string;
  ttl?: number;
  c?: string;
  pow?: PowParams;
  puzzle?: PuzzlePublic;
  p?: string;
  wait?: boolean;
  support?: string;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'omit',
    cache: 'no-store',
  });
  return (await r.json()) as T;
}

let generation = 0;
let worker: Worker | null = null;

function solve(p: PowParams, onProgress?: (v: number) => void): Promise<number[]> {
  worker?.terminate();
  const w = new Worker(workerUrl);
  worker = w;
  return new Promise((res, rej) => {
    w.onerror = () => rej(new Error('worker-failed'));
    w.onmessage = (ev: MessageEvent<{ progress?: number; nonces?: number[] }>) => {
      if (ev.data.progress !== undefined) onProgress?.(ev.data.progress);
      if (ev.data.nonces) {
        w.terminate();
        res(ev.data.nonces);
      }
    };
    w.postMessage(p);
  });
}

function loadScript(src: string, integrity: string): Promise<void> {
  return new Promise((res) => {
    const s = document.createElement('script');
    s.src = src;
    s.integrity = integrity;
    s.onload = () => res();
    s.onerror = () => res();
    document.head.append(s);
  });
}

let finishWaiter: ((m: HostMessage) => void) | null = null;
let earlyFinish: HostMessage | null = null;

function waitForFinish(): Promise<HostMessage> {
  if (earlyFinish) {
    const m = earlyFinish;
    earlyFinish = null;
    return Promise.resolve(m);
  }
  return new Promise((res) => {
    finishWaiter = res;
  });
}

async function run(action: string, cdata: string): Promise<void> {
  const mine = ++generation;
  const stale = () => mine !== generation;
  earlyFinish = null;
  badge('busy', t.verifying);
  let reply: ChallengeReply;
  try {
    reply = await post<ChallengeReply>('/v1/challenge', { sitekey: siteKey, action, hostname, cdata });
  } catch {
    return showError('network-error');
  }
  if (stale()) return;
  if (reply.token) return pass(reply.token, reply.ttl ?? 300);
  if (!reply.c || !reply.pow) return showError(reply.error ?? 'challenge-failed');

  let collectorReady = Promise.resolve();
  if (reply.collect?.frame) {
    send('collect', { page: reply.collect.page, pageSri: reply.collect.pageSri });
    collectorReady = loadScript(reply.collect.frame, reply.collect.frameSri);
  }
  let nonces: number[];
  try {
    nonces = await solve(reply.pow);
  } catch {
    return showError('worker-failed');
  }
  if (stale()) return;

  let signals: unknown;
  if (reply.collect) {
    send('pow-ready');
    const finish = await waitForFinish();
    if (stale()) return;
    await collectorReady;
    try {
      signals = await window.__sweetcaptchaCollect?.(reply.collect.nonce, reply.collect.worker, {
        behaviour: finish.behaviour,
        artefacts: finish.artefacts,
      });
    } catch {
      signals = undefined; // The server scores missing evidence.
    }
    if (stale()) return;
  }
  let result: SubmitReply;
  try {
    result = await post<SubmitReply>('/v1/submit', { c: reply.c, nonces, signals });
  } catch {
    return showError('network-error');
  }
  if (!stale()) await handle(result, action, cdata, mine);
}

function pass(token: string, ttl: number): void {
  badge('ok', t.verified);
  send('token', { token, ttl });
}

function showError(code: string): void {
  send('overlay', { on: false });
  badge('bad', t.failed, { label: t.retry, run: () => void run(lastAction, lastCData) });
  send('error', { code });
}

async function handle(r: SubmitReply, action: string, cdata: string, mine: number): Promise<void> {
  const stale = () => mine !== generation;
  switch (r.status) {
    case 'pass':
      send('overlay', { on: false });
      return pass(r.token!, r.ttl ?? 300);
    case 'stepup': {
      const onProgress = progressView();
      let nonces: number[];
      try {
        nonces = await solve(r.pow!, onProgress);
      } catch {
        return showError('worker-failed');
      }
      if (stale()) return;
      const next = await post<SubmitReply>('/v1/submit', { c: r.c, nonces });
      if (!stale()) await handle(next, action, cdata, mine);
      return;
    }
    case 'puzzle':
      send('overlay', { on: true });
      return showPuzzle(r, action, cdata, mine);
    case 'deny':
      send('overlay', { on: false });
      badge('bad', t.denied, undefined, r.support ? { label: t.contact, href: r.support } : undefined);
      send('error', { code: 'denied' });
      return;
    default:
      return void run(action, cdata);
  }
}

// While a step-up runs in a small widget, the badge shows a percentage. In the
// wait fallback, the modal is open and shows a bar.
let barTarget: HTMLElement | null = null;

function progressView(): (v: number) => void {
  if (barTarget) {
    const b = barTarget;
    return (v) => {
      b.style.width = `${Math.round(v * 100)}%`;
    };
  }
  badge('busy', t.working);
  return () => undefined;
}

function showPuzzle(r: SubmitReply, action: string, cdata: string, mine: number, note = ''): void {
  barTarget = null;
  const p = r.puzzle!;
  const box = el('div', 'modal');
  const heading = el('h1', '', t.puzzleTitle);
  heading.tabIndex = -1;
  box.append(heading);
  if (note) {
    const n = el('p', 'note', note);
    n.setAttribute('role', 'alert');
    box.append(n);
  }
  let collect: () => number[];
  if (p.family === 'line-trace') collect = lineTraceView(box, p);
  else if (p.family === 'gap-rings') collect = gapRingsView(box, p);
  else collect = rotateView(box, p);

  const submit = el('button', 'primary', t.submit);
  submit.type = 'button';
  const stale = () => mine !== generation;
  submit.addEventListener('click', () => {
    submit.disabled = true;
    void (async () => {
      let next: SubmitReply;
      try {
        next = await post<SubmitReply>('/v1/answer', { p: r.p, values: collect() });
      } catch {
        return showError('network-error');
      }
      if (stale()) return;
      if (next.status === 'puzzle') return showPuzzle(next, action, cdata, mine, t.wrong);
      if (next.status === 'stepup') showWait();
      await handle(next, action, cdata, mine);
    })();
  });
  box.append(submit);
  if (r.wait) {
    const offer = el('button', 'secondary', t.waitOffer);
    offer.type = 'button';
    offer.addEventListener('click', () => {
      offer.disabled = true;
      void (async () => {
        let next: SubmitReply;
        try {
          next = await post<SubmitReply>('/v1/wait', { p: r.p });
        } catch {
          return showError('network-error');
        }
        if (stale()) return;
        if (next.status === 'stepup') showWait();
        await handle(next, action, cdata, mine);
      })();
    });
    box.append(offer, el('p', 'muted', t.waitNote));
  }
  if (r.support) {
    const a = el('a', '', t.contact);
    a.href = r.support;
    a.target = '_blank';
    a.rel = 'noopener';
    box.append(a);
  }
  root.replaceChildren(box);
  // Focus the heading rather than the first control, so that the task is read
  // first and nothing scrolls out of view.
  heading.focus({ preventScroll: true });
}

function showWait(): void {
  const box = el('div', 'modal');
  box.append(el('h1', '', t.puzzleTitle));
  const status = el('p', '', t.waiting);
  status.setAttribute('role', 'status');
  box.append(status);
  const bar = el('div', 'bar');
  const fill = el('div');
  bar.append(fill);
  box.append(bar);
  barTarget = fill;
  root.replaceChildren(box);
}

function image(src: string): HTMLImageElement {
  const i = el('img');
  i.src = src;
  i.alt = '';
  return i;
}

function lineTraceView(box: HTMLElement, p: PuzzlePublic): () => number[] {
  box.append(el('p', '', t.lineTrace));
  const stage = el('div', 'stage');
  stage.append(image(p.images[0]));
  box.append(stage);
  const answers: number[] = [-1, -1];
  [t.lineCircle, t.lineSquare].forEach((label, q) => {
    const id = `q${q}`;
    const l = el('p', '', label);
    l.id = id;
    const row = el('div', 'choices');
    row.setAttribute('role', 'group');
    row.setAttribute('aria-labelledby', id);
    for (let i = 0; i < (p.options ?? 0); i++) {
      const b = el('button', 'choice', String(i + 1));
      b.type = 'button';
      b.setAttribute('aria-pressed', 'false');
      b.addEventListener('click', () => {
        answers[q] = i;
        row.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      });
      row.append(b);
    }
    box.append(l, row);
  });
  return () => answers;
}

function gapRingsView(box: HTMLElement, p: PuzzlePublic): () => number[] {
  box.append(el('p', '', t.gapRings));
  const stage = el('div', 'stage');
  stage.append(image(p.images[0]));
  const grid = el('div', 'grid');
  grid.style.gridTemplateColumns = `repeat(${p.columns}, 1fr)`;
  grid.style.gridTemplateRows = `repeat(${p.rows}, 1fr)`;
  const chosen = new Set<number>();
  for (let i = 0; i < (p.options ?? 0); i++) {
    const b = el('button', 'cell', `${t.cell} ${i + 1}`);
    b.type = 'button';
    b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', () => {
      if (chosen.has(i)) chosen.delete(i);
      else chosen.add(i);
      b.setAttribute('aria-pressed', String(chosen.has(i)));
    });
    grid.append(b);
  }
  stage.append(grid);
  box.append(stage);
  return () => [...chosen];
}

function rotateView(box: HTMLElement, p: PuzzlePublic): () => number[] {
  box.append(el('p', '', t.rotate));
  const values: number[] = [];
  for (let i = 0; i < p.images.length; i += 2) {
    const index = i / 2;
    values[index] = 0;
    const pair = el('div', 'pair');
    const turned = image(p.images[i + 1]);
    const slider = el('input');
    slider.type = 'range';
    slider.min = '0';
    slider.max = '359';
    slider.step = '1';
    slider.value = '0';
    slider.setAttribute('aria-label', `${t.rotateLabel} ${index + 1}`);
    slider.addEventListener('input', () => {
      values[index] = Number(slider.value);
      turned.style.transform = `rotate(${slider.value}deg)`;
    });
    pair.append(image(p.images[i]), turned, slider);
    box.append(pair);
  }
  return () => values;
}

let lastAction = '';
let lastCData = '';

window.addEventListener('message', (ev: MessageEvent<HostMessage>) => {
  if (ev.source !== parent || ev.origin !== parentOrigin || ev.data?.sc !== 1) return;
  switch (ev.data.type) {
    case 'start':
      lastAction = ev.data.action ?? '';
      lastCData = ev.data.cdata ?? '';
      void run(lastAction, lastCData);
      break;
    case 'finish':
      if (finishWaiter) {
        const w = finishWaiter;
        finishWaiter = null;
        w(ev.data);
      } else {
        earlyFinish = ev.data;
      }
      break;
    case 'reset':
      generation++;
      worker?.terminate();
      break;
  }
});

send('ready');
