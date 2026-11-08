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
// The server chose the language and set it on <html lang>.
const t = strings(document.documentElement.lang);
const invisible = q.get('s') === 'invisible';
const theme = q.get('t');
if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
if (q.get('s') === 'compact') document.body.classList.add('compact');

const root = document.getElementById('root')!;
const workerUrl = document.documentElement.dataset.worker!;

interface Collectors {
  __sweetcaptchaCollect?: (nonce: string, workerUrl: string, page: { behaviour: unknown; artefacts: unknown }) => Promise<unknown>;
  // Standard mode only: marks when the checkbox appears and describes how it was used.
  __sweetcaptchaMark?: () => void;
  __sweetcaptchaClick?: () => unknown;
}
const hooks = window as unknown as Collectors;

function send(type: string, extra: Record<string, unknown> = {}): void {
  parent.postMessage({ sc: 1, type, ...extra }, parentOrigin);
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls = '', text = ''): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text) n.textContent = text;
  return n;
}

// The site's own privacy notice and imprint, when configured. Never the project's.
function legalLinks(into: HTMLElement): void {
  const d = document.documentElement.dataset;
  for (const [href, label] of [[d.privacy, t.privacy], [d.imprint, t.imprint]] as const) {
    if (!href) continue;
    const a = el('a', '', label);
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener';
    into.append(' · ', a);
  }
}

function brandLine(): HTMLElement {
  const line = el('div', 'brand', `SweetCaptcha ${document.documentElement.dataset.version ?? ''}`.trim());
  legalLinks(line);
  return line;
}

function statusLine(message: string): HTMLElement {
  const status = el('div', 'status', message);
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  return status;
}

function badge(state: 'busy' | 'ok' | 'bad', message: string, action?: { label: string; run: () => void }, link?: { label: string; href: string }): void {
  const box = el('div', 'badge');
  const icon = el('div', 'icon');
  if (state === 'busy') icon.append(el('div', 'spin'));
  else icon.append(el('div', state === 'ok' ? 'mark' : 'mark bad', state === 'ok' ? '✓' : '!'));
  const text = el('div', 'text');
  text.append(statusLine(message));
  if (action || link) {
    const row = el('div', 'links');
    if (action) {
      const b = el('button', 'link', action.label);
      b.type = 'button';
      b.addEventListener('click', action.run);
      row.append(b);
    }
    if (link) {
      const a = el('a', '', link.label);
      a.href = link.href;
      a.target = '_blank';
      a.rel = 'noopener';
      row.append(a);
    }
    // Errors always offer the help page, which gives advice for blocked visitors.
    if (state === 'bad') {
      const help = el('a', '', t.help);
      help.href = `/v1/help?k=${encodeURIComponent(siteKey)}&l=${encodeURIComponent(document.documentElement.lang)}`;
      help.target = '_blank';
      help.rel = 'noopener';
      row.append(help);
    }
    text.append(row);
  } else if (state === 'bad') {
    const help = el('a', '', t.help);
    help.href = `/v1/help?k=${encodeURIComponent(siteKey)}&l=${encodeURIComponent(document.documentElement.lang)}`;
    help.target = '_blank';
    help.rel = 'noopener';
    text.append(help);
  } else {
    text.append(brandLine());
  }
  box.append(icon, text);
  root.replaceChildren(box);
}

// Shows a status with a progress bar. Proof of work reports progress per
// sub-puzzle, so the bar moves in steps.
function busyWithProgress(message: string): (v: number) => void {
  badge('busy', message);
  const bar = el('div', 'bar');
  const fill = el('div');
  bar.append(fill);
  root.querySelector('.brand')?.replaceWith(bar);
  return (v) => {
    fill.style.width = `${Math.round(v * 100)}%`;
  };
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
  frames?: number;
  fps?: number;
  frameSize?: number;
}

interface SubmitReply {
  status: 'pass' | 'interact' | 'stepup' | 'hold' | 'puzzle' | 'deny' | 'retry';
  retry?: number;
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

// Proof of work runs in a fixed number of workers. A fixed count avoids reading
// the device's core count, which strict mode must not do. Devices with fewer
// cores simply share them.
const WORKERS = 4;
let workers: Worker[] = [];

function stopWorkers(): void {
  for (const w of workers) w.terminate();
  workers = [];
}

function solve(p: PowParams, onProgress?: (v: number) => void, count = WORKERS): Promise<number[]> {
  stopWorkers();
  const nonces: number[] = new Array(p.count);
  let solved = 0;
  return new Promise((res, rej) => {
    const fail = () => {
      stopWorkers();
      // Memory-hard work can exhaust memory with several workers on small devices.
      // Retry once with a single worker; the algorithm and difficulty stay the same.
      if (count > 1) solve(p, onProgress, 1).then(res, rej);
      else rej(new Error('worker-failed'));
    };
    for (let k = 0; k < Math.min(count, p.count); k++) {
      const indices: number[] = [];
      for (let i = k; i < p.count; i += count) indices.push(i);
      const w = new Worker(workerUrl);
      workers.push(w);
      w.onerror = fail;
      w.onmessage = (ev: MessageEvent<{ index?: number; nonce?: number; done?: boolean; error?: string }>) => {
        if (ev.data.error) return fail();
        if (ev.data.index === undefined || ev.data.nonce === undefined) return;
        if (nonces[ev.data.index] === undefined) solved++;
        nonces[ev.data.index] = ev.data.nonce;
        onProgress?.(solved / p.count);
        if (solved === p.count) {
          stopWorkers();
          res(nonces);
        }
      };
      w.postMessage({ params: p, indices });
    }
  });
}

// Posts solved work. The wait path has a minimum duration enforced by the server,
// which answers "hold" until it has passed; the request is then repeated.
async function submitWork(body: Record<string, unknown>, onHold?: (ms: number) => void): Promise<SubmitReply> {
  for (;;) {
    const r = await post<SubmitReply>('/v1/submit', body);
    if (r.status !== 'hold') return r;
    const ms = Math.max(200, Math.min(r.retry ?? 1000, 60000));
    onHold?.(ms);
    await new Promise((res) => setTimeout(res, ms));
  }
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
// Set while the checkbox waits for a click, so that a form submit can prompt for it.
let checkboxPrompt: (() => void) | null = null;
// The open puzzle, kept so that closing the dialog does not throw it away.
let openPuzzle: { reply: SubmitReply; expires: number } | null = null;
let lastAction = '';
let lastCData = '';
// A "retry" reply means the challenge expired or was lost. One silent retry hides
// that from the visitor; after it, an error with a retry button appears instead of
// looping.
let silentRetries = 0;

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
  checkboxPrompt = null;
  openPuzzle = null;
  const showProgress = busyWithProgress(t.verifying);
  let reply: ChallengeReply;
  try {
    const trap = document.querySelector<HTMLAnchorElement>('a.t[data-trap]')?.dataset.trap ?? '';
    reply = await post<ChallengeReply>('/v1/challenge', { sitekey: siteKey, action, hostname, cdata, trap });
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
    nonces = await solve(reply.pow, showProgress);
  } catch {
    return showError('worker-failed');
  }
  if (stale()) return;

  let signals: unknown;
  let user = invisible;
  if (reply.collect) {
    // The host page decides when to finish: after the visitor's first input, or a
    // short timeout. Waiting briefly lets the evidence include some interaction.
    send('pow-ready');
    const finish = await waitForFinish();
    if (stale()) return;
    user = user || Boolean(finish.user);
    await collectorReady;
    try {
      signals = await hooks.__sweetcaptchaCollect?.(reply.collect.nonce, reply.collect.worker, {
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
  if (!stale()) await handle(result, action, cdata, mine, user);
}

function pass(token: string, ttl: number): void {
  silentRetries = 0;
  checkboxPrompt = null;
  openPuzzle = null;
  send('overlay', { on: false });
  badge('ok', t.verified);
  send('token', { token, ttl });
}

function showError(code: string): void {
  send('overlay', { on: false });
  badge('bad', t.failed, { label: t.retry, run: () => void run(lastAction, lastCData) });
  send('error', { code });
}

// user is true when the visitor's own action led here. A task opens only then;
// otherwise the widget offers it, so that nothing takes focus while someone types.
async function handle(r: SubmitReply, action: string, cdata: string, mine: number, user = false): Promise<void> {
  const stale = () => mine !== generation;
  switch (r.status) {
    case 'pass':
      return pass(r.token!, r.ttl ?? 300);
    case 'interact':
      return showCheckbox(r, action, cdata, mine);
    case 'stepup': {
      // The calculation fills most of the bar; any server-enforced remainder fills
      // the rest, so the bar never sits full while the visitor still waits.
      const progress = progressView();
      let nonces: number[];
      try {
        nonces = await solve(r.pow!, (v) => progress(v * 0.8));
      } catch {
        return showError('worker-failed');
      }
      if (stale()) return;
      const next = await submitWork({ c: r.c, nonces }, (ms) => progress(1, ms));
      if (!stale()) await handle(next, action, cdata, mine, user);
      return;
    }
    case 'puzzle':
      openPuzzle = { reply: r, expires: new Date().getTime() + 4.5 * 60 * 1000 };
      if (user) return showPuzzle(r, action, cdata, mine);
      return offerTask(action, cdata, mine);
    case 'deny':
      send('overlay', { on: false });
      badge('bad', t.denied, undefined, r.support ? { label: t.contact, href: r.support } : undefined);
      send('error', { code: 'denied' });
      return;
    default:
      if (silentRetries++ < 1) return void run(action, cdata);
      return showError('verification-failed');
  }
}

// The checkbox appears when the evidence is unclear, including when there was no
// interaction at all. The extra proof of work runs while it is shown.
function showCheckbox(r: SubmitReply, action: string, cdata: string, mine: number): void {
  const stale = () => mine !== generation;
  const work = solve(r.pow!).catch(() => null);
  const b = el('button', 'check');
  b.type = 'button';
  b.setAttribute('role', 'checkbox');
  b.setAttribute('aria-checked', 'false');
  const text = el('div', 'text');
  text.append(el('div', 'status', t.checkbox), brandLine());
  b.append(el('div', 'box'), text);
  b.addEventListener('click', () => {
    checkboxPrompt = null;
    void (async () => {
      const click = hooks.__sweetcaptchaClick?.();
      busyWithProgress(t.verifying);
      const nonces = await work;
      if (stale()) return;
      if (!nonces) return showError('worker-failed');
      let next: SubmitReply;
      try {
        next = await post<SubmitReply>('/v1/submit', { c: r.c, nonces, click });
      } catch {
        return showError('network-error');
      }
      if (!stale()) await handle(next, action, cdata, mine, true);
    })();
  }, { once: true });
  checkboxPrompt = () => {
    if (!text.querySelector('.prompt')) {
      const p = el('div', 'prompt', t.checkboxPrompt);
      p.setAttribute('role', 'alert');
      text.querySelector('.brand')?.replaceWith(p);
    }
    b.focus();
  };
  if (invisible) {
    // An invisible widget has no place on the page, so the checkbox opens as a dialog.
    const box = modalShell(() => dismiss(action, cdata, mine));
    box.append(b);
    send('overlay', { on: true });
  } else {
    root.replaceChildren(b);
  }
  hooks.__sweetcaptchaMark?.();
}

// A step-up shows its bar in the badge. The wait path shows one in the open dialog.
let barTarget: HTMLElement | null = null;

function progressView(): (v: number, overMs?: number) => void {
  const b = barTarget;
  if (!b) {
    const set = busyWithProgress(t.working);
    return (v) => set(v);
  }
  return (v, overMs) => {
    b.style.transition = overMs ? `width ${overMs}ms linear` : '';
    b.style.width = `${Math.round(v * 100)}%`;
  };
}

// Builds the dialog used for tasks. A native dialog closes with Escape and keeps
// focus inside, with no key listeners of our own.
function modalShell(onClose: () => void): HTMLElement {
  barTarget = null;
  const dialog = el('dialog', 'modal');
  const box = el('div');
  box.style.display = 'grid';
  box.style.gap = '12px';
  const head = el('div', 'modal-head');
  const heading = el('h1', '', t.puzzleTitle);
  heading.tabIndex = -1;
  const close = el('button', 'close', '×');
  close.type = 'button';
  close.setAttribute('aria-label', t.close);
  close.addEventListener('click', onClose);
  head.append(heading, close);
  box.append(head);
  dialog.append(box);
  dialog.addEventListener('cancel', (e) => {
    e.preventDefault();
    onClose();
  });
  root.replaceChildren(dialog);
  dialog.showModal();
  // Focus the heading rather than the first control, so that the task is read
  // first and nothing scrolls out of view.
  heading.focus({ preventScroll: true });
  return box;
}

// Closing a task returns to the checkbox. Ticking it again reopens the same task
// while it is still valid, so closing does not cost the visitor anything.
function dismiss(action: string, cdata: string, mine: number): void {
  send('overlay', { on: false, dismissed: true });
  offerTask(action, cdata, mine);
}

// Shows the checkbox for a pending task. The task opens on a click, or when the
// visitor sends the form.
function offerTask(action: string, cdata: string, mine: number): void {
  const b = el('button', 'check');
  b.dataset.task = '1';
  b.type = 'button';
  b.setAttribute('role', 'checkbox');
  b.setAttribute('aria-checked', 'false');
  const text = el('div', 'text');
  text.append(el('div', 'status', t.checkbox), brandLine());
  b.append(el('div', 'box'), text);
  const open = () => {
    checkboxPrompt = null;
    const keep = openPuzzle;
    if (keep && keep.expires > new Date().getTime() && mine === generation) {
      showPuzzle(keep.reply, action, cdata, mine);
    } else {
      void run(action, cdata);
    }
  };
  b.addEventListener('click', open, { once: true });
  checkboxPrompt = open;
  root.replaceChildren(b);
}

function showPuzzle(r: SubmitReply, action: string, cdata: string, mine: number, note = ''): void {
  send('overlay', { on: true });
  const p = r.puzzle!;
  const box = modalShell(() => dismiss(action, cdata, mine));
  if (note) {
    const n = el('p', 'note', note);
    n.setAttribute('role', 'alert');
    box.append(n);
  }
  let collect: () => number[];
  if (p.family === 'line-trace') collect = lineTraceView(box, p);
  else if (p.family === 'gap-rings') collect = gapRingsView(box, p);
  else if (p.family === 'kinetic') collect = kineticView(box, p);
  else if (p.family === 'stack-order') collect = stackOrderView(box, p);
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
      if (next.status === 'puzzle') {
        openPuzzle = { reply: next, expires: new Date().getTime() + 4.5 * 60 * 1000 };
        return showPuzzle(next, action, cdata, mine, t.wrong);
      }
      openPuzzle = null;
      if (next.status === 'stepup') showWait(action, cdata, mine);
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
        openPuzzle = null;
        if (next.status === 'stepup') showWait(action, cdata, mine);
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
  const legal = el('p', 'muted');
  legalLinks(legal);
  if (legal.childNodes.length) {
    legal.firstChild?.remove(); // Drop the leading separator.
    box.append(legal);
  }
}

function showWait(action: string, cdata: string, mine: number): void {
  // Closing the dialog here abandons the calculation, so it starts again from the
  // checkbox, which runs a fresh verification.
  const box = modalShell(() => {
    generation++;
    stopWorkers();
    dismiss(action, cdata, mine + 1);
  });
  const status = el('p', '', t.waiting);
  status.setAttribute('role', 'status');
  box.append(status);
  const bar = el('div', 'bar');
  const fill = el('div');
  bar.append(fill);
  box.append(bar);
  barTarget = fill;
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
  const chosen = cellGrid(stage, p);
  box.append(stage);
  return () => [...chosen];
}

// Selectable cells laid over a picture, shared by the grid tasks.
function cellGrid(stage: HTMLElement, p: PuzzlePublic): Set<number> {
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
  return chosen;
}

// The frames are one sprite sheet that CSS steps through, so no script draws
// anything and the animation runs only after Play.
function kineticView(box: HTMLElement, p: PuzzlePublic): () => number[] {
  box.append(el('p', '', t.kineticAuto));
  const note = el('p', 'muted motion-note', t.motionNote);
  const stage = el('div', 'stage kinetic');
  const film = el('div', 'film');
  film.style.backgroundImage = `url("${p.images[0]}")`;
  film.style.backgroundSize = `100% ${(p.frames ?? 1) * 100}%`;
  film.style.animationDuration = `${(p.frames ?? 1) / (p.fps ?? 25)}s`;
  film.style.setProperty('--frames', String(p.frames ?? 1));
  stage.append(film);
  const chosen = cellGrid(stage, p);
  // The motion starts by itself, since a task only opens after a deliberate action.
  // A checkbox toggles it and CSS does the rest: with "reduce motion" set the film
  // starts still and the checkbox plays it. No script reads that preference.
  const toggle = el('input', 'motion-input');
  toggle.type = 'checkbox';
  toggle.id = 'motion-toggle';
  const label = el('label', 'secondary motion-toggle');
  label.htmlFor = toggle.id;
  label.append(el('span', 'when-running', t.pause), el('span', 'when-paused', t.play));
  box.append(toggle, label, stage, note);
  return () => [...chosen];
}

function stackOrderView(box: HTMLElement, p: PuzzlePublic): () => number[] {
  const stage = el('div', 'stage');
  stage.append(image(p.images[0]));
  box.append(stage);
  const answers = [-1, -1];
  [t.stackOrder, t.stackFront].forEach((label, q) => {
    const id = `s${q}`;
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
    slider.max = '357';
    slider.step = '3';
    slider.value = '0';
    slider.setAttribute('aria-label', `${t.rotateLabel} ${index + 1}`);
    slider.addEventListener('input', () => {
      values[index] = Number(slider.value);
      turned.style.transform = `rotate(${slider.value}deg)`;
    });
    // The image turns inside a fixed circle, so its corners never cover the page.
    const dial = (img: HTMLImageElement): HTMLElement => {
      const d = el('div', 'dial');
      d.append(img);
      return d;
    };
    pair.append(dial(image(p.images[i])), dial(turned), slider);
    box.append(pair);
  }
  return () => values;
}

window.addEventListener('message', (ev: MessageEvent<HostMessage>) => {
  if (ev.source !== parent || ev.origin !== parentOrigin || ev.data?.sc !== 1) return;
  switch (ev.data.type) {
    case 'start':
      silentRetries = 0;
      lastAction = ev.data.action ?? '';
      lastCData = ev.data.cdata ?? '';
      void run(lastAction, lastCData);
      break;
    case 'finish':
      if (checkboxPrompt) {
        checkboxPrompt();
      } else if (finishWaiter) {
        const w = finishWaiter;
        finishWaiter = null;
        w(ev.data);
      } else {
        earlyFinish = ev.data;
      }
      break;
    case 'dismiss':
      root.querySelector<HTMLButtonElement>('dialog .close')?.click();
      break;
    case 'reset':
      generation++;
      stopWorkers();
      break;
  }
});

send('ready');
