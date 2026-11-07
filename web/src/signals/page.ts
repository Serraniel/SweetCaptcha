// Standard-mode interaction features, run in the host page only when the server
// requests them. Coordinates and timings stay here: only counts and ratios leave,
// plus a short hash of a coarsely quantised path for replay detection. Key values
// are never read.
import { keyedHash } from '../shared/sha256.ts';
import { scanArtefacts } from './artefacts.ts';

interface Point { x: number; y: number; t: number; }

const MAX_POINTS = 400;
const TELEPORT_PX = 40;

const path: Point[] = [];
let moves = 0;
let coalescedTotal = 0;
let movesSinceClick = 0;
let last: Point | null = null;
// Where the pointer was before the current run of moves. A driver typically sends
// one move onto the target and then clicks, so the jump is measured from here.
let anchor: Point | null = null;
let clicks = 0;
let kbClicks = 0;
let noApproach = 0;
let keys = 0;
let lastKey = 0;
const keyGaps: number[] = [];
let pastes = 0;
let programmatic = 0;
let scrolls = 0;
let keySinceInput = 0;
let pasteSinceInput = 0;
let mode: 'mouse' | 'touch' | 'keyboard' | 'none' = 'none';
const started = performance.now();
const interactListeners: Array<() => void> = [];
let interacted = false;

function touched(): void {
  if (interacted) return;
  interacted = true;
  for (const fn of interactListeners) fn();
}

function setMode(next: 'mouse' | 'touch' | 'keyboard'): void {
  if (mode === 'none' || next !== 'keyboard') mode = next;
}

const opts = { capture: true, passive: true } as const;

document.addEventListener('pointermove', (e: PointerEvent) => {
  if (e.pointerType === 'touch') {
    setMode('touch');
    return;
  }
  setMode('mouse');
  moves++;
  movesSinceClick++;
  if (movesSinceClick > 2) anchor = last ?? anchor;
  coalescedTotal += e.getCoalescedEvents?.().length ?? 1;
  const p = { x: e.clientX, y: e.clientY, t: e.timeStamp };
  path.push(p);
  if (path.length > MAX_POINTS) path.shift();
  last = p;
  if (moves > 3) touched();
}, opts);

document.addEventListener('pointerdown', (e: PointerEvent) => {
  touched();
  if (e.pointerType !== 'mouse') {
    setMode(e.pointerType === 'touch' ? 'touch' : 'mouse');
    return;
  }
  setMode('mouse');
  const jump = anchor ? Math.hypot(e.clientX - anchor.x, e.clientY - anchor.y) : Infinity;
  // A click with no path leading to it. Moving, resting and then clicking is
  // normal, so a pause does not count. The pointer must have arrived in at most
  // two moves from somewhere else, or from nowhere at all.
  if (movesSinceClick < 3 && jump > TELEPORT_PX) noApproach++;
  movesSinceClick = 0;
  last = { x: e.clientX, y: e.clientY, t: e.timeStamp };
  anchor = last;
}, opts);

document.addEventListener('click', (e: MouseEvent) => {
  if (!e.isTrusted) {
    programmatic++;
    return;
  }
  clicks++;
  // Keyboard and many assistive-technology activations report detail 0.
  if (e.detail === 0) {
    kbClicks++;
    setMode('keyboard');
  }
}, opts);

document.addEventListener('keydown', (e: KeyboardEvent) => {
  touched();
  setMode('keyboard');
  if (e.repeat) return;
  keys++;
  keySinceInput++;
  if (lastKey) keyGaps.push(e.timeStamp - lastKey);
  if (keyGaps.length > 200) keyGaps.shift();
  lastKey = e.timeStamp;
}, opts);

document.addEventListener('paste', () => {
  touched();
  pastes++;
  pasteSinceInput++;
}, opts);

document.addEventListener('input', (e: Event) => {
  const ie = e as InputEvent;
  // Autofill and password managers replace text or fire plain events. Those are
  // ordinary, so only a typed-text insertion with no key or paste counts.
  if (ie.inputType === 'insertText' && keySinceInput === 0 && pasteSinceInput === 0) programmatic++;
  keySinceInput = 0;
  pasteSinceInput = 0;
}, opts);

document.addEventListener('scroll', () => {
  scrolls++;
}, opts);

document.addEventListener('wheel', touched, opts);
document.addEventListener('touchstart', touched, opts);
document.addEventListener('focusin', touched, opts);

function pathFeatures(): { straightness: number; speedCv: number; dirChanges: number; sketch: string } {
  const result = { straightness: 0, speedCv: 0, dirChanges: 0, sketch: '' };
  if (path.length < 8) return result;
  let total = 0;
  const speeds: number[] = [];
  let changes = 0;
  let lastAngle: number | null = null;
  for (let i = 1; i < path.length; i++) {
    const a = path[i - 1];
    const b = path[i];
    const d = Math.hypot(b.x - a.x, b.y - a.y);
    total += d;
    const dt = b.t - a.t;
    if (dt > 0 && dt < 200) speeds.push(d / dt);
    if (d > 2) {
      const angle = Math.atan2(b.y - a.y, b.x - a.x);
      if (lastAngle !== null) {
        const diff = Math.abs(Math.atan2(Math.sin(angle - lastAngle), Math.cos(angle - lastAngle)));
        if (diff > Math.PI / 4) changes++;
      }
      lastAngle = angle;
    }
  }
  const first = path[0];
  const end = path[path.length - 1];
  result.straightness = total > 0 ? Math.hypot(end.x - first.x, end.y - first.y) / total : 0;
  result.dirChanges = changes;
  if (speeds.length > 1) {
    const mean = speeds.reduce((s, v) => s + v, 0) / speeds.length;
    const variance = speeds.reduce((s, v) => s + (v - mean) ** 2, 0) / speeds.length;
    result.speedCv = mean > 0 ? Math.sqrt(variance) / mean : 0;
  }
  if (path.length >= 30) {
    const parts: string[] = [];
    for (let i = 0; i < 16; i++) {
      const p = path[Math.floor((i * (path.length - 1)) / 15)];
      parts.push(`${Math.round((p.x - first.x) / 16)},${Math.round((p.y - first.y) / 16)}`);
    }
    result.sketch = keyedHash('sketch', parts.join(';'));
  }
  return result;
}

function median(values: number[]): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

function coefficientOfVariation(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  if (mean === 0) return 0;
  return Math.sqrt(values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length) / mean;
}

window.__sweetcaptchaPage = {
  onInteract(fn: () => void) {
    if (interacted) fn();
    else interactListeners.push(fn);
  },
  artefacts: scanArtefacts,
  features() {
    return {
      mode,
      moves,
      clicks,
      kbClicks,
      noApproach,
      keys,
      keyMedianMs: median(keyGaps),
      keyCv: coefficientOfVariation(keyGaps),
      pastes,
      programmatic,
      scrolls,
      dwellMs: Math.round(performance.now() - started),
      coalescedMean: moves ? coalescedTotal / moves : 0,
      ...pathFeatures(),
    };
  },
};
