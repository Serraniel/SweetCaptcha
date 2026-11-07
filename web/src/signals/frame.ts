// Standard-mode device checks, run inside the frame. These look for contradictions
// and automation markers, not identity: values are reduced to booleans, classes
// and keyed hashes. See docs/SIGNALS.md for the full register.
import { keyedHash } from '../shared/sha256.ts';
import { scanArtefacts } from './artefacts.ts';

function safe<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

const NATIVE = /\{\s*\[native code\]\s*\}\s*$/;
const fnToString = Function.prototype.toString;

function looksNative(fn: unknown): boolean {
  return typeof fn === 'function' && NATIVE.test(fnToString.call(fn));
}

function isProxied(fn: object): boolean {
  // Setting an ordinary object's prototype to something inheriting from itself is
  // a cycle and throws. The cycle check stops at a Proxy, so a Proxy-wrapped
  // function does not throw. The original prototype is restored straight away.
  const original = Object.getPrototypeOf(fn);
  try {
    Object.setPrototypeOf(fn, Object.create(fn));
    Object.setPrototypeOf(fn, original);
    return true;
  } catch {
    return false;
  }
}

function getter(proto: object, prop: string): unknown {
  return Object.getOwnPropertyDescriptor(proto, prop)?.get;
}

// Canvas, WebGL, audio and timezone functions are excluded on purpose: privacy
// extensions patch them for good reasons, and that must not count against a user.
function tamperChecks(engine: string): string[] {
  const out: string[] = [];
  const nav = navigator as Navigator & { permissions?: Permissions };
  const proto = Navigator.prototype;
  const targets: Array<[string, unknown]> = [
    ['toString', Function.prototype.toString],
    ['languages', getter(proto, 'languages')],
    ['platform', getter(proto, 'platform')],
    ['hardwareConcurrency', getter(proto, 'hardwareConcurrency')],
    ['userAgent', getter(proto, 'userAgent')],
    ['webdriver', getter(proto, 'webdriver')],
    ['query', nav.permissions?.query],
  ];
  for (const [name, fn] of targets) {
    if (fn === undefined) continue;
    if (!looksNative(fn)) out.push('native:' + name);
    else if (typeof fn === 'function' && safe(() => isProxied(fn), false)) out.push('proxy:' + name);
    else if (typeof fn === 'function' && name !== 'toString' && Object.prototype.hasOwnProperty.call(fn, 'prototype')) out.push('native:' + name);
  }
  for (const prop of ['webdriver', 'languages', 'platform', 'userAgent', 'hardwareConcurrency']) {
    if (Object.prototype.hasOwnProperty.call(nav, prop)) out.push(prop === 'webdriver' ? 'webdriver' : 'native:' + prop);
  }
  if ((engine === 'v8' || engine === 'spidermonkey') && !('webdriver' in nav)) out.push('webdriver');
  return out;
}

function engineFamily(): { family: string; evalLen: number } {
  const evalLen = safe(() => eval.toString().length, 0);
  const stack = safe(() => new Error('x').stack ?? '', '');
  let family = 'unknown';
  if (evalLen === 33 && stack.includes('    at ')) family = 'v8';
  else if (safe(() => CSS.supports('-moz-appearance', 'none'), false)) family = 'spidermonkey';
  else if (safe(() => CSS.supports('-webkit-touch-callout', 'none') || CSS.supports('-apple-pay-button-style', 'black'), false)) family = 'jsc';
  return { family, evalLen };
}

function hashes(nonce: string, win: Window): Record<string, string> {
  const n = win.navigator;
  const Dtf = (win as unknown as { Intl: typeof Intl }).Intl.DateTimeFormat;
  return {
    ua: keyedHash(nonce, n.userAgent),
    platform: keyedHash(nonce, n.platform),
    langs: keyedHash(nonce, (n.languages ?? []).join(',')),
    cores: keyedHash(nonce, String(n.hardwareConcurrency)),
    tz: keyedHash(nonce, new Dtf().resolvedOptions().timeZone ?? ''),
  };
}

function iframeHashes(nonce: string): Record<string, string> | null {
  const f = document.createElement('iframe');
  f.style.display = 'none';
  f.setAttribute('aria-hidden', 'true');
  document.body.append(f);
  try {
    return f.contentWindow ? hashes(nonce, f.contentWindow) : null;
  } catch {
    return null;
  } finally {
    f.remove();
  }
}

function workerHashes(nonce: string, url: string): Promise<Record<string, string> | null> {
  return new Promise((res) => {
    let w: Worker;
    try {
      w = new Worker(url);
    } catch {
      res(null);
      return;
    }
    const timer = setTimeout(() => {
      w.terminate();
      res(null);
    }, 1500);
    w.onmessage = (ev) => {
      clearTimeout(timer);
      w.terminate();
      res(ev.data);
    };
    w.onerror = () => {
      clearTimeout(timer);
      res(null);
    };
    w.postMessage(nonce);
  });
}

function gpu(): { gpu: string; gpuApi: string } {
  const canvas = document.createElement('canvas');
  const gl = (canvas.getContext('webgl') ?? canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
  if (!gl) return { gpu: 'none', gpuApi: 'unknown' };
  const info = gl.getExtension('WEBGL_debug_renderer_info');
  const renderer = String(gl.getParameter(info ? info.UNMASKED_RENDERER_WEBGL : gl.RENDERER) ?? '');
  gl.getExtension('WEBGL_lose_context')?.loseContext();
  const r = renderer.toLowerCase();
  const classes: Array<[RegExp, string]> = [
    [/swiftshader|llvmpipe|softpipe|software|microsoft basic/, 'software'],
    [/nvidia|geforce|quadro/, 'nvidia'], [/amd|radeon/, 'amd'], [/intel/, 'intel'], [/apple/, 'apple'],
    [/adreno/, 'adreno'], [/mali/, 'mali'], [/powervr/, 'powervr'],
  ];
  const vendor = classes.find(([re]) => re.test(r))?.[1] ?? 'other';
  const api = /direct3d|d3d/.test(r) ? 'd3d' : /metal/.test(r) ? 'metal' : /vulkan/.test(r) ? 'vulkan' : /opengl/.test(r) ? 'opengl' : 'unknown';
  return { gpu: vendor, gpuApi: api };
}

function canvasStable(): boolean {
  const draw = (): string => {
    const c = document.createElement('canvas');
    c.width = 60;
    c.height = 20;
    const x = c.getContext('2d');
    if (!x) return '';
    x.fillStyle = '#336';
    x.fillRect(2, 2, 40, 12);
    x.fillText('sc', 4, 12);
    return c.toDataURL();
  };
  return draw() === draw();
}

async function notificationLie(): Promise<boolean> {
  if (!('Notification' in window) || !navigator.permissions) return false;
  const status = await navigator.permissions.query({ name: 'notifications' as PermissionName });
  return Notification.permission === 'denied' && status.state === 'prompt';
}

async function uach(): Promise<unknown> {
  const data = (navigator as Navigator & { userAgentData?: { brands: Array<{ brand: string; version: string }>; mobile: boolean; platform: string } }).userAgentData;
  if (!data) return null;
  const chromium = data.brands.find((b) => /chromium|google chrome|microsoft edge/i.test(b.brand));
  return { chromiumMajor: chromium ? Number(chromium.version) : 0, mobile: data.mobile, platform: data.platform };
}

// A link people never see, which assistive technology skips because it is hidden
// and out of the tab order. Agents acting on a raw DOM snapshot may still use it.
let trapped = false;
function installTrap(): void {
  const a = document.createElement('a');
  a.className = 't';
  a.href = '#verify';
  a.textContent = 'Continue without verification';
  a.tabIndex = -1;
  a.setAttribute('aria-hidden', 'true');
  a.addEventListener('click', (e) => {
    e.preventDefault();
    trapped = true;
  });
  document.body.append(a);
}
installTrap();

function cdpObserved(): boolean {
  // Observed only and never scored: DevTools triggers it too, and its reliability
  // after the 2025 V8 changes is disputed.
  let hit = false;
  const e = new Error();
  Object.defineProperty(e, 'name', { get() { hit = true; return 'Error'; }, configurable: true });
  // eslint-disable-next-line no-console
  console.debug(e);
  return hit;
}

window.__sweetcaptchaCollect = async (nonce, workerUrl, page) => {
  const engine = engineFamily();
  const pointer = safe(() => (matchMedia('(pointer: fine)').matches ? 'fine' : matchMedia('(pointer: coarse)').matches ? 'coarse' : 'none'), 'none');
  const artefacts = new Set<string>(scanArtefacts());
  if (Array.isArray(page.artefacts)) for (const a of page.artefacts) artefacts.add(String(a));
  const [worker, ua, notifLie] = await Promise.all([
    workerHashes(nonce, workerUrl),
    uach().catch(() => null),
    notificationLie().catch(() => false),
  ]);
  return {
    v: 1,
    secure: isSecureContext,
    auto: { webdriver: navigator.webdriver === true, artefacts: [...artefacts] },
    tamper: safe(() => tamperChecks(engine.family), []),
    hash: hashes(nonce, window),
    worker,
    iframe: safe(() => iframeHashes(nonce), null),
    engine,
    uach: ua,
    device: {
      platform: navigator.platform,
      touch: navigator.maxTouchPoints ?? 0,
      pointer,
      screenZero: screen.width === 0 || screen.height === 0,
      windowZero: top === self ? window.outerWidth === 0 : false,
      langs: navigator.languages?.length ?? 0,
      canvasStable: safe(canvasStable, true),
      notifLie,
      ...safe(gpu, { gpu: 'none', gpuApi: 'unknown' }),
    },
    trap: trapped,
    cdp: safe(cdpObserved, false),
    beh: page.behaviour ?? null,
  };
};
