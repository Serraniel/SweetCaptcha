// The script host pages include. It renders frames and exposes the provider API
// that matches the path it was loaded from. It ships in every edition and reads
// no device properties. In standard mode the frame asks it to load a separate
// page collector. In strict mode that never happens, and the strict-only image
// does not contain that file.
import type { FrameMessage, HostMessage } from '../shared/protocol.ts';

type Fn = (...args: any[]) => void;

interface Options {
  sitekey: string;
  action?: string;
  cData?: string;
  cdata?: string;
  theme?: string;
  size?: string;
  tabindex?: number | string;
  language?: string;
  hl?: string;
  callback?: Fn | string;
  'expired-callback'?: Fn | string;
  'error-callback'?: Fn | string;
  'timeout-callback'?: Fn | string;
  execution?: string;
  appearance?: string;
  'response-field'?: boolean | string;
  'response-field-name'?: string;
  'refresh-expired'?: string;
}

const script = document.currentScript as HTMLScriptElement | null;
const scriptUrl = new URL(script?.src ?? location.href);
const origin = scriptUrl.origin;
const params = scriptUrl.searchParams;

type ProviderName = 'native' | 'recaptcha' | 'hcaptcha' | 'turnstile';

const providers: Record<ProviderName, { global: string; className: string; field: string; extraField?: string }> = {
  native: { global: 'sweetcaptcha', className: 'sweetcaptcha', field: 'sc-response' },
  recaptcha: { global: 'grecaptcha', className: 'g-recaptcha', field: 'g-recaptcha-response' },
  hcaptcha: { global: 'hcaptcha', className: 'h-captcha', field: 'h-captcha-response', extraField: 'g-recaptcha-response' },
  turnstile: { global: 'turnstile', className: 'cf-turnstile', field: 'cf-turnstile-response' },
};

function detectProvider(path: string): ProviderName {
  if (path.startsWith('/recaptcha/')) return 'recaptcha';
  if (path.startsWith('/turnstile/')) return 'turnstile';
  if (path.startsWith('/1/')) return 'hcaptcha';
  return 'native';
}

const providerName = detectProvider(scriptUrl.pathname);
const provider = providers[providerName];

function resolve(cb: Fn | string | undefined): Fn | undefined {
  if (typeof cb === 'function') return cb;
  if (typeof cb === 'string' && cb) {
    const found = cb.split('.').reduce<any>((o, k) => (o == null ? o : o[k]), window);
    if (typeof found === 'function') return found;
  }
  return undefined;
}

interface PageCollector {
  features(): unknown;
  artefacts(): string[];
  onInteract(fn: () => void): void;
}

declare global {
  interface Window {
    __sweetcaptchaPage?: PageCollector;
  }
}

let collectorLoad: Promise<void> | null = null;

function loadCollector(src: string, integrity: string): Promise<void> {
  collectorLoad ??= new Promise((res) => {
    const el = document.createElement('script');
    el.src = src;
    el.integrity = integrity;
    el.crossOrigin = 'anonymous';
    el.onload = () => res();
    el.onerror = () => res(); // The server treats missing evidence on its own terms.
    document.head.appendChild(el);
  });
  return collectorLoad;
}

// Verification waits briefly for the visitor's first input, so that the evidence
// includes some interaction. Without input, the server asks for the checkbox.
const NO_INPUT_FINISH_MS = 2500;
const AFTER_INPUT_FINISH_MS = 600;
const FRAME_LOAD_MS = 15000;

class Widget {
  readonly id: number;
  readonly opts: Options;
  readonly host: HTMLElement;
  readonly frame: HTMLIFrameElement;
  readonly invisible: boolean;
  readonly fields: HTMLInputElement[] = [];
  token = '';
  expired = false;
  private ready = false;
  private powReady = false;
  private finishing = false;
  private pendingStart: { action?: string; cdata?: string } | null = null;
  private pendingResolve: Array<(t: string) => void> = [];
  private pendingReject: Array<(e: Error) => void> = [];
  private pendingSubmit: { form: HTMLFormElement; submitter: HTMLElement | null } | null = null;
  private timers: number[] = [];
  private expiryTimer = 0;
  private onSubmit: ((e: SubmitEvent) => void) | null = null;
  private form: HTMLFormElement | null = null;
  private deferred: boolean;

  constructor(id: number, host: HTMLElement, opts: Options) {
    this.id = id;
    this.host = host;
    this.opts = opts;
    this.invisible = opts.size === 'invisible' || opts.appearance === 'execute';
    this.deferred = opts.execution === 'execute' || opts.size === 'invisible';
    this.frame = this.makeFrame();
    this.makeFields();
    this.bindForm();
    host.appendChild(this.frame);
    window.addEventListener('message', this.onMessage);
    this.timers.push(window.setTimeout(() => {
      if (!this.ready) this.fail('frame-timeout');
    }, FRAME_LOAD_MS));
  }

  private makeFrame(): HTMLIFrameElement {
    const f = document.createElement('iframe');
    const lang = this.opts.hl ?? this.opts.language ?? params.get('hl') ?? document.documentElement.lang ?? '';
    const q = new URLSearchParams({
      k: this.opts.sitekey,
      h: location.hostname,
      o: location.origin,
      l: lang,
      t: this.opts.theme ?? 'auto',
      s: this.opts.size ?? 'normal',
    });
    f.src = `${origin}/v1/frame?${q}`;
    f.title = 'Verification';
    f.setAttribute('allow', '');
    f.style.border = '0';
    f.style.overflow = 'hidden';
    if (this.opts.tabindex !== undefined) f.tabIndex = Number(this.opts.tabindex);
    if (this.invisible) {
      f.style.position = 'absolute';
      f.style.width = '1px';
      f.style.height = '1px';
      f.style.opacity = '0';
      f.setAttribute('aria-hidden', 'true');
      f.tabIndex = -1;
    } else if (this.opts.size === 'compact') {
      f.style.width = '150px';
      f.style.height = '140px';
    } else {
      f.style.width = this.opts.size === 'flexible' ? '100%' : '300px';
      f.style.height = '65px';
    }
    return f;
  }

  private makeFields(): void {
    const off = this.opts['response-field'] === false || this.opts['response-field'] === 'false';
    if (off) return;
    const names = [this.opts['response-field-name'] ?? provider.field];
    if (provider.extraField) names.push(provider.extraField);
    for (const name of names) {
      const el = document.createElement('input');
      el.type = 'hidden';
      el.name = name;
      if (!document.getElementById(name)) el.id = name;
      this.host.appendChild(el);
      this.fields.push(el);
    }
  }

  private bindForm(): void {
    this.form = this.host.closest('form');
    if (!this.form) return;
    // Capture on the form runs before the page's own submit handlers. The token
    // is minted at submit time, so the evidence covers the whole interaction.
    this.onSubmit = (e: SubmitEvent) => {
      if (this.token && !this.expired) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      this.pendingSubmit = { form: this.form!, submitter: e.submitter };
      this.requestFinish(true);
    };
    this.form.addEventListener('submit', this.onSubmit, true);
  }

  private get contentWindow(): Window | null {
    return this.frame.contentWindow;
  }

  private post(msg: Omit<HostMessage, 'sc'>): void {
    this.contentWindow?.postMessage({ sc: 1, ...msg }, origin);
  }

  private onMessage = (ev: MessageEvent): void => {
    if (ev.origin !== origin || ev.source !== this.contentWindow) return;
    const m = ev.data as FrameMessage;
    if (!m || m.sc !== 1) return;
    switch (m.type) {
      case 'ready':
        this.ready = true;
        if (!this.deferred || this.pendingStart) this.start();
        break;
      case 'collect':
        if (m.page) void loadCollector(new URL(m.page, origin).href, m.pageSri ?? '').then(() => this.armTriggers());
        break;
      case 'pow-ready':
        this.powReady = true;
        if (this.pendingSubmit || this.pendingResolve.length) this.requestFinish(true);
        else this.armIdle();
        break;
      case 'token':
        this.onToken(m.token ?? '', m.ttl ?? 300);
        break;
      case 'error':
        this.fail(m.code ?? 'error');
        break;
      case 'overlay':
        this.setOverlay(Boolean(m.on));
        // Closing a task cancels a held form submission. The visitor sends again.
        if (m.dismissed) this.pendingSubmit = null;
        break;
    }
  };

  private armTriggers(): void {
    window.__sweetcaptchaPage?.onInteract(() => {
      this.timers.push(window.setTimeout(() => this.requestFinish(), AFTER_INPUT_FINISH_MS));
    });
  }

  private armIdle(): void {
    this.timers.push(window.setTimeout(() => this.requestFinish(), NO_INPUT_FINISH_MS));
  }

  private start(action?: string, cdata?: string): void {
    const pending = this.pendingStart;
    this.pendingStart = null;
    this.finishing = false;
    this.powReady = false;
    this.post({
      type: 'start',
      action: action ?? pending?.action ?? this.opts.action ?? '',
      cdata: cdata ?? pending?.cdata ?? this.opts.cData ?? this.opts.cdata ?? '',
    });
  }

  requestFinish(user = false): void {
    if (!this.ready || this.token) return;
    if (this.finishing) {
      // The frame is waiting for the checkbox. When the visitor sends the form,
      // tell it, so that it can prompt or open the pending task.
      if (user) this.post({ type: 'finish', user });
      return;
    }
    if (!this.powReady) return;
    this.finishing = true;
    const page = window.__sweetcaptchaPage;
    this.post({ type: 'finish', behaviour: page?.features(), artefacts: page?.artefacts(), user });
  }

  execute(action?: string): Promise<string> {
    return new Promise((res, rej) => {
      this.pendingResolve.push(res);
      this.pendingReject.push(rej);
      this.clearToken();
      if (!this.ready) {
        this.pendingStart = { action };
        return;
      }
      this.start(action);
    });
  }

  private onToken(token: string, ttl: number): void {
    this.token = token;
    this.expired = false;
    this.setOverlay(false);
    for (const f of this.fields) f.value = token;
    this.clearTimers();
    window.clearTimeout(this.expiryTimer);
    this.expiryTimer = window.setTimeout(() => this.onExpire(), ttl * 1000);
    resolve(this.opts.callback)?.(token);
    for (const r of this.pendingResolve.splice(0)) r(token);
    this.pendingReject.length = 0;
    const submit = this.pendingSubmit;
    this.pendingSubmit = null;
    if (submit) {
      if (submit.form.requestSubmit) {
        const s = submit.submitter;
        if (s) submit.form.requestSubmit(s);
        else submit.form.requestSubmit();
      } else {
        submit.form.submit();
      }
    }
  }

  private onExpire(): void {
    this.expired = true;
    this.clearToken();
    resolve(this.opts['expired-callback'])?.();
    if (this.opts['refresh-expired'] !== 'never' && this.opts['refresh-expired'] !== 'manual' && !this.deferred) this.reset();
  }

  private clearToken(): void {
    this.token = '';
    for (const f of this.fields) f.value = '';
  }

  private clearTimers(): void {
    for (const t of this.timers) window.clearTimeout(t);
    this.timers.length = 0;
  }

  private fail(code: string): void {
    this.clearTimers();
    this.setOverlay(false);
    this.pendingSubmit = null;
    resolve(this.opts['error-callback'])?.(code);
    const err = new Error(code);
    for (const r of this.pendingReject.splice(0)) r(err);
    this.pendingResolve.length = 0;
  }

  // A task opens as a popup at the widget, not as a page-wide modal. It is placed
  // so that it stays inside the viewport, and it follows the page on scroll.
  private setOverlay(on: boolean): void {
    if (on && !this.popup) {
      this.popup = true;
      this.saved = this.frame.getAttribute('style') ?? '';
      const r = this.frame.getBoundingClientRect();
      // Keep the widget's space, so the page does not shift while the popup is open.
      this.host.style.minWidth = `${r.width}px`;
      this.host.style.minHeight = `${r.height}px`;
      Object.assign(this.frame.style, {
        position: 'fixed', zIndex: '2147483647', opacity: '1', border: '0', borderRadius: '12px',
        boxShadow: '0 12px 40px rgba(0,0,0,.3)', transform: 'none',
      });
      this.frame.removeAttribute('aria-hidden');
      this.frame.tabIndex = 0;
      this.place();
      window.addEventListener('resize', this.place);
      window.addEventListener('scroll', this.place, true);
      document.addEventListener('click', this.onOutside, true);
      this.frame.focus();
    } else if (!on && this.popup) {
      this.popup = false;
      window.removeEventListener('resize', this.place);
      window.removeEventListener('scroll', this.place, true);
      document.removeEventListener('click', this.onOutside, true);
      this.frame.setAttribute('style', this.saved);
      this.host.style.minWidth = '';
      this.host.style.minHeight = '';
      if (this.invisible) {
        this.frame.setAttribute('aria-hidden', 'true');
        this.frame.tabIndex = -1;
      }
    }
  }

  private popup = false;

  private place = (): void => {
    const margin = 8;
    const vw = document.documentElement.clientWidth;
    const vh = document.documentElement.clientHeight;
    const w = Math.min(440, vw - 2 * margin);
    const h = Math.min(660, vh - 2 * margin);
    const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(v, hi));
    const r = this.host.getBoundingClientRect();
    const visible = r.width > 0 && r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw;
    let left = (vw - w) / 2;
    let top = (vh - h) / 2;
    if (visible) {
      left = clamp(r.left, margin, vw - w - margin);
      if (r.top + h <= vh - margin) top = Math.max(r.top, margin);
      else if (r.bottom - h >= margin) top = r.bottom - h;
      else top = clamp(r.top, margin, vh - h - margin);
    }
    Object.assign(this.frame.style, { left: `${left}px`, top: `${top}px`, width: `${w}px`, height: `${h}px` });
  };

  private onOutside = (e: Event): void => {
    if (e.target !== this.frame) this.post({ type: 'dismiss' });
  };

  private saved = '';

  reset(): void {
    this.clearToken();
    this.clearTimers();
    this.setOverlay(false);
    window.clearTimeout(this.expiryTimer);
    this.post({ type: 'reset' });
    this.start();
  }

  remove(): void {
    this.clearTimers();
    this.setOverlay(false);
    window.clearTimeout(this.expiryTimer);
    window.removeEventListener('message', this.onMessage);
    if (this.form && this.onSubmit) this.form.removeEventListener('submit', this.onSubmit, true);
    this.frame.remove();
    for (const f of this.fields) f.remove();
  }
}

const widgets: Widget[] = [];
let nextId = 0;

function byId(id?: unknown): Widget | undefined {
  if (id === undefined || id === null) return widgets[0];
  if (typeof id === 'number' || typeof id === 'string') {
    const direct = widgets.find((w) => String(w.id) === String(id));
    if (direct) return direct;
    if (typeof id === 'string') {
      const el = document.querySelector(id);
      return widgets.find((w) => w.host === el);
    }
  }
  if (id instanceof Element) return widgets.find((w) => w.host === id);
  return undefined;
}

function datasetOptions(el: HTMLElement): Options {
  const d = el.dataset;
  const opts: Record<string, unknown> = { sitekey: d.sitekey ?? '' };
  const map: Record<string, string> = {
    action: 'action', cdata: 'cdata', theme: 'theme', size: 'size', tabindex: 'tabindex', language: 'language', hl: 'hl',
    callback: 'callback', expiredCallback: 'expired-callback', errorCallback: 'error-callback', timeoutCallback: 'timeout-callback',
    execution: 'execution', appearance: 'appearance', responseField: 'response-field',
    responseFieldName: 'response-field-name', refreshExpired: 'refresh-expired',
  };
  for (const [from, to] of Object.entries(map)) {
    if (d[from] !== undefined) opts[to] = d[from];
  }
  return opts as unknown as Options;
}

function render(container: string | HTMLElement, options: Partial<Options> = {}): number {
  const host = typeof container === 'string'
    ? (document.getElementById(container.replace(/^#/, '')) ?? document.querySelector<HTMLElement>(container))
    : container;
  if (!host) throw new Error('SweetCaptcha: container not found');
  const merged = { ...datasetOptions(host), ...options } as Options;
  if (!merged.sitekey) throw new Error('SweetCaptcha: sitekey is required');
  const w = new Widget(nextId++, host, merged);
  widgets.push(w);
  return w.id;
}

function bindButton(btn: HTMLElement, opts: Options): void {
  // <button class="g-recaptcha" data-sitekey data-callback> runs on click, and it
  // uses a hidden frame placed next to the button.
  const holder = document.createElement('span');
  btn.after(holder);
  const id = render(holder, { ...opts, size: 'invisible' });
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    void byId(id)?.execute(opts.action).catch(() => undefined);
  });
}

function autoRender(): void {
  document.querySelectorAll<HTMLElement>('.' + provider.className).forEach((el) => {
    if (widgets.some((w) => w.host === el) || el.dataset.scBound) return;
    el.dataset.scBound = '1';
    if (el.tagName === 'BUTTON' || el.tagName === 'INPUT') bindButton(el, datasetOptions(el));
    else render(el);
  });
}

const v3Keys = new Map<string, number>();

function v3Widget(key: string): number {
  let id = v3Keys.get(key);
  if (id === undefined) {
    const holder = document.createElement('div');
    document.body.appendChild(holder);
    id = render(holder, { sitekey: key, size: 'invisible', 'response-field': false });
    v3Keys.set(key, id);
  }
  return id;
}

function ready(fn: () => void): void {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => fn(), { once: true });
  else fn();
}

const common = {
  render,
  reset: (id?: unknown) => byId(id)?.reset(),
  getResponse: (id?: unknown) => byId(id)?.token ?? '',
  remove: (id?: unknown) => {
    const w = byId(id);
    if (!w) return;
    w.remove();
    widgets.splice(widgets.indexOf(w), 1);
  },
};

function buildApi(): Record<string, unknown> {
  switch (providerName) {
    case 'recaptcha':
      return {
        ...common,
        ready,
        // A string sitekey means v3. A widget ID, or nothing, means v2.
        execute(a?: unknown, b?: { action?: string }) {
          if (typeof a === 'string' && !byId(a)) {
            return byId(v3Widget(a))!.execute(b?.action);
          }
          return byId(a)?.execute();
        },
      };
    case 'hcaptcha':
      return {
        ...common,
        getRespKey: () => '',
        execute(a?: unknown, b?: { async?: boolean }) {
          const opt = (typeof a === 'object' && a !== null && !(a instanceof Element) ? a : b) as { async?: boolean } | undefined;
          const id = typeof a === 'object' && !(a instanceof Element) ? undefined : a;
          const p = byId(id)?.execute();
          if (opt?.async) return p?.then((response) => ({ response, key: '' }));
          p?.catch(() => undefined);
          return undefined;
        },
      };
    case 'turnstile':
      return {
        ...common,
        ready,
        isExpired: (id?: unknown) => byId(id)?.expired ?? true,
        execute(a?: unknown, opts?: Partial<Options>) {
          let w = byId(a);
          if (!w && a) {
            const id = render(a as string | HTMLElement, { ...opts, execution: 'execute' });
            w = byId(id);
          }
          w?.execute().catch(() => undefined);
        },
      };
    default:
      return {
        ...common,
        ready,
        execute: (id?: unknown, opts?: { action?: string }) => byId(id)?.execute(opts?.action),
      };
  }
}

(window as unknown as Record<string, unknown>)[provider.global] = buildApi();

ready(() => {
  const mode = params.get('render');
  if (mode !== 'explicit') {
    if (mode && mode !== 'onload') v3Widget(mode);
    autoRender();
  }
  const onload = params.get('onload');
  if (onload) resolve(onload)?.();
});
