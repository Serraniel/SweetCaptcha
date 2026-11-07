// Reports properties from inside a Web Worker. Script patches applied to a page
// often miss worker scopes, which is why comparing the two contexts is useful.
// Values are returned as keyed hashes. Standard mode only.
import { keyedHash } from '../shared/sha256.ts';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = (ev: MessageEvent<string>) => {
  const nonce = ev.data;
  const n = ctx.navigator;
  ctx.postMessage({
    ua: keyedHash(nonce, n.userAgent),
    platform: keyedHash(nonce, n.platform),
    langs: keyedHash(nonce, (n.languages ?? []).join(',')),
    cores: keyedHash(nonce, String(n.hardwareConcurrency)),
    tz: keyedHash(nonce, new Intl.DateTimeFormat().resolvedOptions().timeZone ?? ''),
  });
};
