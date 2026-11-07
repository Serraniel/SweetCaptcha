// Solves proof of work off the main thread, so the page stays responsive. This
// file ships in every edition and must not read any device property.
import { solve, type PowParams } from './shared/pow.ts';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = (ev: MessageEvent<PowParams>) => {
  const nonces = solve(ev.data, (done) => ctx.postMessage({ progress: done }));
  ctx.postMessage({ nonces });
};
