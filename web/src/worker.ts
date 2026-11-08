// Solves proof of work off the main thread, so the page stays responsive. This
// file ships in every edition and must not read any device property.
import { solveIndices, type PowParams } from './shared/pow.ts';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = (ev: MessageEvent<{ params: PowParams; indices: number[] }>) => {
  try {
    solveIndices(ev.data.params, ev.data.indices, (index, nonce) => ctx.postMessage({ index, nonce }));
    ctx.postMessage({ done: true });
  } catch (e) {
    // Most often an allocation failure on a low-memory or 32-bit device. The
    // frame then retries with fewer workers, using the same algorithm.
    ctx.postMessage({ error: String(e) });
  }
};
