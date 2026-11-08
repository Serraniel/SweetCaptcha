import { scrypt } from './scrypt.ts';
import { firstWord } from './sha256.ts';

export interface PowParams {
  algo: 'sha256' | 'scrypt';
  bits: number;
  count: number;
  salt: string;
}

function decodeSalt(b64: string): Uint8Array {
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function leadingZeros(bytes: Uint8Array): number {
  let n = 0;
  for (const v of bytes) {
    if (v === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(v) - 24;
  }
  return n;
}

/**
 * Solves the given sub-puzzles, calling found for each solution. Work is split
 * across several workers by index, so each solves only its own share.
 */
export function solveIndices(p: PowParams, indices: number[], found: (index: number, nonce: number) => void): void {
  const salt = decodeSalt(p.salt);
  if (p.algo === 'sha256') {
    const view = new DataView(salt.buffer);
    const words = new Int32Array(4);
    for (let i = 0; i < 4; i++) words[i] = view.getInt32(i * 4);
    for (const i of indices) {
      let nonce = 0;
      while (Math.clz32(firstWord(words, i, nonce)) < p.bits) nonce = (nonce + 1) >>> 0;
      found(i, nonce);
    }
    return;
  }
  const input = new Uint8Array(salt.length + 8);
  input.set(salt);
  const view = new DataView(input.buffer);
  for (const i of indices) {
    view.setUint32(salt.length, i);
    let nonce = 0;
    for (;;) {
      view.setUint32(salt.length + 4, nonce);
      if (leadingZeros(scrypt(input, salt)) >= p.bits) break;
      nonce = (nonce + 1) >>> 0;
    }
    found(i, nonce);
  }
}

/** Solves every sub-puzzle in order. Used by tests. */
export function solve(p: PowParams, progress: (done: number) => void): number[] {
  const nonces: number[] = [];
  const all = Array.from({ length: p.count }, (_, i) => i);
  solveIndices(p, all, (i, nonce) => {
    nonces[i] = nonce;
    progress((i + 1) / p.count);
  });
  return nonces;
}
