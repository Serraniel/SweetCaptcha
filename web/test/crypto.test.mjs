import assert from 'node:assert/strict';
import { createHash, scryptSync } from 'node:crypto';
import { test } from 'node:test';
import { scrypt } from '../src/shared/scrypt.ts';
import { firstWord, keyedHash, sha256 } from '../src/shared/sha256.ts';
import { solve } from '../src/shared/pow.ts';

const hex = (b) => Buffer.from(b).toString('hex');

test('sha256 matches the platform across block boundaries', () => {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
    const data = Buffer.alloc(len, 0x61);
    assert.equal(hex(sha256(data)), createHash('sha256').update(data).digest('hex'), `length ${len}`);
  }
});

test('firstWord is the first word of a full hash', () => {
  const salt = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const words = new Int32Array(4);
  for (let i = 0; i < 4; i++) words[i] = salt.readInt32BE(i * 4);
  const input = Buffer.concat([salt, Buffer.from('00000007', 'hex'), Buffer.from('0000abcd', 'hex')]);
  const expected = createHash('sha256').update(input).digest().readInt32BE(0);
  assert.equal(firstWord(words, 7, 0xabcd), expected);
});

test('scrypt matches the platform', () => {
  const password = Buffer.from('password-bytes');
  const salt = Buffer.from('salt-bytes');
  const expected = scryptSync(password, salt, 32, { N: 1024, r: 8, p: 1 });
  assert.equal(hex(scrypt(password, salt)), expected.toString('hex'));
});

test('keyedHash is stable and keyed', () => {
  assert.equal(keyedHash('n', 'v'), createHash('sha256').update('n:v').digest('hex').slice(0, 16));
  assert.notEqual(keyedHash('a', 'v'), keyedHash('b', 'v'));
});

test('solve produces valid sha256 nonces', () => {
  const salt = Buffer.alloc(16, 7);
  const nonces = solve({ algo: 'sha256', bits: 8, count: 3, salt: salt.toString('base64') }, () => {});
  nonces.forEach((nonce, i) => {
    const buf = Buffer.alloc(24);
    salt.copy(buf);
    buf.writeUInt32BE(i, 16);
    buf.writeUInt32BE(nonce, 20);
    assert.equal(createHash('sha256').update(buf).digest()[0], 0);
  });
});

test('solve produces valid scrypt nonces', () => {
  const salt = Buffer.alloc(16, 9);
  const [nonce] = solve({ algo: 'scrypt', bits: 2, count: 1, salt: salt.toString('base64') }, () => {});
  const buf = Buffer.alloc(24);
  salt.copy(buf);
  buf.writeUInt32BE(0, 16);
  buf.writeUInt32BE(nonce, 20);
  assert.ok(scryptSync(buf, salt, 32, { N: 1024, r: 8, p: 1 })[0] < 0x40);
});
