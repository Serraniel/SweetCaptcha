// Static half of the strict-mode guarantee: the bundles every edition ships must
// not contain device reads, storage, or interaction telemetry. The browser half is
// in lab/, which instruments these APIs at runtime and watches the network.
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const core = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'internal', 'assets', 'dist', 'core');

const FORBIDDEN = [
  'navigator', 'userAgent', 'hardwareConcurrency', 'deviceMemory', 'screen.', 'outerWidth', 'innerWidth',
  'getContext', 'toDataURL', 'WebGL', 'AudioContext', 'OfflineAudio', 'localStorage', 'sessionStorage',
  'indexedDB', 'document.cookie', 'pointermove', 'mousemove', 'keydown', 'keyup', 'touchstart', 'deviceorientation',
  'performance.', 'Date.now', 'getTimezoneOffset', 'timeZone', 'getBattery', 'enumerateDevices', 'matchMedia',
];

test('core bundles contain no device reads, storage or telemetry', { skip: !existsSync(core) }, () => {
  const files = readdirSync(core).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 3, 'core bundles are missing; run npm run build first');
  for (const file of files) {
    const body = readFileSync(join(core, file), 'utf8');
    for (const word of FORBIDDEN) {
      assert.ok(!body.includes(word), `${file} contains "${word}"`);
    }
  }
});
