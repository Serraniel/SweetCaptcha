// Builds the widget bundles into internal/assets/dist.
//
// core/ holds what every edition ships. signals/ holds the collectors, which the
// strict-only image does not embed. The two sets share no entry points, so
// collector code cannot reach a core bundle except through a shared module, and
// test/strict-audit.test.mjs checks the output for that.
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, '..', 'internal', 'assets', 'dist');

const sets = {
  core: {
    'api': 'src/loader/api.ts',
    'frame': 'src/frame/frame.ts',
    'worker': 'src/worker.ts',
  },
  signals: {
    'signals-frame': 'src/signals/frame.ts',
    'signals-page': 'src/signals/page.ts',
    'signals-worker': 'src/signals/worker.ts',
  },
};

for (const [set, entries] of Object.entries(sets)) {
  const out = join(dist, set);
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  await writeFile(join(out, '.gitkeep'), '');
  await build({
    entryPoints: Object.fromEntries(Object.entries(entries).map(([k, v]) => [k, join(root, v)])),
    bundle: true,
    minify: true,
    format: 'iife',
    target: ['es2020'],
    outdir: out,
    entryNames: '[name]-[hash]',
    legalComments: 'none',
    logLevel: 'warning',
    loader: { '.css': 'css' },
  });
  const manifest = {};
  for (const file of await readdir(out)) {
    const match = file.match(/^(.+)-[A-Z0-9]+\.(js|css)$/);
    if (!match) continue;
    const body = await readFile(join(out, file));
    manifest[`${match[1]}.${match[2]}`] = {
      path: file,
      sri: 'sha384-' + createHash('sha384').update(body).digest('base64'),
    };
  }
  await writeFile(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
}
