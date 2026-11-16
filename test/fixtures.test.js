// Fixture'lar belirlenimci olmalı: scripts/make-fixtures.js aynı baytları üretir; diskteki dosyalar ve arayüz örneği
// (src/sample-data.js) güncel olmalı.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { fixtures } from '../scripts/make-fixtures.js';

const a = fixtures();
const b = fixtures();
assert.equal(a.length, b.length);
for (let i = 0; i < a.length; i++) assert.deepEqual(a[i].bytes, b[i].bytes, `${a[i].name} belirlenimci değil`);
const r = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/make-fixtures.js', import.meta.url)), '--check'], { encoding: 'utf8' });
assert.equal(r.status, 0, `fixture dosyaları eski: ${r.stdout}${r.stderr} (npm run fixtures)`);
console.log(`fixtures: ${a.length} fixture belirlenimci ve güncel`);
