// Sınır ve sandbox testleri: zip bombası, yalan boyutlar, dev sabit havuzu, bozuk DEX/AXML, sonsuz döngü, sınırsız
// özyineleme ve büyüyen bellek. Hiçbiri süreci kilitlememeli ya da çökertmemeli; rastgele bozulmuş girdiler de.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deflateSync } from 'fflate';
import { peel } from '../src/index.js';
import { listZip, readEntry, writeZip } from '../src/core/zip.js';
import { parseClass } from '../src/jvm/classfile.js';
import { parseDex } from '../src/dex/dex.js';
import { parseAxml } from '../src/dex/axml.js';
import { ParseError, Writer } from '../src/core/bytes.js';
import { LIMITS } from '../src/core/limits.js';
import { rawZip } from '../scripts/lib/rawzip.js';
import { limitsJar } from '../scripts/lib/samples.js';

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const timed = async (fn) => { const t = Date.now(); const r = await fn(); return [r, Date.now() - t]; };

// zip bombası: 64 MB sıfır ~64 KB'a sıkışır (oran > 400), açılmamalı
const zeros = deflateSync(new Uint8Array(LIMITS.zipEntryBytes), { level: 9 });
const bomb = new Writer(true);
const name = new TextEncoder().encode('a/Bomb.class');
bomb.u4(0x04034b50).u2(20).u2(0).u2(8).u2(0).u2(0x21).u4(0).u4(zeros.length).u4(LIMITS.zipEntryBytes).u2(name.length).u2(0).bytes(name).bytes(zeros);
const cd = bomb.pos;
bomb.u4(0x02014b50).u2(20).u2(20).u2(0).u2(8).u2(0).u2(0x21).u4(0).u4(zeros.length).u4(LIMITS.zipEntryBytes).u2(name.length).u2(0).u2(0).u2(0).u2(0).u4(0).u4(0).bytes(name);
const cdLen = bomb.pos - cd;
bomb.u4(0x06054b50).u2(0).u2(0).u2(1).u2(1).u4(cdLen).u4(cd).u2(0);
const bz = bomb.done();
const be = listZip(bz).entries[0];
assert.match(readEntry(bz, be).error, /oran/);
const [br, bms] = await timed(() => peel(bz, { name: 'bomb.jar', timeline: false }));
assert.ok(br.error, 'yalnızca bomba içeren arşiv: hata, çökme yok');
assert.ok(bms < 3000, `bomba hızlı reddedilmeli (${bms} ms)`);
// bildirilen boyut sınırın üstünde
assert.match(readEntry(bz, { ...be, size: LIMITS.zipEntryBytes + 1 }).error, /çok büyük/);
// toplam bütçe
assert.match(readEntry(bz, { ...be, size: 2000, csize: 1000 }, { left: 10 }).error, /toplam/);

// dev sabit havuzu bildirimi, kısa dosya: hızlı ParseError
const fake = new Uint8Array(16);
fake.set([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0xff, 0xff, 1, 0xff, 0xff]);
assert.throws(() => parseClass(fake), ParseError);
assert.throws(() => parseClass(Uint8Array.of(0xca, 0xfe, 0xba, 0xbe)), ParseError);

// bozuk DEX: tablo boyutları dosyayı aşıyor
const dex = new Uint8Array(0x70);
dex.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0]);
const dv = new DataView(dex.buffer);
dv.setUint32(0x24, 0x70, true);
dv.setUint32(0x28, 0x12345678, true);
dv.setUint32(0x38, 0x0fffffff, true);
dv.setUint32(0x3c, 0x70, true);
assert.throws(() => parseDex(dex), ParseError);
// bozuk AXML
assert.throws(() => parseAxml(Uint8Array.of(3, 0, 8, 0, 0xff, 0xff, 0, 0, 1, 0, 28, 0, 0xff, 0xff, 0xff, 0x7f)), ParseError);

// yorumlayıcı bütçeleri: sonsuz döngü, sınırsız özyineleme, büyüyen dizge
const [lr, lms] = await timed(() => peel(limitsJar(), { name: 'limits.jar', timeline: false }));
const reasons = lr.report.strings.decryptors.map((d) => `${d.name}: ${d.reasons.join('; ')}`);
assert.equal(lr.report.strings.decrypted, 0);
assert.equal(lr.report.strings.failed, 3);
assert.ok(reasons.some((r) => /^spin: .*(komut bütçesi|süre sınırı)/.test(r)), reasons.join(' | '));
assert.ok(reasons.some((r) => /^deep: .*derinli/.test(r)), reasons.join(' | '));
assert.ok(reasons.some((r) => /^grow: .*bellek/.test(r)), reasons.join(' | '));
assert.ok(lms < 10_000, `bütçeler süreyi sınırlamalı (${lms} ms)`);
assert.ok(lr.verified, 'çözülemeyen çağrılar dokunulmadan kalır, arşiv geçerli');

// rastgele bozulmuş girdiler: hiçbir durumda yakalanmamış istisna ya da kilitlenme yok
let seed = 12345;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
let handled = 0;
const t0 = Date.now();
for (const f of ['hello.class', 'zkm.jar', 'dexguard.apk', 'allatori.jar']) {
  const base = fx(f);
  for (let k = 0; k < 40; k++) {
    const b = base.slice();
    for (let n = 0; n < 1 + (rnd() % 8); n++) b[rnd() % b.length] = rnd() & 0xff;
    const r = await peel(b, { name: f, timeline: false });
    assert.ok(r.error || r.report, `${f} #${k}: sonuç ya da hata dönmeli`);
    handled++;
  }
}
assert.ok(Date.now() - t0 < 60_000);
// boş ve tanınmayan girdiler
assert.match((await peel(new Uint8Array(0), {})).error, /Tanınan bir biçim değil/);
assert.match((await peel(writeZip([['readme.txt', new TextEncoder().encode('hi')]]), {})).error, /sınıf ya da DEX yok/);
assert.ok((await peel(rawZip([['x.class', Uint8Array.of(1, 2, 3)]]), {})).error);

console.log(`limits: bomba ${bms} ms'de reddedildi, bütçeler ${lms} ms, ${handled} bozuk girdi güvenle işlendi`);
