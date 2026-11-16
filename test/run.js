// Fixture testleri: test/fixtures/* tam hattan (yükleme, geçişler, temiz çıktı, rapor) geçer. Beklentiler aynı adlı
// .json dosyasındadır (scripts/make-fixtures.js üretir):
//   expect  ayrıştırma çıktısında · java  sözde Java'da · gone  hiçbirinde olmamalı · detect  tespit kimlikleri
//   strings çözülen dizge · failed  dokunulmayan çağrı yeri · rewritten/verified  temiz arşiv ve yapısal doğrulama
//   entries/removed/nested  temiz arşivin içeriği · permissions/threat/native/ips  rapor alanları
//   node test/run.js              hepsi
//   node test/run.js zkm          tek fixture, günlük ve özetle (--code ile çıktı da)
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { peel } from '../src/index.js';
import { listZip, readEntry } from '../src/core/zip.js';

const dir = new URL('./fixtures/', import.meta.url);
const filter = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : null;
const files = readdirSync(dir).filter((f) => f.endsWith('.json') && (!filter || f.startsWith(filter))).sort();

const namesIn = (bytes) => listZip(bytes).entries.map((e) => e.name);
let pass = 0;
const t0 = Date.now();
for (const f of files) {
  const meta = JSON.parse(readFileSync(new URL(f, dir), 'utf8'));
  const bytes = new Uint8Array(readFileSync(new URL(meta.file, dir)));
  const mapping = meta.mapping && existsSync(new URL(meta.mapping, dir)) ? readFileSync(new URL(meta.mapping, dir), 'utf8') : null;
  const logs = [];
  const r = await peel(bytes, { name: meta.file, mapping, timeline: false, onLog: (m, l) => logs.push(`[${l}] ${m}`) });
  const fails = [];
  if (r.error) fails.push(`hata: ${r.error}`);
  const code = r.code ?? '';
  const java = r.java ?? '';
  for (const e of meta.expect) if (!code.includes(e)) fails.push(`EXPECT yok: ${e}`);
  for (const e of meta.java ?? []) if (!java.includes(e)) fails.push(`JAVA yok: ${e}`);
  for (const g of meta.gone) if (code.includes(g) || java.includes(g)) fails.push(`GONE duruyor: ${g}`);
  const ids = new Set(r.report?.detection.map((d) => d.id) ?? []);
  for (const d of meta.detect) if (!ids.has(d)) fails.push(`tespit yok: ${d} (var: ${[...ids].join(', ')})`);
  if ((r.report?.strings.decrypted ?? 0) !== meta.strings) fails.push(`dizge: ${r.report?.strings.decrypted} != ${meta.strings}`);
  if ((r.report?.strings.failed ?? 0) !== meta.failed) fails.push(`dokunulmayan: ${r.report?.strings.failed} != ${meta.failed}`);
  if (Boolean(r.rewritten) !== meta.rewritten) fails.push(`yeniden yazma: ${r.rewritten} != ${meta.rewritten}`);
  if (Boolean(r.verified) !== meta.verified) fails.push(`doğrulama: ${r.verified} != ${meta.verified}`);
  if (r.bytes && meta.ext !== 'class' && !meta.file.endsWith('.class')) {
    const names = namesIn(r.bytes);
    for (const e of meta.entries ?? []) if (!names.includes(e)) fails.push(`çıktı arşivinde yok: ${e}`);
    for (const e of meta.removed ?? []) if (names.includes(e)) fails.push(`çıktı arşivinde duruyor: ${e}`);
    for (const [inner, want] of Object.entries(meta.nested ?? {})) {
      const z = listZip(r.bytes).entries.find((e) => e.name === inner);
      const data = z && readEntry(r.bytes, z).data;
      const got = data ? namesIn(data) : [];
      for (const w of want) if (!got.includes(w)) fails.push(`${inner} içinde yok: ${w}`);
    }
    // temiz arşiv yeniden ayrıştırılabilmeli ve aynı sonucu vermeli
    const again = await peel(r.bytes, { name: meta.file, timeline: false });
    if (again.error) fails.push(`temiz arşiv açılamadı: ${again.error}`);
    else if (again.report.strings.sites !== meta.failed) fails.push(`temiz arşivde ${again.report.strings.sites} çözücü çağrısı kaldı`);
  }
  const perms = r.report?.manifest?.permissions.map((p) => p.name) ?? [];
  for (const p of meta.permissions ?? []) if (!perms.includes(p)) fails.push(`izin yok: ${p}`);
  const th = r.report?.threat.classes.map((c) => c.id) ?? [];
  for (const c of meta.threat ?? []) if (!th.includes(c)) fails.push(`tehdit sınıfı yok: ${c}`);
  const nat = r.report?.native.map((n) => n.path) ?? [];
  for (const n of meta.native ?? []) if (!nat.includes(n)) fails.push(`yerel kütüphane yok: ${n}`);
  for (const ip of meta.ips ?? []) if (!r.report?.iocs.ips.includes(ip)) fails.push(`IP yok: ${ip}`);
  if (r.events?.some((e) => e.state === 'fail')) fails.push(`başarısız geçiş: ${r.events.filter((e) => e.state === 'fail').map((e) => `${e.id} (${e.reason})`).join(', ')}`);
  if (!fails.length) pass++;
  console.log(`${fails.length ? 'FAIL' : 'ok  '} ${meta.file}${meta.mapping ? ' + mapping' : ''} (${r.ms ?? 0} ms)${fails.length ? `\n     ${fails.join('\n     ')}` : ''}`);
  if (filter) {
    console.log(logs.join('\n'));
    console.log(r.report?.summary ?? '');
    if (process.argv.includes('--code')) console.log(code);
    if (process.argv.includes('--java')) console.log(java);
  }
}
console.log(`\ntoplam ${Date.now() - t0}ms | ${pass}/${files.length}`);
if (pass !== files.length) process.exitCode = 1;
