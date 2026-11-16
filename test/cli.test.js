// CLI testleri: kullanım hataları, çıkış kodları, çıktı dosyaları (ayrıştırma, sözde Java, temiz JAR), mapping.txt,
// rapor biçimleri, dizin girdisi ve --fail-on.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseClass, thisName } from '../src/jvm/classfile.js';
import { listZip } from '../src/core/zip.js';

const BIN = fileURLToPath(new URL('../bin/peel-java.js', import.meta.url));
const FX = fileURLToPath(new URL('./fixtures/', import.meta.url));
const cli = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, timeout: 120_000 });

const tmp = mkdtempSync(join(tmpdir(), 'peel-java-cli-'));
try {
  // kullanım ve hata çıkış kodları
  assert.equal(cli(['-h']).status, 0);
  assert.match(cli(['--help', '--lang', 'en']).stdout.toString(), /Exit codes/);
  assert.equal(cli([]).status, 2);
  assert.equal(cli(['x.jar', '--lang', 'de']).status, 2);
  assert.equal(cli(['x.jar', '--fail-on', 'none']).status, 2);
  assert.equal(cli(['x.jar', '--only', 'strings,nope']).status, 2);
  assert.equal(cli(['x.jar', '--view', 'smali']).status, 2);
  assert.equal(cli(['x.jar', '--bogus']).status, 2);
  assert.equal(cli([join(tmp, 'yok.jar'), '-q']).status, 1);
  // tanınmayan girdi: hata (1), çökme yok
  let r = cli(['-', '-q'], Buffer.from('bu bir Java dosyası değil'));
  assert.equal(r.status, 1);

  // tek dosya: ayrıştırma stdout'a, özet stderr'e
  r = cli([join(FX, 'zkm.jar')]);
  assert.equal(r.status, 0, r.stderr.toString());
  assert.match(r.stdout.toString(), /ldc_w\s+"http:\/\/203\.0\.113\.7:8080\/beacon"/);
  assert.match(r.stderr.toString(), /Zelix KlassMaster/);

  // sözde Java + temiz JAR + JSON rapor dosyası
  const out = join(tmp, 'out.java.txt');
  const jar = join(tmp, 'clean.jar');
  const rep = join(tmp, 'report.json');
  r = cli([join(FX, 'allatori.jar'), '--view', 'java', '-o', out, '-j', jar, '-r', rep, '-q', '--lang', 'en']);
  assert.equal(r.status, 0, r.stderr.toString());
  assert.match(readFileSync(out, 'utf8'), /System\.out\.println\("Peel demo ready"\);/);
  const names = listZip(new Uint8Array(readFileSync(jar))).entries.map((e) => e.name);
  assert.ok(names.includes('com/peel/demo/Launcher.class'));
  const json = JSON.parse(readFileSync(rep, 'utf8'));
  assert.equal(json.ok, true);
  assert.equal(json.report.strings.decrypted, 4);
  assert.equal(json.report.lang, 'en');

  // mapping.txt
  r = cli([join(FX, 'proguard-mapped.jar'), '-m', join(FX, 'proguard-mapped.mapping.txt'), '-q']);
  assert.equal(r.status, 0);
  assert.match(r.stdout.toString(), /com\/example\/app\/net\/UpdateClient\.fetch/);

  // tek sınıf dosyası: temiz çıktı yine .class
  const cls = join(tmp, 'clean.class');
  r = cli([join(FX, 'hello.class'), '-j', cls, '-q']);
  assert.equal(r.status, 0);
  assert.equal(thisName(parseClass(new Uint8Array(readFileSync(cls)))), 'demo/Hello');

  // APK: temiz arşiv yok, uyarı; metin rapor stdout'a
  r = cli([join(FX, 'dexguard.apk'), '-j', join(tmp, 'x.apk'), '-r', 'text', '--lang', 'en']);
  assert.equal(r.status, 0);
  assert.ok(!existsSync(join(tmp, 'x.apk')));
  assert.match(r.stderr.toString(), /DEX\/APK is not rewritten/);
  assert.match(r.stdout.toString(), /Manifest: com\.peel\.demo/);

  // stdin + --json
  r = cli(['-', '--json', '-q'], readFileSync(join(FX, 'stringer.jar')));
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout.toString()).report.strings.failed, 1);

  // --fail-on: düşük eşik aşılır (APK'da açılışta başlama + dinamik yükleme), örnek JAR'da aşılmaz
  assert.equal(cli([join(FX, 'dexguard.apk'), '--fail-on', 'low', '-r', 'json', '-q']).status, 4);
  assert.equal(cli([join(FX, 'zkm.jar'), '--fail-on', 'low', '-r', 'json', '-q']).status, 0);

  // dizin girdisi: yapı korunur, rapor JSON dizisi, -o/-j kullanım hatası
  const dir = join(tmp, 'in');
  mkdirSync(join(dir, 'sub'), { recursive: true });
  copyFileSync(join(FX, 'zkm.jar'), join(dir, 'a.jar'));
  copyFileSync(join(FX, 'hello.class'), join(dir, 'sub', 'b.class'));
  copyFileSync(join(FX, 'zkm.json'), join(dir, 'ignored.json'));
  assert.equal(cli([dir, '-o', join(tmp, 'x')]).status, 2);
  const od = join(tmp, 'outdir');
  const rj = join(tmp, 'all.json');
  r = cli([dir, '-d', od, '-r', rj, '-q']);
  assert.equal(r.status, 0, r.stderr.toString());
  assert.deepEqual(readdirSync(od).sort(), ['a.disasm.txt', 'a.peeled.jar', 'sub']);
  assert.ok(existsSync(join(od, 'sub', 'b.disasm.txt')));
  assert.ok(existsSync(join(od, 'sub', 'b.peeled.class')));
  const arr = JSON.parse(readFileSync(rj, 'utf8'));
  assert.deepEqual(arr.map((e) => e.file), ['a.jar', 'sub/b.class']);
  console.log(`cli: ${arr.length} dosyalık dizin, çıkış kodları 0/1/2/4 doğrulandı`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
