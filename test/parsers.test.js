// Ayrıştırıcı testleri: sınıf dosyası (bayt bayt geri yazma), MUTF-8, JVM komut çözücü, DEX (tablolar, sağlama, kod,
// statik değerler, veri yükleri), Android ikili XML ve ZIP okuyucu.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseClass, writeClass, thisName, memberName, utf8, addString, parseMethodDesc, mapDesc, javaType } from '../src/jvm/classfile.js';
import { decode as decodeJvm } from '../src/jvm/opcodes.js';
import { decodeMutf8, encodeMutf8, adler32 } from '../src/core/bytes.js';
import { parseDex, methodsOf } from '../src/dex/dex.js';
import { decode as decodeDex, payloadAt } from '../src/dex/opcodes.js';
import { parseAxml, manifestSummary } from '../src/dex/axml.js';
import { listZip, readEntry } from '../src/core/zip.js';
import { loadProgram } from '../src/core/program.js';
import { buildDex } from '../scripts/lib/dexgen.js';
import { ClassBuilder } from '../scripts/lib/jasm.js';

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const entries = (zip) => listZip(zip).entries.filter((e) => !e.dir).map((e) => ({ name: e.name, data: readEntry(zip, e).data }));

// MUTF-8: NUL iki bayt, ek düzlem iki vekil
const tricky = 'a\u0000bç中\u{1f600}';
const enc = encodeMutf8(tricky);
assert.deepEqual([...enc.slice(1, 3)], [0xc0, 0x80], 'NUL C0 80 olmalı');
assert.equal(enc.length, 1 + 2 + 1 + 2 + 3 + 6);
assert.equal(decodeMutf8(enc), tricky);

// sınıf dosyaları: her fixture sınıfı bayt bayt geri yazılır, her yöntem gövdesi çözülür
let classes = 0;
let insns = 0;
for (const f of ['proguard.jar', 'allatori.jar', 'zkm.jar', 'stringer.jar', 'paramorphism.jar']) {
  for (const e of entries(fx(f))) {
    if (!e.name.endsWith('.class') || !e.data || e.data[0] !== 0xca) continue;
    let cf;
    try { cf = parseClass(e.data); } catch { continue; }
    assert.deepEqual(writeClass(cf), e.data, `${f}!${e.name} geri yazılınca aynı olmalı`);
    for (const m of cf.methods) if (m.code) insns += decodeJvm(m.code.code).length;
    classes++;
  }
}
const hello = fx('hello.class');
const hcf = parseClass(hello);
assert.equal(thisName(hcf), 'demo/Hello');
assert.deepEqual(writeClass(hcf), hello);
assert.deepEqual(hcf.methods.map((m) => memberName(hcf, m)), ['<init>', 'main', 'sum']);
// havuza ekleme eski indeksleri kaydırmaz, var olan değeri yeniden kullanır
const before = hcf.cp.length;
const idx = addString(hcf, 'yeni dizge');
assert.equal(idx, before + 1, 'Utf8 + String eklenmeli');
assert.equal(addString(hcf, 'yeni dizge'), idx, 'aynı dizge yeniden kullanılmalı');
assert.equal(utf8(hcf, hcf.cp[idx].index), 'yeni dizge');
assert.equal(parseClass(writeClass(hcf)).cp.length, hcf.cp.length);
assert.deepEqual(parseMethodDesc('(I[JLjava/lang/String;[[La/b;D)V'), { params: ['I', '[J', 'Ljava/lang/String;', '[[La/b;', 'D'], ret: 'V' });
assert.equal(mapDesc('(La/a;[La/b;Ljava/util/List<La/a;>;)La/c;', (n) => ({ 'a/a': 'x/Y', 'a/c': 'x/Z' })[n]), '(Lx/Y;[La/b;Ljava/util/List<Lx/Y;>;)Lx/Z;');
assert.equal(javaType('[[Ljava/lang/String;'), 'java.lang.String[][]');

// tableswitch dolgusu ve geniş komutlar
const sw = new ClassBuilder('t/Sw');
sw.method(9, 's', '(I)I', (a) => a.op('iload', 0).tableswitch(1, ['a', 'b'], 'd').label('a').iconst(10).op('ireturn').label('b').iconst(20).op('ireturn').label('d').iconst(-1).op('ireturn'));
const swCode = parseClass(sw.bytes()).methods[0].code.code;
const ts = decodeJvm(swCode).find((i) => i.name === 'tableswitch');
assert.deepEqual(ts.cases.map((c) => c[0]), [1, 2]);
assert.deepEqual([ts.pc, ts.len], [2, 1 + 1 + 12 + 8], 'tableswitch: işlem kodu + 1 bayt dolgu + başlık + 2 hedef');
assert.ok(ts.default > ts.cases[1][1]);

// DEX: tablolar, sağlama, kod, statik değerler
const apk = fx('dexguard.apk');
const dexEntry = entries(apk).find((e) => e.name === 'classes.dex');
const dex = parseDex(dexEntry.data);
assert.equal(dex.version, '035');
assert.ok(dex.checksumOk, 'Adler-32 tutmalı');
assert.equal(adler32(dexEntry.data, 12), new DataView(dexEntry.data.buffer, dexEntry.data.byteOffset).getUint32(8, true));
assert.deepEqual([...dex.strings].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)), dex.strings, 'dizgeler sıralı olmalı');
assert.equal(dex.classes.length, 5);
assert.ok(dex.strings.some((s) => s.startsWith('~~R8{')), 'R8 işareti');
const ob = dex.classes.find((c) => c.type === 'Lo/b;');
assert.deepEqual(ob.staticValues.map((v) => [v.type, v.value]), [['I', 9]]);
let dexInsns = 0;
for (const c of dex.classes) for (const m of methodsOf(c)) if (m.code) dexInsns += decodeDex(m.code.insns).length;
const clinit = methodsOf(dex.classes.find((c) => c.type === 'Lo/a;')).find((m) => dex.methods[m.idx].name === '<clinit>');
const fill = decodeDex(clinit.code.insns).find((i) => i.name === 'fill-array-data');
const pay = payloadAt(clinit.code.insns, fill.target);
assert.equal(pay.kind, 'array');
assert.equal(pay.width, 1);
assert.equal(pay.size, 101);
// üretici belirlenimci
const mk = () => buildDex([{ type: 'Lx/A;', superType: 'Ljava/lang/Object;', methods: [{ name: 'f', params: ['I'], ret: 'I', access: 9, registers: 1, ins: 1, code: (a) => a.op('return', 0) }] }]);
assert.deepEqual(mk(), mk());

// Android ikili XML
const man = parseAxml(entries(apk).find((e) => e.name === 'AndroidManifest.xml').data);
assert.match(man.xml, /<manifest .*package="com\.peel\.demo"/);
assert.match(man.xml, /android:name="\.MainActivity"/);
const sum = manifestSummary(man.root);
assert.equal(sum.package, 'com.peel.demo');
assert.equal(sum.versionName, '1.2.0');
assert.equal(sum.minSdk, '24');
assert.deepEqual(sum.permissions, ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.RECEIVE_BOOT_COMPLETED']);
assert.deepEqual(sum.components.map((c) => [c.kind, c.name, c.exported]), [['activity', 'com.peel.demo.MainActivity', true], ['receiver', 'com.peel.demo.BootReceiver', false]]);

// ZIP: Paramorphism hileleri görünür kalır
const para = listZip(fx('paramorphism.jar'));
assert.equal(para.entries.filter((e) => e.name === 'Main.class').length, 2);
assert.ok(para.entries.every((e) => e.name !== 'Main.class' || e.dup));
const prog = loadProgram(fx('paramorphism.jar'), 'paramorphism.jar');
assert.deepEqual(prog.tricks.classDirs, ['Main.class/']);
assert.deepEqual(prog.tricks.dupEntries, ['Main.class']);
assert.equal(prog.tricks.badClasses.length, 2, 'bozuk kopya ve Junk.class');
assert.deepEqual(prog.classes.map((c) => c.name).sort(), ['Main', 'if']);
// AAR: iç classes.jar açılır
const aar = loadProgram(fx('library.aar'), 'library.aar');
assert.equal(aar.kind, 'aar');
assert.ok(aar.classes.some((c) => c.path === 'classes.jar!/a/a.class'));
assert.deepEqual(aar.manifest.summary.permissions, ['android.permission.INTERNET']);

console.log(`parsers: ${classes} sınıf bayt bayt, ${insns} JVM komutu, DEX ${dex.classes.length} sınıf / ${dexInsns} komut, manifest ${sum.permissions.length} izin`);
