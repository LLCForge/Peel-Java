// Parmak izi ve rapor testleri: her gizleyici kendi fixture'ında tanınır, düz sınıfta hiçbir şey tanınmaz; tehdit,
// IOC, kripto, yansıma ve paketleyici kuralları; rapor metni ve özet iki dilde.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { peel } from '../src/index.js';
import { threat } from '../src/report/threat.js';
import { iocs } from '../src/report/iocs.js';
import { reportText } from '../src/report/text.js';
import { ClassBuilder } from '../scripts/lib/jasm.js';
import { writeZip } from '../src/core/zip.js';

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const ids = (r) => r.report.detection.map((d) => d.id);
const top = (r) => r.report.detection.filter((d) => d.kind === 'obfuscator').sort((a, b) => b.confidence - a.confidence)[0]?.id;

const want = { 'allatori.jar': 'allatori', 'zkm.jar': 'zkm', 'stringer.jar': 'stringer', 'dexguard.apk': 'dexguard', 'paramorphism.jar': 'paramorphism', 'proguard.jar': 'proguard' };
for (const [file, id] of Object.entries(want)) {
  const r = await peel(fx(file), { name: file, timeline: false });
  assert.equal(top(r), id, `${file}: en güçlü tespit ${id} olmalı (var: ${ids(r).join(', ')})`);
  const d = r.report.detection.find((x) => x.id === id);
  assert.ok(d.evidence.length > 0 && d.confidence >= 0.5, `${file}: kanıt ve güven`);
}
const hello = await peel(fx('hello.class'), { name: 'hello.class', timeline: false });
assert.deepEqual(ids(hello), [], 'düz sınıfta tespit olmamalı');
assert.equal(hello.report.threat.level, 'none');
const mapped = await peel(fx('proguard.jar'), { name: 'p.jar', mapping: readFileSync(new URL('./fixtures/proguard-mapped.mapping.txt', import.meta.url), 'utf8'), timeline: false });
assert.ok(mapped.report.detection.find((d) => d.id === 'proguard').evidence.some((e) => /mapping\.txt/.test(e)));

// APK raporu: manifest, yerel kütüphane, yansıma, çözülmüş dizgelerden IOC, okunurluk
const apk = await peel(fx('dexguard.apk'), { name: 'dexguard.apk', lang: 'en', timeline: false });
const rep = apk.report;
assert.equal(rep.manifest.package, 'com.peel.demo');
assert.ok(rep.manifest.permissions.every((p) => !p.dangerous), 'örnek tehlikeli izin istemez');
assert.deepEqual(rep.native.map((n) => [n.path, n.elf]), [['lib/arm64-v8a/libpeelcore.so', true]]);
assert.ok(rep.reflection.some((x) => x.kind === 'reflection' && x.api === 'java.lang.Class.forName'));
assert.ok(rep.reflection.some((x) => x.kind === 'native' && /loadLibrary/.test(x.api)));
assert.deepEqual(rep.iocs.urls, ['https://config.peel-demo.invalid/v1/flags'], 'IOC çözülmüş dizgeden gelmeli');
assert.ok(rep.threat.classes.some((c) => c.id === 'dynamic-loading' && c.evidence.some((e) => /DexClassLoader/.test(e))));
assert.ok(rep.readability.after > rep.readability.before);
assert.match(rep.summary, /Android app \(APK\) com\.peel\.demo/);
const text = reportText(rep, 'en');
for (const s of ['Detections:', 'Manifest: com.peel.demo 1.2.0', 'Native libraries:', 'String decryptors: 4/4', 'n/a (DEX is not rewritten)']) assert.ok(text.includes(s), `metin raporu: ${s}`);
const tr = await peel(fx('zkm.jar'), { name: 'zkm.jar', lang: 'tr', timeline: false });
assert.match(tr.report.summary, /Geri kazanılan: 3 dizge/);
assert.match(reportText(tr.report, 'tr'), /Yapısal doğrulama|yapısal doğrulama geçti/);

// tehdit kuralları: izin + API + dizge
const th = threat({
  manifest: { permissions: ['android.permission.SEND_SMS', 'android.permission.RECEIVE_BOOT_COMPLETED'], components: [{ kind: 'service', name: 'x.A', exported: true, permission: 'android.permission.BIND_ACCESSIBILITY_SERVICE', actions: [] }] },
  refs: new Map([['android/telephony/SmsManager.sendTextMessage', new Set(['x.B.run'])], ['java/lang/Runtime.exec', new Set(['x.C.go'])]]),
  strings: ['/system/xbin/su', 'https://discord.com/api/webhooks/1/abc'],
  iocs: { discordWebhooks: ['https://discord.com/api/webhooks/1/abc'], telegram: [] },
}, 'en');
assert.deepEqual(th.classes.map((c) => c.id).sort(), ['accessibility', 'exfiltration', 'persistence', 'process-exec', 'root', 'sms-send'].sort());
assert.equal(th.level, 'critical');
// IOC: sürüm numarası ve platform alanları gürültü değildir
const io = iocs(['http://10.0.0.5/x', 'https://schemas.android.com/apk/res/android', 'version 1.2.0.0', 'mail me: a.b@peel-demo.invalid']);
assert.deepEqual(io.ips, ['10.0.0.5']);
assert.deepEqual(io.benign, ['schemas.android.com']);
assert.deepEqual(io.emails, ['a.b@peel-demo.invalid']);

// kripto sabitleri ve paketleyici
const c = new ClassBuilder('k/Crypto');
c.field(0x19, 'IV', 'I', 0x67452301);
c.method(9, 'sbox', '()[B', (a) => {
  a.iconst(8).op('newarray', 8);
  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5].forEach((v, i) => a.op('dup').iconst(i).iconst((v << 24) >> 24).op('bastore'));
  a.op('areturn');
});
c.method(9, 'alg', '()Ljava/lang/String;', (a) => a.ldc('AES/CBC/PKCS5Padding').op('areturn'));
const cr = await peel(writeZip([['k/Crypto.class', c.bytes()], ['lib/armeabi-v7a/libjiagu.so', Uint8Array.of(0x7f, 0x45, 0x4c, 0x46)]]), { name: 'c.jar', timeline: false });
const cids = cr.report.crypto.map((x) => x.id);
for (const id of ['aes', 'md5-sha1', 'algo']) assert.ok(cids.includes(id), `kripto: ${id} (var: ${cids.join(', ')})`);
assert.ok(cr.report.protection?.product.includes('Jiagu'), 'paketleyici yalnızca raporlanır');
assert.ok(cr.report.detection.some((d) => d.kind === 'packer' && d.decodable === false));

console.log(`detect: ${Object.keys(want).length} gizleyici parmak izi, tehdit ${th.score}/100, kripto ${cids.length} sabit`);
