// Fixture üretici: zararsız örnek programlar (scripts/lib/samples.js) JDK ya da Android SDK olmadan, doğrudan bayt
// olarak yazılır. Çıktı: test/fixtures/<ad>.<uzantı> + beklentiler (<ad>.json) ve arayüz örneği (src/sample-data.js).
// Üretim belirlenimcidir: aynı kod her zaman aynı baytları verir (test/fixtures.test.js bunu denetler).
//   node scripts/make-fixtures.js            yaz
//   node scripts/make-fixtures.js --check    yalnızca diskteki dosyalarla karşılaştır
import { writeFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { proguardJar, allatoriJar, zkmJar, stringerJar, dexguardApk, paramorphismJar, helloClass, libraryAar } from './lib/samples.js';

const root = new URL('../', import.meta.url);
const dir = new URL('test/fixtures/', root);

// expect: ayrıştırma çıktısında bulunmalı · java: sözde Java'da bulunmalı · gone: bulunmamalı · detect: tespit kimlikleri
// strings: çözülen dizge sayısı · failed: dokunulmadan bırakılan çağrı yeri · rewritten/verified: temiz çıktı ve doğrulama
// entries: temiz arşivde bulunmalı · removed: temiz arşivde bulunmamalı
export function fixtures() {
  const pg = proguardJar();
  return [
    { name: 'hello', ext: 'class', bytes: helloClass(), meta: { expect: ['ldc             "tick"', 'getstatic       demo/Hello.GREETING'], java: ['System.out.println(Hello.GREETING);', 'return p0 + p1;', 'if (v1 >= 3) goto L'], gone: [], detect: [], strings: 0, failed: 0, rewritten: true, verified: true } },
    { name: 'proguard', ext: 'jar', bytes: pg.jar, meta: { expect: ['class a.Class1', 'method1', 'strField1'], java: ['v1.method1("status")'], gone: ['invokevirtual   a/a.a:'], detect: ['proguard'], strings: 0, failed: 0, rewritten: true, verified: true, entries: ['a/Class1.class', 'com/example/app/Main.class'], removed: ['a/a.class'] } },
    { name: 'proguard-mapped', ext: 'jar', bytes: pg.jar, mapping: pg.mapping, meta: { expect: ['com.example.app.net.UpdateClient', 'com/example/app/net/UpdateClient.fetch:(Ljava/lang/String;)Ljava/lang/String;'], java: ['v2.execute();', 'this.endpoint = "https://api.peel-demo.invalid/v1/";', 'public void reset()'], gone: ['a/a.a:'], detect: ['proguard'], strings: 0, failed: 0, rewritten: true, verified: true, entries: ['com/example/app/net/UpdateClient.class', 'com/example/app/net/PingTask.class', 'com/example/app/net/Task.class'] } },
    { name: 'allatori', ext: 'jar', bytes: allatoriJar(), meta: { expect: ['"https://cdn.peel-demo.invalid/update.json"', '"Peel demo ready"', 'decryptString1'], java: ['System.out.println("Checking for updates...");'], gone: ['ALLATORIxDEMO'], detect: ['allatori', 'string-encryption'], strings: 4, failed: 0, rewritten: true, verified: true } },
    { name: 'zkm', ext: 'jar', bytes: zkmJar(), meta: { expect: ['"http://203.0.113.7:8080/beacon"', '"Connecting to config server"'], java: ['System.out.println("Done");', 'switch (v1 % 5)'], gone: ['aaload'], detect: ['zkm', 'string-encryption'], strings: 3, failed: 0, rewritten: true, verified: true, ips: ['203.0.113.7'] } },
    { name: 'stringer', ext: 'jar', bytes: stringerJar(), meta: { expect: ['"License check passed"', '"mailto:support@peel-demo.invalid"', 'invokestatic    com/peel/s/'], java: ['System.out.println("License check passed");'], gone: [], detect: ['stringer', 'indy-obfuscation', 'string-encryption'], strings: 2, failed: 1, rewritten: true, verified: true } },
    { name: 'dexguard', ext: 'apk', bytes: dexguardApk(), meta: { expect: ['const-string v3, "dalvik.system.DexClassLoader"', '"https://config.peel-demo.invalid/v1/flags"', '.super Landroid/app/Activity;'], java: ['v3 = "Welcome to the Peel demo";', 'System.loadLibrary(v3);'], gone: [], detect: ['dexguard', 'r8', 'string-encryption', 'reflection', 'native-code'], strings: 4, failed: 0, rewritten: false, verified: false, permissions: ['android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED'], threat: ['dynamic-loading', 'persistence'], native: ['lib/arm64-v8a/libpeelcore.so'] } },
    { name: 'paramorphism', ext: 'jar', bytes: paramorphismJar(), meta: { expect: ['"Paramorphism-style sample"'], java: [], gone: ['Main.do', ' if.'], detect: ['paramorphism', 'archive-tricks', 'generic-names'], strings: 0, failed: 0, rewritten: true, verified: true, entries: ['Main.class', 'META-INF/MANIFEST.MF'], removed: ['Main.class/', 'Junk.class', 'if.class'] } },
    { name: 'library', ext: 'aar', bytes: libraryAar(), meta: { expect: ['class a.Class1'], java: [], gone: [], detect: ['proguard'], strings: 0, failed: 0, rewritten: true, verified: true, entries: ['classes.jar', 'AndroidManifest.xml'], nested: { 'classes.jar': ['a/Class1.class'] }, permissions: ['android.permission.INTERNET'] } },
  ];
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const check = process.argv.includes('--check');
  mkdirSync(dir, { recursive: true });
  let diff = 0;
  const put = (url, data) => {
    const buf = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);
    if (check) { if (!existsSync(url) || !readFileSync(url).equals(buf)) { diff++; console.log(`farklı: ${url.pathname}`); } return; }
    writeFileSync(url, buf);
  };
  for (const f of fixtures()) {
    put(new URL(`${f.name}.${f.ext}`, dir), f.bytes);
    if (f.mapping) put(new URL(`${f.name}.mapping.txt`, dir), f.mapping);
    put(new URL(`${f.name}.json`, dir), `${JSON.stringify({ file: `${f.name}.${f.ext}`, ...(f.mapping ? { mapping: `${f.name}.mapping.txt` } : {}), ...f.meta }, null, 2)}\n`);
  }
  // arayüz örnekleri: APK ve JAR (base64, zararsız)
  const list = fixtures();
  const b64 = (n) => Buffer.from(list.find((f) => f.name === n).bytes).toString('base64');
  put(new URL('src/sample-data.js', root), `// scripts/make-fixtures.js üretir; elle düzenlemeyin. Zararsız örnekler (bkz. scripts/lib/samples.js).\nexport const SAMPLES = [\n  { name: 'PeelDemo.apk', data: '${b64('dexguard')}' },\n  { name: 'Launcher.jar', data: '${b64('allatori')}' },\n];\n`);
  // isteğe bağlı: JDK varsa üretilen sınıflar javap ile de okunur (çalışma zamanı bağımlılığı değildir)
  if (!check) {
    try {
      execFileSync('javap', ['-version'], { stdio: 'ignore' });
      execFileSync('javap', ['-c', new URL('hello.class', dir).pathname.replace(/^\/([A-Za-z]:)/, '$1')], { stdio: 'ignore' });
      console.log('javap: hello.class okundu');
    } catch { /* JDK yok: atlanır */ }
  }
  if (check) { console.log(diff ? `${diff} dosya farklı` : 'fixture dosyaları güncel'); process.exitCode = diff ? 1 : 0; } else console.log(`${list.length} fixture yazıldı`);
}
