// Tarayıcı yolunun Node'daki taklidi: web-worker.js'teki ileti işleyicisi (engine.js) doğrudan kullanılır. Arayüz
// örnekleri (src/sample-data.js) çözülebilmeli, _headers kuralları ayrıştırılmalı ve worker CSP'si dış ağı kapatmalı.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createEngine } from '../src/sandbox/engine.js';
import { sandboxApi } from '../src/sandbox/api.js';
import { SAMPLES } from '../src/sample-data.js';
import { parseHeaders } from '../vite.config.js';

const engine = createEngine();
const sandbox = sandboxApi((msg) => engine.handle(msg));
await sandbox.ready();

const bytesOf = (b64) => Uint8Array.from(Buffer.from(b64, 'base64'));
assert.deepEqual(SAMPLES.map((s) => s.name), ['PeelDemo.apk', 'Launcher.jar']);
const apk = await sandbox.peel(bytesOf(SAMPLES[0].data), { name: SAMPLES[0].name, lang: 'en' });
assert.equal(apk.ok, true, apk.error);
assert.equal(apk.kind, 'apk');
assert.equal(apk.bytes, null, 'APK yeniden yazılmaz');
assert.match(apk.code, /const-string v3, "https:\/\/config\.peel-demo\.invalid\/v1\/flags"/);
assert.match(apk.java, /v3 = "dalvik\.system\.DexClassLoader";/);
assert.ok(apk.passes.some(([id, st]) => id === 'strings' && st === 'ok'));
assert.ok(apk.snapshots.length >= 1, 'zaman çizelgesi anlık görüntüleri');
assert.ok(apk.input.includes('Lo/a;->$(III)Ljava/lang/String;'), 'girdi görünümü özgün adları gösterir');
const jar = await sandbox.peel(bytesOf(SAMPLES[1].data), { name: SAMPLES[1].name });
assert.equal(jar.ok, true);
assert.ok(jar.bytes.length > 0);
assert.equal(jar.ext, '.jar');
assert.equal(jar.report.strings.decrypted, 4);
// sonuç yapılandırılmış klonlanabilir olmalı (postMessage)
structuredClone({ ...apk });
structuredClone({ ...jar });
// tanınmayan dosya: ok=false, hata metni
const bad = await sandbox.peel(new TextEncoder().encode('not java'), { name: 'x.bin' });
assert.equal(bad.ok, false);
assert.match(bad.error, /Tanınan bir biçim değil/);

// barındırma başlıkları
const rules = parseHeaders(readFileSync(new URL('../public/_headers', import.meta.url), 'utf8'));
const worker = rules.find((r) => r.path === '/assets/web-worker-*')?.headers['Content-Security-Policy'] ?? '';
assert.match(worker, /default-src 'none'/);
assert.match(worker, /connect-src 'self'/);
assert.doesNotMatch(worker, /unsafe-eval|unsafe-inline|wasm-unsafe-eval/);
const page = rules.find((r) => r.path === '/index.html')?.headers['Content-Security-Policy'] ?? '';
assert.ok(page.includes("frame-ancestors 'none'"));
assert.doesNotMatch(page, /script-src[^;]*unsafe/);
// manifest ve service worker
const manifest = JSON.parse(readFileSync(new URL('../public/manifest.webmanifest', import.meta.url), 'utf8'));
assert.deepEqual(manifest.icons.map((i) => i.src), ['peel-icon-512.png', 'peel-icon-1024.png', 'peel-icon.svg']);
assert.match(readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8'), /peel-java-v1/);
console.log(`web: örnek APK ${apk.code.split('\n').length} satır smali, JAR ${jar.bytes.length} bayt temiz arşiv, ${rules.length} başlık kuralı`);
