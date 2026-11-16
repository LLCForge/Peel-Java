// Sandbox testleri (Node): motor izin modeliyle yalıtılmış alt süreçte çalışır (yazma, alt süreç, ağ kapalı); son
// tarihi aşan istek bekçi tarafından kesilir ve sonraki istek yeni süreçte başarıyla çalışır.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createNodeSandbox } from '../src/sandbox/node-host.js';
import { limitsJar } from '../scripts/lib/samples.js';

const sb = createNodeSandbox();
try {
  const ping = await sb.ready();
  assert.equal(ping.isolation.fsWrite, false, 'alt süreç dosya yazamamalı');
  assert.equal(ping.isolation.child, false, 'alt süreç süreç başlatamamalı');
  if (ping.isolation.net !== null) assert.equal(ping.isolation.net, false, 'alt süreç ağa çıkamamalı');

  const bytes = new Uint8Array(readFileSync(new URL('./fixtures/zkm.jar', import.meta.url)));
  const r = await sb.peel(bytes, { name: 'zkm.jar', timeline: false });
  assert.equal(r.ok, true, r.error);
  assert.ok(r.bytes instanceof Uint8Array && r.bytes.length > 0);
  assert.equal(r.report.strings.decrypted, 3);
  assert.ok(r.logs.some(([m]) => /strings: tur 1/.test(m)));

  // bekçi: bütçeyi sonuna kadar kullanan çözücüler (~100 ms) 10 ms son tarihi aşar, süreç öldürülür
  const slow = await sb.peel(limitsJar(), { name: 'limits.jar', deadlineMs: 10 });
  assert.equal(slow.ok, false);
  assert.equal(slow.timedOut, true);
  assert.ok(sb.watchdogStats.timeouts >= 1);
  // sonraki istek yeni süreçte çalışır
  const again = await sb.peel(bytes, { name: 'zkm.jar', timeline: false });
  assert.equal(again.ok, true);
  assert.ok(sb.watchdogStats.restarts >= 1);
  // durdurma: uçuştaki iş hata alır
  const pending = sb.peel(bytes, { name: 'zkm.jar' });
  sb.kill('Durduruldu');
  assert.equal((await pending).ok, false);
  console.log(`sandbox: yalıtım ${JSON.stringify(ping.isolation)}, ${sb.watchdogStats.timeouts} zaman aşımı, ${sb.watchdogStats.restarts} yeniden başlatma`);
} finally {
  sb.close();
}
