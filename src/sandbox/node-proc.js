// Yalıtılmış alt süreç: node --permission ile başlatılır (ağ, alt süreç, worker, dosya yazma kapalı; okuma yalnızca
// src/ ve fflate). Çözücüler burada, sınırlı yorumlayıcıda çalışır; kilitlenirse bekçi süreci öldürüp yenisini başlatır.
import { createEngine } from './engine.js';

const engine = createEngine();

process.on('message', async ({ id, ...msg }) => {
  let result;
  try {
    result = await engine.handle(msg);
    // yalıtım kanıtı (testler denetler): izin modeli etkin, yazma ve alt süreç kapalı
    if (msg.type === 'ping') result.isolation = { fsWrite: process.permission?.has('fs.write') ?? null, child: process.permission?.has('child') ?? null, net: process.permission?.has('net') ?? null };
  } catch (err) {
    result = { ok: false, error: String(err?.message ?? err).split('\n').slice(0, 3).join(' | ') };
  }
  process.send({ id, ...result });
});
process.send({ ready: true });
