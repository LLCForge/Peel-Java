// Motor ileti işleyicisi (Web Worker ve Node alt süreci ortak). Çağrılar durumsuzdur: her iletide dosya baytları gelir,
// bekçi süreci öldürse bile hat kaldığı yerden sürer. İleti türleri: ping | peel
import { peel } from '../index.js';

export function createEngine() {
  return {
    async handle(msg) {
      switch (msg.type) {
        case 'ping':
          return { ok: true };
        case 'peel': {
          const logs = [];
          const passes = [];
          const snapshots = [];
          const bytes = msg.bytes instanceof Uint8Array ? msg.bytes : Uint8Array.from(msg.bytes ?? []);
          const r = await peel(bytes, {
            name: String(msg.name ?? 'input.jar').slice(0, 300),
            mapping: typeof msg.mapping === 'string' ? msg.mapping : null,
            lang: msg.lang === 'en' ? 'en' : 'tr',
            only: Array.isArray(msg.only) ? msg.only : null,
            timeline: msg.timeline !== false,
            onLog: (m, level) => { if (logs.length < 2000) logs.push([m, level]); },
            onPass: (id, state) => passes.push([id, state]),
            onSnapshot: (s) => snapshots.push(s),
          });
          if (r.error) return { ok: false, error: r.error, logs, passes };
          return { ok: true, ...r, logs, passes, snapshots };
        }
        default:
          return { ok: false, error: `bilinmeyen ileti: ${msg.type}` };
      }
    },
  };
}
