// Web Worker tarafı: çözme hattı (src/core/pipeline.js) burada çalışır; kilitlenirse ana thread'deki bekçi worker'ı
// sonlandırır.
//
// Yalıtım worker düzeyindedir:
//  1. CSP: worker betiğinin yanıt başlığı (dev/preview: vite.config.js ara katmanı, üretim: public/_headers)
//     default-src 'none'; script-src 'self'; connect-src 'self' (yalnızca aynı köken; kilitten sonra hiç ağ API'si yok)
//  2. JS kilidi: ilk iletiden önce ağ API'leri, eval/Function kurucuları, dizge zamanlayıcıları ve iç içe worker kaldırılır.
//     Başlık veremeyen barındırmada tek katman budur; durum ana thread'e 'env' iletisiyle bildirilir.
//  3. Dosyadaki kod hiçbir zaman çalıştırılmaz: çözücüler sınırlı bir bytecode yorumlayıcısında, yalnızca yan etkisiz
//     çekirdek API'lerle değerlendirilir (src/sandbox/runtime.js).
import { createEngine } from './engine.js';

// CSP sınaması: bu betiğin kendi yanıtı yeniden (aynı köken) okunur ve başlıkta default-src 'none' aranır
const cspProbe = fetch(self.location.href, { method: 'HEAD', cache: 'no-store' })
  .then((r) => /(^|;)\s*default-src 'none'\s*(;|$)/.test(r.headers.get('content-security-policy') ?? ''), () => false);

const BLOCKED = [
  'fetch', 'fetchLater', 'XMLHttpRequest', 'WebSocket', 'WebSocketStream', 'EventSource', 'WebTransport',
  'importScripts', 'Worker', 'SharedWorker', 'caches', 'BroadcastChannel', 'indexedDB',
];
const denied = () => { throw new EvalError('Peel sandbox: kod üretimi kapalı'); };

function lockdown() {
  const ctorProtos = [
    Function.prototype,
    Object.getPrototypeOf(async function () {}),
    Object.getPrototypeOf(function* () {}),
    Object.getPrototypeOf(async function* () {}),
  ];
  for (const name of BLOCKED) {
    for (let o = self; o; o = Object.getPrototypeOf(o)) {
      if (Object.prototype.hasOwnProperty.call(o, name)) {
        Object.defineProperty(o, name, { value: undefined, writable: false, configurable: false });
      }
    }
  }
  const BlockedFunction = function Function() { denied(); };
  BlockedFunction.prototype = Function.prototype;
  const freeze = (o, k, value) => Object.defineProperty(o, k, { value, writable: false, configurable: false });
  freeze(self, 'eval', denied);
  freeze(self, 'Function', BlockedFunction);
  for (const proto of ctorProtos) freeze(proto, 'constructor', BlockedFunction);
  for (const name of ['setTimeout', 'setInterval']) {
    const real = self[name];
    Object.defineProperty(self, name, {
      value: (fn, ...rest) => (typeof fn === 'function' ? real(fn, ...rest) : 0),
      writable: false,
      configurable: false,
    });
  }
}

const engine = createEngine();
const ready = cspProbe.then((csp) => {
  lockdown();
  self.postMessage({ type: 'env', csp, locked: true });
});

self.addEventListener('message', async ({ data }) => {
  const { id, ...msg } = data ?? {};
  await ready;
  let result;
  try {
    result = await engine.handle(msg);
  } catch (err) {
    result = { ok: false, error: String(err?.message ?? err).split('\n').filter(Boolean).slice(-3).join(' | ') };
  }
  self.postMessage({ id, ...result }, [result.bytes?.buffer].filter(Boolean));
});
