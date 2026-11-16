// Peel-Java kütüphane API'si. Saf JavaScript: Node'da ve tarayıcıda aynı kod çalışır. Çözücüler sınırlı, yan etkisiz bir
// bytecode yorumlayıcısında çalıştırılır; hiçbir örnek kodu gerçek JVM ya da ART üzerinde çalıştırılmaz.
//   import { peel } from 'peel-java';
//   const r = await peel(readFileSync('app.jar'), { name: 'app.jar' });   // r.code, r.java, r.bytes (temiz JAR), r.report
import { deobfuscate as runPipeline } from './core/pipeline.js';
import { analyze as runAnalyze } from './core/analyze.js';
import { PASSES } from './core/registry.js';

const toBytes = (input) => {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new TypeError('girdi Uint8Array ya da ArrayBuffer olmalı (.class, .jar, .apk, .aar, .dex baytları)');
};

// iç model (prog, facts) yalnızca rapor üretimi için; dışarı düz veri verilir
function plain(r) {
  const { prog, facts, results, mapping, ...rest } = r;
  return { ...rest, kind: prog?.kind ?? null, strings: results?.strings ?? null, rename: results?.rename ?? null };
}

/** Yalnızca çözme: { code (ayrıştırma), java (sözde Java), bytes (temiz JAR/sınıf ya da null), stats, events, ... } */
export async function deobfuscate(input, options = {}) {
  const r = await runPipeline(toBytes(input), options);
  return r.error ? r : plain(r);
}

/** Çözme + analiz raporu */
export async function peel(input, { lang = 'tr', ...options } = {}) {
  const bytes = toBytes(input);
  const r = await runPipeline(bytes, options);
  if (r.error) return { ...r, report: null };
  const report = runAnalyze(r, { inBytes: bytes.length, lang });
  return { ...plain(r), report };
}

export const analyze = runAnalyze;
export const passes = () => PASSES.map(({ id, title }) => ({ id, title }));
