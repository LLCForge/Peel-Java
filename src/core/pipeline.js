// Çözme hattı: yükle (ZIP/sınıf/DEX) → özgün ayrıştırma (girdi görünümü) → geçişler (strings, rename) → temiz çıktı
// (sınıf dosyaları ve JAR/AAR yeniden yazılır ve yeniden ayrıştırılarak doğrulanır; DEX yalnızca görünümde değişir) →
// ayrıştırma metni + sözde Java. Tarayıcıda Web Worker'da, Node'da worker thread'de ya da doğrudan çalışır.
import { loadProgram, mainClassOf } from './program.js';
import { parseMapping } from './mapping.js';
import { rewrite } from './rewrite.js';
import { PASSES } from './registry.js';
import { LIMITS } from './limits.js';
import { decryptJvm, decryptDex } from '../passes/strings.js';
import { planRename, applyToClass, looksReadable } from '../passes/rename.js';
import { collectFacts } from '../report/facts.js';
import { disassembleClass } from '../jvm/disasm.js';
import { pseudoClass } from '../jvm/pseudo.js';
import { smaliDex, pseudoDex } from '../dex/smali.js';
import { thisName } from '../jvm/classfile.js';

const IDENT = { cls: (n) => n, desc: (d) => d, method: (o, n) => n, field: (o, n) => n };

function cap(text) {
  if (text.length <= LIMITS.outputChars) return text;
  return `${text.slice(0, LIMITS.outputChars)}\n\n// Peel: output truncated at ${LIMITS.outputChars} characters (${text.length} in total). Use the CLI for the full output.\n`;
}

/** Ayrıştırma (ya da sözde Java) metni: sınıflar ada göre sıralı, sonra DEX sınıfları */
export function render(prog, { plan = IDENT, notes = new Map(), mode = 'disasm' } = {}) {
  const parts = [];
  const stats = { methods: 0, structured: 0, fallback: 0 };
  let size = 0;
  const classes = [...prog.classes].sort((a, b) => (thisName(a.cf) < thisName(b.cf) ? -1 : 1));
  for (const { cf } of classes) {
    if (size > LIMITS.outputChars) break;
    let t;
    try {
      if (mode === 'java') {
        const r = pseudoClass(cf);
        for (const k of Object.keys(stats)) stats[k] += r.stats[k];
        t = r.text;
      } else t = disassembleClass(cf);
    } catch (e) {
      t = `// ${thisName(cf)}: cannot display (${e.message})`;
    }
    size += t.length;
    parts.push(t);
  }
  for (const { path, dex } of prog.dexes) {
    if (size > LIMITS.outputChars) break;
    const head = `// ${path} · DEX ${dex.version} · ${dex.classes.length} classes${dex.checksumOk ? '' : ' · checksum mismatch'}`;
    try {
      if (mode === 'java') {
        const r = pseudoDex(dex, { plan, notes });
        for (const k of Object.keys(stats)) stats[k] += r.stats[k];
        parts.push(`${head}\n${r.text}`);
      } else parts.push(`${head}\n${smaliDex(dex, { plan, notes })}`);
    } catch (e) {
      parts.push(`${head}\n// cannot display (${e.message})`);
    }
    size += parts.at(-1).length;
  }
  return { text: cap(parts.join('\n\n')), stats };
}

/** Okunurluk puanı (0-100): okunur ad oranı ve çözülmüş dizge oranı */
export function readability(model, plan, strings) {
  let total = 0;
  let ok = 0;
  for (const c of model.values()) {
    const nn = plan.cls(c.name);
    total++;
    if (looksReadable(nn.slice(nn.lastIndexOf('/') + 1).replace(/^.*\$/, ''))) ok++;
    for (const m of c.methods) { if (m.name.startsWith('<')) continue; total++; if (looksReadable(plan.method(c.name, m.name, m.desc))) ok++; }
    for (const f of c.fields) { total++; if (looksReadable(plan.field(c.name, f.name, f.desc))) ok++; }
  }
  const names = total ? ok / total : 1;
  return Math.round(100 * (0.8 * names + 0.2 * strings));
}

/**
 * @param {Uint8Array} input
 * @param {{ name?: string, mapping?: string|null, only?: string[]|null, onLog?: Function, onPass?: Function,
 *           onSnapshot?: Function, signal?: AbortSignal|null, timeline?: boolean, views?: boolean }} o
 */
export async function deobfuscate(input, { name = 'input.jar', mapping = null, only = null, onLog = () => {}, onPass = () => {}, onSnapshot = () => {}, signal = null, timeline = true, views = true } = {}) {
  const t0 = Date.now();
  const log = (m, level = 'info') => onLog(m, level);
  const checkAbort = () => { if (signal?.aborted) throw new Error('Durduruldu'); };
  const events = [];
  const stats = {};
  let prog;
  try {
    prog = loadProgram(input, name);
  } catch (e) {
    return { error: e.message, events, stats };
  }
  const methods = prog.classes.reduce((s, c) => s + c.cf.methods.length, 0) + prog.dexes.reduce((s, d) => s + d.dex.methods.length, 0);
  log(`${name} · ${prog.kind} · ${prog.classes.length} sınıf dosyası, ${prog.dexes.length} DEX (${prog.dexes.reduce((s, d) => s + d.dex.classes.length, 0)} sınıf)`, 'info');
  for (const n of prog.notes.slice(0, 20)) log(n.msg, n.level);
  const map = mapping ? parseMapping(mapping) : null;
  if (map) log(`mapping.txt: ${map.classes.size} sınıf, ${map.methods.size} yöntem, ${map.fields.size} alan${map.errors ? `, ${map.errors} okunamayan satır` : ''}`, 'info');
  const facts0 = collectFacts(prog);
  const model0 = facts0.model;
  const inputText = views ? render(prog).text : '';
  checkAbort();

  const results = { strings: null, rename: null };
  let plan = IDENT;
  const notes = new Map();
  const want = (id) => !only || only.includes(id);
  for (const p of PASSES) {
    if (!want(p.id)) continue;
    checkAbort();
    const t = Date.now();
    onPass(p.id, 'run');
    try {
      let changed = false;
      if (p.id === 'strings') {
        const deadline = Date.now() + LIMITS.decryptMs;
        const j = prog.classes.length ? decryptJvm(prog, { log, deadline }) : null;
        const d = prog.dexes.length ? decryptDex(prog, { log, deadline }) : null;
        if (d) for (const [k, v] of d.notes) notes.set(k, v);
        results.strings = {
          strings: (j?.stats.strings ?? 0) + (d?.stats.strings ?? 0),
          sites: (j?.stats.sites ?? 0) + (d?.stats.sites ?? 0),
          decryptors: [...(j?.decryptors ?? []), ...(d?.decryptors ?? [])],
          failures: [...(j?.failures ?? []), ...(d?.failures ?? [])],
          values: [...(j?.values ?? []), ...(d?.values ?? [])],
        };
        for (const f of results.strings.failures.slice(0, 8)) log(`strings: ${f.where} → ${f.target}: ${f.reason} (dokunulmadı)`, 'warn');
        stats.strings = results.strings.strings;
        changed = stats.strings > 0;
      } else if (p.id === 'rename') {
        const keep = [...(prog.manifest?.summary?.components ?? []).map((c) => c.name), prog.manifest?.summary?.application, mainClassOf(prog)].filter(Boolean);
        const strs = [...facts0.strings, ...(results.strings?.values ?? []).map((v) => v.value)];
        plan = planRename(prog, { mapping: map, decryptors: results.strings?.decryptors ?? [], strings: strs, keepNames: keep });
        results.rename = plan.stats;
        if (plan.changed && prog.classes.length) {
          for (const c of prog.classes) c.name = applyToClass(c.cf, plan);
          prog.classMap = new Map(prog.classes.map((c) => [c.name, c.cf]));
        }
        stats.classes = plan.stats.classes;
        stats.methods = plan.stats.methods;
        stats.fields = plan.stats.fields;
        changed = plan.changed;
        if (changed) log(`rename: ${plan.stats.classes} sınıf, ${plan.stats.methods} yöntem, ${plan.stats.fields} alan (${map ? 'mapping.txt' : 'üretilmiş adlar'})${plan.stats.kept ? `, ${plan.stats.kept} ad korundu (manifest/yansıma/native)` : ''}`, 'info');
      }
      events.push({ id: p.id, round: 1, state: changed ? 'ok' : 'skip', ms: Date.now() - t });
      onPass(p.id, changed ? 'ok' : 'skip');
      if (changed && timeline && views) onSnapshot({ id: p.id, round: 1, code: render(prog, { plan, notes }).text });
    } catch (e) {
      log(`${p.id}: ${e.message}`, 'warn');
      events.push({ id: p.id, round: 1, state: 'fail', reason: e.message, ms: Date.now() - t });
      onPass(p.id, 'fail');
    }
  }
  checkAbort();

  // temiz çıktı: sınıf dosyası içeren girdiler yeniden yazılır (APK/DEX yazılmaz)
  let out = null;
  if (prog.classes.length && prog.kind !== 'apk' && prog.kind !== 'dex') {
    try {
      out = rewrite(prog, plan === IDENT ? null : plan);
      if (out.removed.length) log(`çıktıdan çıkarılan kayıtlar: ${out.removed.slice(0, 5).join(', ')}${out.removed.length > 5 ? ` (+${out.removed.length - 5})` : ''}`, 'info');
      for (const e of out.errors.slice(0, 5)) log(`doğrulama: ${e}`, 'warn');
    } catch (e) {
      log(`yeniden yazma başarısız: ${e.message}`, 'warn');
    }
  } else if (prog.dexes.length) log('DEX yeniden yazılmaz: çözülmüş dizgeler ve yeni adlar yalnızca ayrıştırma çıktısındadır', 'info');

  const code = views ? render(prog, { plan, notes }) : { text: '', stats: {} };
  const java = views ? render(prog, { plan, notes, mode: 'java' }) : { text: '', stats: {} };
  const s = results.strings;
  const undecoded = s ? s.sites - s.strings : 0;
  const before = readability(model0, IDENT, s?.sites ? 0 : 1);
  const after = readability(model0, plan, s?.sites ? 1 - undecoded / s.sites : 1);
  return {
    code: code.text,
    java: java.text,
    javaStats: java.stats,
    input: inputText,
    bytes: out?.bytes ?? null,
    ext: out?.ext ?? null,
    changed: Boolean(out) && (stats.strings > 0 || plan !== IDENT && plan.changed),
    verified: Boolean(out?.verified),
    rewritten: Boolean(out),
    removed: out?.removed ?? [],
    stats,
    events,
    prog,
    facts: facts0,
    results,
    mapping: map,
    readability: { before, after },
    ms: Date.now() - t0,
  };
}

