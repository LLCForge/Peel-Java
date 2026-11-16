// Dizge çözme geçişi. Arşivdeki statik bir yönteme yalnızca sabit argümanlarla yapılan ve String döndüren çağrılar
// (ldc "x"; invokestatic C.f(String)String, sipush..; invokestatic C.f(II)String ...) ile statik String[] tablosundan
// sabit indisle okumalar (getstatic C.z; iconst_1; aaload) bulunur, sınırlı yorumlayıcıda çalıştırılır ve sonuç sabit
// olarak yazılır. Sınıf dosyalarında çağrı dizisi "ldc_w sonuç" + nop ile değiştirilir (konumlar, dallar, StackMapTable
// ve istisna tabloları kaymaz). DEX'te çağrı yeri ayrıştırma çıktısında işaretlenir (DEX yeniden yazılmaz).
// Yorumlayıcının bilmediği bir şeye ulaşan çözücü (G/Ç, yansıma, yığın izi, nesne alanı...) değiştirilmez, raporlanır.
import { decode as decodeJvm, leaders as jvmLeaders, OP } from '../jvm/opcodes.js';
import { ref, constant, parseMethodDesc, memberName, thisName, addString } from '../jvm/classfile.js';
import { createJvm, Unsupported, BudgetExceeded } from '../jvm/interp.js';
import { decode as decodeDex, payloadAt, isDalvikTerminal } from '../dex/opcodes.js';
import { createDalvik } from '../dex/interp.js';
import { methodsOf } from '../dex/dex.js';
import { JavaThrow } from '../sandbox/runtime.js';
import { LIMITS } from '../core/limits.js';

const STR = 'Ljava/lang/String;';
const OK_PARAMS = new Set([STR, 'Ljava/lang/Object;', 'I', 'S', 'B', 'C', 'Z', 'J']);
const MAX_ROUNDS = 4;

// sabit yükleyen JVM komutunun değeri: { cat: 'int'|'long'|'str', value }
function constOf(cf, ins) {
  const op = ins.op;
  if (op >= OP.iconst_m1 && op <= OP.iconst_5) return { cat: 'int', value: op - OP.iconst_0 };
  if (op === OP.bipush || op === OP.sipush) return { cat: 'int', value: ins.value };
  if (op === OP.lconst_0 || op === OP.lconst_1) return { cat: 'long', value: BigInt(op - OP.lconst_0) };
  if (op === OP.ldc || op === OP.ldc_w || op === OP.ldc2_w) {
    const c = constant(cf, ins.index);
    if (c?.type === 'I') return { cat: 'int', value: c.value };
    if (c?.type === 'J') return { cat: 'long', value: c.value };
    if (c?.type === 'String') return { cat: 'str', value: c.value };
  }
  return null;
}
const catOf = (t) => (t === 'J' ? 'long' : t === STR || t === 'Ljava/lang/Object;' ? 'str' : 'int');
const reason = (e) => (e instanceof JavaThrow ? `Java istisnası: ${e.message}` : e.message);

/** Kendi sınıfının <clinit>'i dışında yazılan statik alanlar */
function mutableJvm(prog) {
  const out = new Set();
  for (const { cf } of prog.classes) {
    const self = thisName(cf);
    for (const m of cf.methods) {
      if (!m.code) continue;
      const clinit = memberName(cf, m) === '<clinit>';
      let insns;
      try { insns = decodeJvm(m.code.code); } catch { continue; }
      for (const ins of insns) {
        if (ins.op !== OP.putstatic) continue;
        const r = ref(cf, ins.index);
        if (r && (!clinit || r.owner !== self)) out.add(`${r.owner}.${r.name}`);
      }
      // dizi öğesine yazma: tabloyu <clinit> dışında değiştiren kod (getstatic + ... + aastore) da değişken sayılır
      if (!clinit) for (let i = 0; i < insns.length; i++) {
        if (insns[i].op !== OP.getstatic) continue;
        const r = ref(cf, insns[i].index);
        if (!r?.desc.startsWith('[')) continue;
        for (let k = i + 1; k < Math.min(insns.length, i + 6); k++) if (insns[k].op >= OP.iastore && insns[k].op <= OP.sastore) { out.add(`${r.owner}.${r.name}`); break; }
      }
    }
  }
  return out;
}

/**
 * Sınıf dosyalarında dizge çözme (yerinde yeniden yazma)
 * @returns {{ changed, stats, decryptors, failures, values }}
 */
export function decryptJvm(prog, { log = () => {}, deadline = Date.now() + LIMITS.decryptMs } = {}) {
  const jvm = createJvm(prog.classMap, {}, mutableJvm(prog));
  const decryptors = new Map();
  const failures = [];
  const values = [];
  const cache = new Map();
  const failedSites = new Set(); // sonraki turlarda yeniden sayılmasın
  let strings = 0;
  let sites = 0;
  let changed = false;
  const dkey = (o, n, d) => `${o}.${n}${d}`;
  const note = (k, info) => { if (!decryptors.has(k)) decryptors.set(k, { ...info, sites: 0, decoded: 0, failed: 0, reasons: new Set() }); return decryptors.get(k); };

  for (let round = 1; round <= MAX_ROUNDS; round++) {
    let roundChanged = 0;
    for (const { cf } of prog.classes) {
      for (const m of cf.methods) {
        if (!m.code || Date.now() > deadline || sites > LIMITS.decryptSites) continue;
        let insns;
        try { insns = decodeJvm(m.code.code); } catch { continue; }
        const lead = jvmLeaders(insns, m.code.exceptions);
        const where = `${thisName(cf)}.${memberName(cf, m)}`;
        for (let i = 0; i < insns.length; i++) {
          const ins = insns[i];
          if (failedSites.has(`${where}@${ins.pc}`)) continue;
          let start = -1;
          let target = null;
          let evaluate = null;
          if (ins.op === OP.invokestatic) {
            const r = ref(cf, ins.index);
            if (!r) continue;
            const { params, ret } = parseMethodDesc(r.desc);
            if (ret !== STR || !params.length || !params.every((p) => OK_PARAMS.has(p)) || !prog.classMap.has(r.owner)) continue;
            if (i < params.length) continue;
            const args = [];
            let ok = true;
            for (let k = 0; k < params.length; k++) {
              const c = constOf(cf, insns[i - params.length + k]);
              if (!c || c.cat !== catOf(params[k])) { ok = false; break; }
              args.push(c.value);
            }
            if (!ok) continue;
            start = i - params.length;
            target = { owner: r.owner, name: r.name, desc: r.desc };
            evaluate = () => jvm.invoke(r.owner, r.name, r.desc, args);
            sites++;
            note(dkey(r.owner, r.name, r.desc), target).sites++;
            target.args = args;
          } else if (ins.op === OP.aaload && i >= 2 && insns[i - 2].op === OP.getstatic) {
            const r = ref(cf, insns[i - 2].index);
            const c = constOf(cf, insns[i - 1]);
            if (!r || r.desc !== `[${STR}` || !c || c.cat !== 'int' || !prog.classMap.has(r.owner)) continue;
            start = i - 2;
            target = { owner: r.owner, name: r.name, desc: r.desc, array: true, args: [c.value] };
            evaluate = () => {
              const a = jvm.getStatic(r.owner, r.name);
              if (!a?.data || c.value < 0 || c.value >= a.data.length) throw new Unsupported('dizi boş ya da indis dışında');
              return a.data[c.value];
            };
            sites++;
            note(dkey(r.owner, r.name, r.desc), target).sites++;
          } else continue;
          // aralığın içine dallanma varsa dokunulmaz
          const end = ins.pc + ins.len;
          let jumpedInto = false;
          for (let k = start + 1; k <= i; k++) if (lead.has(insns[k].pc)) jumpedInto = true;
          const d = decryptors.get(dkey(target.owner, target.name, target.desc));
          if (jumpedInto) { d.failed++; d.reasons.add('çağrı dizisinin içine dallanma var'); failedSites.add(`${where}@${ins.pc}`); continue; }
          const ck = `${target.owner}.${target.name}${target.desc}|${JSON.stringify(target.args, (k, v) => (typeof v === 'bigint' ? `${v}n` : v))}`;
          let value = cache.get(ck);
          if (value === undefined) {
            try {
              value = evaluate();
              if (typeof value !== 'string') throw new Unsupported(value === null ? 'null döndü' : 'dizge dönmedi');
            } catch (e) {
              value = { error: e instanceof Unsupported || e instanceof BudgetExceeded || e instanceof JavaThrow ? reason(e) : `bozuk bytecode (${e.message})` };
            }
            cache.set(ck, value);
          }
          if (typeof value !== 'string') {
            failedSites.add(`${where}@${ins.pc}`);
            d.failed++;
            d.reasons.add(value.error);
            if (failures.length < 200) failures.push({ where, pc: insns[start].pc, target: `${target.owner}.${target.name}`, reason: value.error });
            continue;
          }
          let idx;
          try { idx = addString(cf, value); } catch (e) { d.failed++; d.reasons.add(e.message); failedSites.add(`${where}@${ins.pc}`); continue; }
          const code = m.code.code;
          const s = insns[start].pc;
          code[s] = OP.ldc_w;
          code[s + 1] = idx >> 8;
          code[s + 2] = idx & 0xff;
          code.fill(OP.nop, s + 3, end);
          d.decoded++;
          strings++;
          roundChanged++;
          if (values.length < 5000) values.push({ where, value });
        }
      }
    }
    if (roundChanged) { changed = true; log(`strings: tur ${round}: ${roundChanged} çağrı yeri çözüldü`); } else break;
  }
  const list = [...decryptors.values()].map((d) => ({ owner: d.owner, name: d.name, desc: d.desc, array: Boolean(d.array), sites: d.sites, decoded: d.decoded, failed: d.failed, reasons: [...d.reasons].slice(0, 4) }));
  return { changed, stats: { strings, sites, decryptors: list.filter((d) => d.decoded).length }, decryptors: list, failures, values };
}

// ── DEX ──
const writesOf = (ins) => {
  const n = ins.name;
  if (ins.a === undefined) return [];
  if (/^(aput|iput|sput|if-|return|throw|monitor|fill-array|packed|sparse|check-cast)/.test(n)) return [];
  const wideW = /-wide|-long|-double|-to-long|-to-double/.test(n) && !/^(long-to-int|long-to-float|double-to-int|double-to-float|double-to-long|cmp)/.test(n);
  const isWideDst = n.startsWith('move-wide') || n.startsWith('const-wide') || n === 'move-result-wide' || n === 'aget-wide' || n === 'iget-wide' || n === 'sget-wide' || (wideW && /^(neg|not|add|sub|mul|div|rem|and|or|xor|shl|shr|ushr|int-to-long|int-to-double|float-to-long|float-to-double|long-to-double|double-to-long)/.test(n));
  return isWideDst ? [ins.a, ins.a + 1] : [ins.a];
};

function mutableDex(prog) {
  const out = new Set();
  for (const { dex } of prog.dexes) for (const c of dex.classes) for (const m of methodsOf(c)) {
    if (!m.code) continue;
    const clinit = dex.methods[m.idx]?.name === '<clinit>';
    let insns;
    try { insns = decodeDex(m.code.insns); } catch { continue; }
    for (const ins of insns) {
      if (ins.name.startsWith('sput')) {
        const f = dex.fields[ins.index];
        if (f && !clinit || f.cls !== c.type) out.add(`${f.cls}.${f.name}`);
      }
    }
  }
  return out;
}

/**
 * DEX'te dizge çözme: kod değişmez; çağrı yerleri ayrıştırma için işaretlenir.
 * @returns {{ changed, stats, decryptors, failures, values, notes: Map<code, Map<pc, { value, reg, until }>> }}
 */
export function decryptDex(prog, { log = () => {}, deadline = Date.now() + LIMITS.decryptMs } = {}) {
  const vm = createDalvik(prog.dexes.map((d) => d.dex), {}, mutableDex(prog));
  const notes = new Map();
  const decryptors = new Map();
  const failures = [];
  const values = [];
  const cache = new Map();
  let strings = 0;
  let sites = 0;
  const note = (k, info) => { if (!decryptors.has(k)) decryptors.set(k, { ...info, sites: 0, decoded: 0, failed: 0, reasons: new Set() }); return decryptors.get(k); };
  const run = (ck, fn) => {
    // bozuk bytecode'un JS hataları da dokunulmayan çağrı yeri sayılır
    if (cache.has(ck)) return cache.get(ck);
    let v;
    try {
      v = fn();
      if (typeof v !== 'string') v = { error: v === null ? 'null döndü' : 'dizge dönmedi' };
    } catch (e) {
      v = { error: e instanceof Unsupported || e instanceof BudgetExceeded || e instanceof JavaThrow ? reason(e) : `bozuk bytecode (${e.message})` };
    }
    cache.set(ck, v);
    return v;
  };
  for (const { dex } of prog.dexes) {
    for (const c of dex.classes) for (const m of methodsOf(c)) {
      if (!m.code || Date.now() > deadline || sites > LIMITS.decryptSites) continue;
      let insns;
      try { insns = decodeDex(m.code.insns); } catch { continue; }
      const lead = new Set([0]);
      for (const ins of insns) {
        if (ins.target !== undefined && !ins.name.startsWith('fill-array')) {
          if (ins.name.endsWith('switch')) { try { for (const [, off] of payloadAt(m.code.insns, ins.target).cases) lead.add(ins.pc + off); } catch { /* bozuk tablo */ } } else lead.add(ins.target);
          lead.add(ins.pc + ins.len);
        }
        if (isDalvikTerminal(ins.name)) lead.add(ins.pc + ins.len);
      }
      for (const t of m.code.tries) { lead.add(t.start); for (const h of t.handlers) lead.add(h.addr); if (t.catchAll !== null) lead.add(t.catchAll); }
      const where = `${c.type}->${dex.methods[m.idx]?.name}`;
      const known = new Map(); // yazmaç → { cat, value } | { sarr: alan }
      let marks = null;
      for (let i = 0; i < insns.length; i++) {
        const ins = insns[i];
        if (lead.has(ins.pc)) known.clear();
        const n = ins.name;
        if (n.startsWith('const-string')) { known.set(ins.a, { cat: 'str', value: dex.strings[ins.index] }); continue; }
        if (n === 'const/4' || n === 'const/16' || n === 'const' || n === 'const/high16') { known.set(ins.a, { cat: 'int', value: ins.lit }); continue; }
        if (n.startsWith('const-wide')) { known.set(ins.a, { cat: 'long', value: ins.wide }); known.delete(ins.a + 1); continue; }
        if (n === 'sget-object' && dex.fields[ins.index]?.type === `[${STR}`) { known.set(ins.a, { sarr: dex.fields[ins.index] }); continue; }
        let hit = null;
        if (n === 'invoke-static' || n === 'invoke-static/range') {
          const mid = dex.methods[ins.index];
          const params = mid?.proto.params ?? [];
          const next = insns[i + 1];
          if (mid && mid.proto.ret === STR && params.length && params.every((p) => OK_PARAMS.has(p)) && vm.has(mid.cls) && next?.name === 'move-result-object' && !lead.has(next.pc)) {
            const args = [];
            let k = 0;
            let ok = true;
            for (const p of params) {
              const v = known.get(ins.regs[k]);
              if (!v || v.cat !== catOf(p)) { ok = false; break; }
              args.push(v.value);
              k += p === 'J' ? 2 : 1;
            }
            if (ok) {
              sites++;
              const dk = `${mid.cls}->${mid.name}${mid.desc}`;
              const d = note(dk, { owner: mid.cls, name: mid.name, desc: mid.desc });
              d.sites++;
              const v = run(`${dk}|${JSON.stringify(args, (x, y) => (typeof y === 'bigint' ? `${y}n` : y))}`, () => vm.invoke(mid.cls, mid.name, mid.desc, args));
              hit = { d, v, reg: next.a, until: next.pc + next.len, where, target: `${mid.cls}->${mid.name}` };
            }
          }
        } else if (n === 'aget-object') {
          const arr = known.get(ins.b);
          const idx = known.get(ins.c);
          if (arr?.sarr && idx?.cat === 'int') {
            sites++;
            const f = arr.sarr;
            const dk = `${f.cls}.${f.name}`;
            const d = note(dk, { owner: f.cls, name: f.name, desc: f.type, array: true });
            d.sites++;
            const v = run(`${dk}|${idx.value}`, () => {
              const a = vm.getStatic(f.cls, f.name);
              if (!a?.data || idx.value < 0 || idx.value >= a.data.length) throw new Unsupported('dizi boş ya da indis dışında');
              return a.data[idx.value];
            });
            hit = { d, v, reg: ins.a, until: ins.pc + ins.len, where, target: dk };
          }
        }
        if (hit) {
          if (typeof hit.v === 'string') {
            marks ??= new Map();
            marks.set(ins.pc, { value: hit.v, reg: hit.reg, until: hit.until, from: hit.target });
            hit.d.decoded++;
            strings++;
            if (values.length < 5000) values.push({ where, value: hit.v });
            known.set(hit.reg, { cat: 'str', value: hit.v });
            if (n.startsWith('invoke')) i++;
            continue;
          }
          hit.d.failed++;
          hit.d.reasons.add(hit.v.error);
          if (failures.length < 200) failures.push({ where, pc: ins.pc, target: hit.target, reason: hit.v.error });
        }
        for (const r of writesOf(ins)) known.delete(r);
      }
      if (marks) notes.set(m.code, marks);
    }
  }
  if (strings) log(`strings: DEX'te ${strings} çağrı yeri çözüldü (ayrıştırma çıktısında işaretli)`);
  const list = [...decryptors.values()].map((d) => ({ owner: d.owner, name: d.name, desc: d.desc, array: Boolean(d.array), sites: d.sites, decoded: d.decoded, failed: d.failed, reasons: [...d.reasons].slice(0, 4) }));
  return { changed: strings > 0, stats: { strings, sites, decryptors: list.filter((d) => d.decoded).length }, decryptors: list, failures, values, notes };
}

