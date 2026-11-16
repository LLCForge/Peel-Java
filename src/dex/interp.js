// Sınırlı Dalvik yorumlayıcısı: JVM yorumlayıcısının (src/jvm/interp.js) yazmaç tabanlı karşılığı. Aynı çalışma zamanı
// alt kümesini (src/sandbox/runtime.js) ve aynı bütçeleri kullanır; nesne alanları, yansıma ve G/Ç yoktur.
import { decodeAt, payloadAt } from './opcodes.js';
import { internalOf, methodsOf } from './dex.js';
import { Unsupported, BudgetExceeded, JavaThrow, createContext, newArray, arrayLoad, arrayStore, isArray, excMatches, builtin, allocate } from '../sandbox/runtime.js';
import { defaultOf } from '../jvm/interp.js';

const TOP = Symbol('top');
const I32 = (v) => v | 0;
const L64 = (v) => BigInt.asIntN(64, v);
const F32 = Math.fround;
const wide = (t) => t === 'J' || t === 'D';
const toInt = (v) => (Number.isNaN(v) ? 0 : v >= 2147483647 ? 2147483647 : v <= -2147483648 ? -2147483648 : Math.trunc(v));
const toLong = (v) => (Number.isNaN(v) ? 0n : v >= 9.223372036854776e18 ? 2n ** 63n - 1n : v <= -9.223372036854776e18 ? -(2n ** 63n) : BigInt(Math.trunc(v)));
const fcmp = (a, b, nan) => (Number.isNaN(a) || Number.isNaN(b) ? nan : a < b ? -1 : a > b ? 1 : 0);
const ACC_STATIC = 0x8;

function intOp(name, a, b) {
  switch (name) {
    case 'add': return I32(a + b);
    case 'sub': return I32(a - b);
    case 'rsub': return I32(b - a);
    case 'mul': return Math.imul(a, b);
    case 'div': if (b === 0) throw new JavaThrow('java/lang/ArithmeticException', '/ by zero'); return I32(Math.trunc(a / b));
    case 'rem': if (b === 0) throw new JavaThrow('java/lang/ArithmeticException', '/ by zero'); return I32(a % b);
    case 'and': return a & b;
    case 'or': return a | b;
    case 'xor': return a ^ b;
    case 'shl': return a << (b & 31);
    case 'shr': return a >> (b & 31);
    case 'ushr': return I32(a >>> (b & 31));
    default: throw new Unsupported(name);
  }
}
function longOp(name, a, b) {
  switch (name) {
    case 'add': return L64(a + b);
    case 'sub': return L64(a - b);
    case 'mul': return L64(a * b);
    case 'div': if (b === 0n) throw new JavaThrow('java/lang/ArithmeticException', '/ by zero'); return L64(a / b);
    case 'rem': if (b === 0n) throw new JavaThrow('java/lang/ArithmeticException', '/ by zero'); return L64(a % b);
    case 'and': return L64(a & b);
    case 'or': return L64(a | b);
    case 'xor': return L64(a ^ b);
    case 'shl': return L64(a << BigInt(Number(b) & 63));
    case 'shr': return a >> BigInt(Number(b) & 63);
    case 'ushr': return L64(BigInt.asUintN(64, a) >> BigInt(Number(b) & 63));
    default: throw new Unsupported(name);
  }
}
function floatOp(name, a, b, f) {
  const r = name === 'add' ? a + b : name === 'sub' ? a - b : name === 'mul' ? a * b : name === 'div' ? a / b : name === 'rem' ? a % b : NaN;
  return f ? F32(r) : r;
}

/**
 * @param {object[]} dexes ayrıştırılmış DEX dosyaları
 */
export function createDalvik(dexes, limits = {}, mutable = new Set()) {
  const classes = new Map(); // "Lx;" → { dex, cls }
  for (const dex of dexes) for (const cls of dex.classes) if (!classes.has(cls.type)) classes.set(cls.type, { dex, cls });
  const statics = new Map();
  const state = new Map();
  const cache = new WeakMap();
  let ctx = createContext(limits);

  const insnAt = (code, pc) => {
    let m = cache.get(code);
    if (!m) { m = new Map(); cache.set(code, m); }
    let ins = m.get(pc);
    if (!ins) {
      if (pc < 0 || pc >= code.insns.length) throw new Unsupported(`geçersiz komut adresi ${pc}`);
      ins = decodeAt(code.insns, pc);
      m.set(pc, ins);
    }
    return ins;
  };

  function findMethod(type, name, desc) {
    for (let t = type, guard = 0; t && guard < 64; guard++) {
      const c = classes.get(t);
      if (!c) return null;
      for (const m of methodsOf(c.cls)) {
        const id = c.dex.methods[m.idx];
        if (id && id.name === name && id.desc === desc) return { ...c, m };
      }
      t = c.cls.superType;
    }
    return null;
  }
  function findField(type, name) {
    for (let t = type, guard = 0; t && guard < 64; guard++) {
      const c = classes.get(t);
      if (!c) return null;
      if ([...c.cls.staticFields, ...c.cls.instanceFields].some((f) => c.dex.fields[f.idx]?.name === name)) return t;
      t = c.cls.superType;
    }
    return null;
  }

  function initClass(type) {
    const st = state.get(type);
    if (st === 'done' || st === 'init') return;
    if (st) throw new Unsupported(st);
    const c = classes.get(type);
    if (!c) throw new Unsupported(`DEX dışı sınıf: ${type}`);
    state.set(type, 'init');
    try {
      if (c.cls.superType && classes.has(c.cls.superType)) initClass(c.cls.superType);
      c.cls.staticFields.forEach((f, i) => {
        const id = c.dex.fields[f.idx];
        const sv = c.cls.staticValues[i];
        statics.set(`${type}.${id.name}`, sv && sv.type !== 'Array' && sv.type !== 'Annotation' ? (sv.type === 'Z' ? sv.value : sv.value) : defaultOf(id.type));
      });
      const clinit = methodsOf(c.cls).find((m) => c.dex.methods[m.idx]?.name === '<clinit>' && m.code);
      if (clinit) execute(c.dex, clinit, []);
      state.set(type, 'done');
    } catch (e) {
      const why = `${type}.<clinit> çalıştırılamadı: ${e.message}`;
      state.set(type, why);
      if (e instanceof BudgetExceeded) throw e;
      throw new Unsupported(why);
    }
  }

  function execute(dex, m, args) {
    if (++ctx.depth > ctx.lim.interpDepth) throw new BudgetExceeded(`çağrı derinliği sınırı (${ctx.lim.interpDepth})`);
    try { return run(dex, m, args); } finally { ctx.depth--; }
  }

  function run(dex, m, args) {
    const code = m.code;
    if (!code) throw new Unsupported('gövdesiz yöntem');
    if (!(m.access & ACC_STATIC)) throw new Unsupported('örnek yöntemi');
    const id = dex.methods[m.idx];
    const regs = new Array(code.registers).fill(undefined);
    let r = code.registers - code.ins;
    id.proto.params.forEach((t, i) => { regs[r++] = args[i]; if (wide(t)) regs[r++] = TOP; });
    let result;
    let pc = 0;
    const setW = (a, v) => { regs[a] = v; regs[a + 1] = TOP; };
    for (;;) {
      ctx.tick();
      const ins = insnAt(code, pc);
      let next = pc + ins.len;
      try {
        const n = ins.name;
        const base = n.split('/')[0];
        if (ins.fmt === 'payload') throw new Unsupported('veri yüküne atlandı');
        if (n === 'nop' || n === 'monitor-enter' || n === 'monitor-exit') { /* etkisiz */ }
        else if (base === 'move' || base === 'move-object') regs[ins.a] = regs[ins.b];
        else if (base === 'move-wide') setW(ins.a, regs[ins.b]);
        else if (n === 'move-result' || n === 'move-result-object') regs[ins.a] = result;
        else if (n === 'move-result-wide') setW(ins.a, result);
        else if (n === 'move-exception') regs[ins.a] = result;
        else if (n === 'return-void') return undefined;
        else if (n.startsWith('return')) return regs[ins.a];
        else if (base === 'const' || n === 'const/4' || n === 'const/16' || n === 'const/high16') regs[ins.a] = ins.lit;
        else if (n.startsWith('const-wide')) setW(ins.a, ins.wide);
        else if (n.startsWith('const-string')) regs[ins.a] = dex.strings[ins.index];
        else if (n === 'check-cast' || n === 'instance-of') {
          const t = internalOf(dex.types[ins.index]);
          const v = regs[n === 'check-cast' ? ins.a : ins.b];
          let ok;
          if (v === null || v === 0) ok = n === 'check-cast';
          else if (t === 'java/lang/Object') ok = true;
          else if (t === 'java/lang/String' || t === 'java/lang/CharSequence') ok = typeof v === 'string' || (t === 'java/lang/CharSequence' && v?.s !== undefined);
          else if (t.startsWith('[')) ok = isArray(v) && `[${v.arr}` === t;
          else if (v?.cls) ok = v.cls === t;
          else throw new Unsupported(`tür denetimi: ${t}`);
          if (n === 'instance-of') regs[ins.a] = ok ? 1 : 0;
          else if (!ok) throw new JavaThrow('java/lang/ClassCastException', t);
        } else if (n === 'array-length') {
          const a = regs[ins.b];
          if (a === null || a === 0) throw new JavaThrow('java/lang/NullPointerException');
          if (!isArray(a)) throw new Unsupported('array-length: dizi değil');
          regs[ins.a] = a.data.length;
        } else if (n === 'new-instance') {
          const o = allocate(internalOf(dex.types[ins.index]));
          if (o === undefined) throw new Unsupported(`new-instance ${dex.types[ins.index]}`);
          regs[ins.a] = o;
        } else if (n === 'new-array') regs[ins.a] = newArray(ctx, dex.types[ins.index].slice(1), regs[ins.b]);
        else if (base === 'filled-new-array') {
          const t = dex.types[ins.index].slice(1);
          const a = newArray(ctx, t, ins.regs.length);
          ins.regs.forEach((x, i) => { a.data[i] = regs[x]; });
          result = a;
        } else if (n === 'fill-array-data') {
          const a = regs[ins.a];
          const p = payloadAt(code.insns, ins.target);
          if (!isArray(a) || p.size > a.data.length) throw new JavaThrow('java/lang/ArrayIndexOutOfBoundsException');
          const dv = new DataView(p.bytes.buffer, p.bytes.byteOffset, p.bytes.byteLength);
          for (let i = 0; i < p.size; i++) {
            const o = i * p.width;
            a.data[i] = p.width === 1 ? dv.getInt8(o) : p.width === 2 ? (a.arr === 'C' ? dv.getUint16(o, true) : dv.getInt16(o, true)) : p.width === 4 ? (a.arr === 'F' ? dv.getFloat32(o, true) : dv.getInt32(o, true)) : a.arr === 'D' ? dv.getFloat64(o, true) : dv.getBigInt64(o, true);
          }
          ctx.tick(p.size >> 4);
        } else if (n === 'throw') {
          const e = regs[ins.a];
          if (e?.exc) throw new JavaThrow(e.exc);
          throw new Unsupported('throw (istisna nesnesi oluşturulamaz)');
        } else if (base === 'goto') next = ins.target;
        else if (n === 'packed-switch' || n === 'sparse-switch') {
          const p = payloadAt(code.insns, ins.target);
          const hit = p.cases.find((c) => c[0] === regs[ins.a]);
          if (hit) next = pc + hit[1];
        } else if (n.startsWith('cmp')) {
          const b = regs[ins.b];
          const c = regs[ins.c];
          regs[ins.a] = n === 'cmp-long' ? (b < c ? -1 : b > c ? 1 : 0) : fcmp(b, c, n.startsWith('cmpl') ? -1 : 1);
        } else if (n.startsWith('if-')) {
          const z = n.endsWith('z');
          const raw = regs[ins.a];
          const a = raw === null ? 0 : raw;
          const b = z ? 0 : regs[ins.b] === null ? 0 : regs[ins.b];
          const cond = n.slice(3, 5);
          const ok = cond === 'eq' ? a === b : cond === 'ne' ? a !== b : cond === 'lt' ? a < b : cond === 'ge' ? a >= b : cond === 'gt' ? a > b : a <= b;
          if (ok) next = ins.target;
        } else if (n.startsWith('aget')) {
          const v = arrayLoad(regs[ins.b] === 0 ? null : regs[ins.b], regs[ins.c]);
          if (n === 'aget-wide') setW(ins.a, v); else regs[ins.a] = v;
        } else if (n.startsWith('aput')) {
          let v = regs[ins.a];
          if (n === 'aput-byte' || n === 'aput-boolean') v = (v << 24) >> 24;
          else if (n === 'aput-char') v &= 0xffff;
          else if (n === 'aput-short') v = (v << 16) >> 16;
          arrayStore(regs[ins.b] === 0 ? null : regs[ins.b], regs[ins.c], v);
        } else if (n.startsWith('iget') || n.startsWith('iput')) throw new Unsupported('nesne alanı erişimi');
        else if (n.startsWith('sget') || n.startsWith('sput')) {
          const f = dex.fields[ins.index];
          const owner = findField(f.cls, f.name);
          if (!owner) throw new Unsupported(`DEX dışı statik alan: ${f.cls}.${f.name}`);
          initClass(owner);
          const key = `${owner}.${f.name}`;
          if (n.startsWith('sget') && mutable.has(key)) throw new Unsupported(`çalışma anında değişen statik alana bağlı: ${key}`);
          if (n.startsWith('sget')) {
            if (!statics.has(key)) throw new Unsupported(`statik olmayan alan: ${key}`);
            if (n === 'sget-wide') setW(ins.a, statics.get(key)); else regs[ins.a] = statics.get(key);
          } else statics.set(key, regs[ins.a]);
        } else if (n.startsWith('invoke-')) {
          if (ins.kind !== 'method') throw new Unsupported(n);
          const mid = dex.methods[ins.index];
          const isStatic = n.startsWith('invoke-static');
          const owner = internalOf(mid.cls);
          const args = [];
          let k = 0;
          if (!isStatic) args.push(regs[ins.regs[k++]]);
          for (const t of mid.proto.params) { args.push(regs[ins.regs[k]]); k += wide(t) ? 2 : 1; }
          if (!isStatic && (args[0] === null || args[0] === 0)) throw new JavaThrow('java/lang/NullPointerException');
          const b = builtin(owner, mid.name, mid.desc) ?? (!isStatic && typeof args[0] === 'string' ? builtin('java/lang/String', mid.name, mid.desc) : undefined);
          if (b) {
            const v = b(ctx, args);
            if (mid.name === '<init>') {
              const self = args[0];
              for (let i = 0; i < regs.length; i++) if (regs[i] === self) regs[i] = v;
            } else result = v;
          } else if (isStatic && classes.has(mid.cls)) {
            const target = findMethod(mid.cls, mid.name, mid.desc);
            if (!target?.m.code) throw new Unsupported(`yöntem bulunamadı: ${mid.cls}->${mid.name}${mid.desc}`);
            initClass(target.cls.type);
            result = execute(target.dex, target.m, args);
          } else throw new Unsupported(`desteklenmeyen çağrı: ${mid.cls}->${mid.name}${mid.desc}`);
        } else if (/^(neg|not|int-to|long-to|float-to|double-to)/.test(n)) {
          const v = regs[ins.b];
          const out = {
            'neg-int': () => I32(-v), 'not-int': () => ~v, 'neg-long': () => L64(-v), 'not-long': () => L64(~v), 'neg-float': () => -v, 'neg-double': () => -v,
            'int-to-long': () => BigInt(v), 'int-to-float': () => F32(v), 'int-to-double': () => v, 'long-to-int': () => Number(BigInt.asIntN(32, v)),
            'long-to-float': () => F32(Number(v)), 'long-to-double': () => Number(v), 'float-to-int': () => toInt(v), 'float-to-long': () => toLong(v),
            'float-to-double': () => v, 'double-to-int': () => toInt(v), 'double-to-long': () => toLong(v), 'double-to-float': () => F32(v),
            'int-to-byte': () => (v << 24) >> 24, 'int-to-char': () => v & 0xffff, 'int-to-short': () => (v << 16) >> 16,
          }[n]();
          if (/-to-(long|double)$|^(neg|not)-(long|double)$/.test(n)) setW(ins.a, out); else regs[ins.a] = out;
        } else if (/-(int|long|float|double)(\/2addr)?$/.test(n) || /\/lit(8|16)$/.test(n) || n === 'rsub-int') {
          const lit = /\/lit|^rsub-int/.test(n);
          const [opn, typ] = lit ? [n.split('-')[0], 'int'] : n.replace('/2addr', '').split('-');
          const two = n.endsWith('/2addr');
          const a = two ? regs[ins.a] : regs[ins.b];
          const b = lit ? ins.lit : two ? regs[ins.b] : regs[ins.c];
          if (typ === 'int') regs[ins.a] = intOp(opn, a, b);
          else if (typ === 'long') setW(ins.a, longOp(opn, a, opn.startsWith('sh') || opn === 'ushr' ? BigInt(b) : b));
          else if (typ === 'float') regs[ins.a] = floatOp(opn, a, b, true);
          else setW(ins.a, floatOp(opn, a, b, false));
        } else throw new Unsupported(`desteklenmeyen komut ${n}`);
      } catch (e) {
        if (!(e instanceof JavaThrow)) throw e;
        const t = code.tries.find((x) => pc >= x.start && pc < x.start + x.count);
        const h = t?.handlers.find((x) => excMatches(e.cls, internalOf(x.type)));
        const addr = h ? h.addr : t?.catchAll ?? null;
        if (addr === null) throw e;
        result = { exc: e.cls };
        next = addr;
      }
      pc = next;
    }
  }

  return {
    invoke(type, name, desc, args, limits2 = limits) {
      ctx = createContext(limits2);
      const target = findMethod(type, name, desc);
      if (!target?.m.code) throw new Unsupported(`yöntem yok: ${type}->${name}${desc}`);
      if (!(target.m.access & ACC_STATIC)) throw new Unsupported('statik değil');
      initClass(target.cls.type);
      return execute(target.dex, target.m, args);
    },
    getStatic(type, name, limits2 = limits) {
      ctx = createContext(limits2);
      const owner = findField(type, name);
      if (!owner) throw new Unsupported(`alan yok: ${type}.${name}`);
      initClass(owner);
      return statics.get(`${owner}.${name}`);
    },
    has: (type) => classes.has(type),
    steps: () => ctx.steps,
  };
}
