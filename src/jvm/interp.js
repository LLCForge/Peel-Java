// Sınırlı JVM yorumlayıcısı. Yalnızca dizge çözücüleri çalıştırmak için: aritmetik, diziler, statik alanlar (arşivdeki
// sınıfların, <clinit> dahil), arşiv içi statik çağrılar ve runtime.js'teki yan etkisiz çekirdek API'ler. Nesne örnekleri
// (arşivdeki sınıflardan), yansıma, iş parçacığı, G/Ç ve yerel kod yoktur: bunlara ulaşan çözücü Unsupported ile durur.
// Her çağrı komut, bellek, süre ve derinlik bütçesiyle sınırlıdır (runtime.js createContext).
import { OP, decodeAt, NEWARRAY_TYPES } from './opcodes.js';
import { constant, ref, nat, className, memberName, memberDesc, parseMethodDesc, findAttr, thisName, superName, ACC } from './classfile.js';
import { Reader } from '../core/bytes.js';
import { Unsupported, BudgetExceeded, JavaThrow, createContext, newArray, arrayLoad, arrayStore, isArray, excMatches, builtin, allocate } from '../sandbox/runtime.js';

const TOP = Symbol('top'); // long/double ikinci yuvası
const I32 = (v) => v | 0;
const L64 = (v) => BigInt.asIntN(64, v);
const F32 = Math.fround;
const MIN_L = -(2n ** 63n);
const MAX_L = 2n ** 63n - 1n;
const toInt = (v) => (Number.isNaN(v) ? 0 : v >= 2147483647 ? 2147483647 : v <= -2147483648 ? -2147483648 : Math.trunc(v));
const toLong = (v) => (Number.isNaN(v) ? 0n : v >= 9.223372036854776e18 ? MAX_L : v <= -9.223372036854776e18 ? MIN_L : BigInt(Math.trunc(v)));
const fcmp = (a, b, nan) => (Number.isNaN(a) || Number.isNaN(b) ? nan : a < b ? -1 : a > b ? 1 : 0);
export const defaultOf = (t) => ('IBCSZ'.includes(t) ? 0 : t === 'J' ? 0n : t === 'F' || t === 'D' ? 0 : null);
const wide = (t) => t === 'J' || t === 'D';

/**
 * @param {Map<string, object>} classes iç ad → ayrıştırılmış sınıf dosyası
 * @param {Set<string>} mutable kendi <clinit>'i dışında yazılan statik alanlar ("sahip.ad"): okunursa değerlendirme durur
 */
export function createJvm(classes, limits = {}, mutable = new Set()) {
  const statics = new Map(); // "sahip.ad" → değer
  const state = new Map(); // sınıf → 'init' | 'done' | hata
  const insnCache = new WeakMap();
  let ctx = createContext(limits);

  const insnAt = (code, pc) => {
    let m = insnCache.get(code);
    if (!m) { m = new Map(); insnCache.set(code, m); }
    let ins = m.get(pc);
    if (!ins) {
      if (pc < 0 || pc >= code.code.length) throw new Unsupported(`geçersiz komut adresi ${pc}`);
      ins = decodeAt(code.code, pc);
      m.set(pc, ins);
    }
    return ins;
  };

  function findMethod(owner, name, desc) {
    for (let c = owner, guard = 0; c && guard < 64; guard++) {
      const cf = classes.get(c);
      if (!cf) return null;
      const m = cf.methods.find((x) => memberName(cf, x) === name && memberDesc(cf, x) === desc);
      if (m) return { cf, m };
      c = superName(cf);
    }
    return null;
  }

  function findField(owner, name) {
    for (let c = owner, guard = 0; c && guard < 64; guard++) {
      const cf = classes.get(c);
      if (!cf) return null;
      const f = cf.fields.find((x) => memberName(cf, x) === name);
      if (f) return { cf, f, owner: c };
      c = superName(cf);
    }
    return null;
  }

  function initClass(name) {
    const st = state.get(name);
    if (st === 'done' || st === 'init') return;
    if (st) throw new Unsupported(st);
    const cf = classes.get(name);
    if (!cf) throw new Unsupported(`arşiv dışı sınıf: ${name}`);
    state.set(name, 'init');
    try {
      const sup = superName(cf);
      if (sup && classes.has(sup)) initClass(sup);
      for (const f of cf.fields) {
        if (!(f.access & ACC.STATIC)) continue;
        const key = `${name}.${memberName(cf, f)}`;
        const cv = findAttr(cf, f.attrs, 'ConstantValue');
        let v = defaultOf(memberDesc(cf, f));
        if (cv && cv.data.length >= 2) {
          const c = constant(cf, new Reader(cv.data).u2());
          if (c) v = c.value;
        }
        statics.set(key, v);
      }
      const clinit = cf.methods.find((m) => memberName(cf, m) === '<clinit>' && m.code);
      if (clinit) execute(cf, clinit, []);
      state.set(name, 'done');
    } catch (e) {
      const why = `${name}.<clinit> çalıştırılamadı: ${e.message}`;
      state.set(name, why);
      if (e instanceof BudgetExceeded) throw e;
      throw new Unsupported(why);
    }
  }

  function popArgs(stack, params) {
    const args = new Array(params.length);
    for (let i = params.length - 1; i >= 0; i--) {
      if (wide(params[i])) stack.pop();
      args[i] = stack.pop();
    }
    return args;
  }
  const pushValue = (stack, t, v) => { stack.push(v); if (wide(t)) stack.push(TOP); };

  function concat(cf, ins, stack) {
    const e = cf.cp[ins.index];
    const bsmAttr = findAttr(cf, cf.attrs, 'BootstrapMethods');
    if (!bsmAttr) throw new Unsupported('invokedynamic: BootstrapMethods yok');
    const r = new Reader(bsmAttr.data);
    const n = r.u2();
    let bsm = null;
    for (let i = 0; i < n; i++) {
      const mh = r.u2();
      const argc = r.u2();
      const args = [];
      for (let k = 0; k < argc; k++) args.push(r.u2());
      if (i === e.bsmIndex) bsm = { mh, args };
    }
    const handle = bsm && constant(cf, bsm.mh)?.value;
    const { name, desc } = nat(cf, e.natIndex);
    if (!handle || handle.owner !== 'java/lang/invoke/StringConcatFactory') throw new Unsupported('invokedynamic (yalnızca dizge birleştirme desteklenir)');
    const { params } = parseMethodDesc(desc);
    const vals = popArgs(stack, params);
    if (name !== 'makeConcatWithConstants' && name !== 'makeConcat') throw new Unsupported(`invokedynamic ${name}`);
    const recipe = name === 'makeConcat' ? '\u0001'.repeat(params.length) : String(constant(cf, bsm.args[0])?.value ?? '');
    const consts = bsm.args.slice(1).map((i) => constant(cf, i)?.value);
    let out = '';
    let ai = 0;
    let ci = 0;
    for (const ch of recipe) {
      if (ch === '\u0001') {
        const t = params[ai];
        const v = vals[ai++];
        const sb = builtin('java/lang/StringBuilder', 'append', `(${t.length === 1 ? t : t === 'Ljava/lang/String;' ? t : 'Ljava/lang/Object;'})Ljava/lang/StringBuilder;`);
        if (!sb) throw new Unsupported(`dizge birleştirme: ${t}`);
        const o = { cls: 'java/lang/StringBuilder', s: '' };
        sb(ctx, [o, v]);
        out += o.s;
      } else if (ch === '\u0002') out += String(consts[ci++]);
      else out += ch;
    }
    ctx.alloc(out.length);
    stack.push(out);
  }

  function execute(cf, m, args) {
    if (++ctx.depth > ctx.lim.interpDepth) throw new BudgetExceeded(`çağrı derinliği sınırı (${ctx.lim.interpDepth})`);
    try {
      return run(cf, m, args);
    } finally {
      ctx.depth--;
    }
  }

  function run(cf, m, args) {
    const code = m.code;
    if (!code) throw new Unsupported(`gövdesiz yöntem: ${memberName(cf, m)}`);
    const locals = new Array(Math.max(code.maxLocals, args.length * 2)).fill(undefined);
    const { params } = parseMethodDesc(memberDesc(cf, m));
    let li = 0;
    if (!(m.access & ACC.STATIC)) throw new Unsupported('örnek yöntemi');
    for (let i = 0; i < params.length; i++) {
      locals[li++] = args[i];
      if (wide(params[i])) locals[li++] = TOP;
    }
    let stack = [];
    let pc = 0;
    const pop = () => stack.pop();
    const pop2 = () => { stack.pop(); return stack.pop(); };
    const push = (v) => stack.push(v);
    const push2 = (v) => stack.push(v, TOP);
    for (;;) {
      ctx.tick();
      const ins = insnAt(code, pc);
      let next = pc + ins.len;
      try {
        const op = ins.op;
        switch (op) {
          case OP.nop: break;
          case OP.aconst_null: push(null); break;
          case OP.iconst_m1: case OP.iconst_0: case OP.iconst_1: case OP.iconst_2: case OP.iconst_3: case OP.iconst_4: case OP.iconst_5: push(op - OP.iconst_0); break;
          case OP.lconst_0: case OP.lconst_1: push2(BigInt(op - OP.lconst_0)); break;
          case OP.fconst_0: case OP.fconst_1: case OP.fconst_2: push(op - OP.fconst_0); break;
          case OP.dconst_0: case OP.dconst_1: push2(op - OP.dconst_0); break;
          case OP.bipush: case OP.sipush: push(ins.value); break;
          case OP.ldc: case OP.ldc_w: case OP.ldc2_w: {
            const c = constant(cf, ins.index);
            if (!c || !['I', 'F', 'J', 'D', 'String'].includes(c.type)) throw new Unsupported(`ldc ${c?.type ?? '?'}`);
            if (c.type === 'J' || c.type === 'D') push2(c.value); else push(c.value);
            break;
          }
          case OP.iload: case OP.fload: case OP.aload: push(locals[ins.local]); break;
          case OP.lload: case OP.dload: push2(locals[ins.local]); break;
          case OP.istore: case OP.fstore: case OP.astore: locals[ins.local] = pop(); break;
          case OP.lstore: case OP.dstore: locals[ins.local] = pop2(); locals[ins.local + 1] = TOP; break;
          case OP.wide: {
            const w = ins.wideOp;
            if (w === OP.iinc) locals[ins.local] = I32(locals[ins.local] + ins.value);
            else if (w === OP.lload || w === OP.dload) push2(locals[ins.local]);
            else if (w >= OP.iload && w <= OP.aload) push(locals[ins.local]);
            else if (w === OP.lstore || w === OP.dstore) { locals[ins.local] = pop2(); locals[ins.local + 1] = TOP; }
            else if (w >= OP.istore && w <= OP.astore) locals[ins.local] = pop();
            else throw new Unsupported('wide ret');
            break;
          }
          default:
            if (op >= OP.iload_0 && op <= OP.aload_3) {
              const k = (op - OP.iload_0) % 4;
              const kind = Math.floor((op - OP.iload_0) / 4);
              if (kind === 1 || kind === 3) push2(locals[k]); else push(locals[k]);
              break;
            }
            if (op >= OP.istore_0 && op <= OP.astore_3) {
              const k = (op - OP.istore_0) % 4;
              const kind = Math.floor((op - OP.istore_0) / 4);
              if (kind === 1 || kind === 3) { locals[k] = pop2(); locals[k + 1] = TOP; } else locals[k] = pop();
              break;
            }
            if (op >= OP.iaload && op <= OP.saload) {
              const i = pop();
              const a = pop();
              const v = arrayLoad(a, i);
              if (op === OP.laload || op === OP.daload) push2(v); else push(v);
              break;
            }
            if (op >= OP.iastore && op <= OP.sastore) {
              const v = op === OP.lastore || op === OP.dastore ? pop2() : pop();
              const i = pop();
              const a = pop();
              arrayStore(a, i, v);
              break;
            }
            next = step(op, ins, cf, stack, locals, pc, next);
            if (next === RETURN) return stack.retval;
        }
      } catch (e) {
        if (!(e instanceof JavaThrow)) throw e;
        const h = code.exceptions.find((x) => pc >= x.start && pc < x.end && excMatches(e.cls, className(cf, x.catchType)));
        if (!h) throw e;
        stack = [{ exc: e.cls }];
        next = h.handler;
      }
      pc = next;
    }
  }

  const RETURN = -1;
  function step(op, ins, cf, stack, locals, pc, next) {
    const pop = () => stack.pop();
    const pop2 = () => { stack.pop(); return stack.pop(); };
    const push = (v) => stack.push(v);
    const push2 = (v) => stack.push(v, TOP);
    switch (op) {
      case OP.pop: pop(); return next;
      case OP.pop2: pop(); pop(); return next;
      case OP.dup: push(stack.at(-1)); return next;
      case OP.dup_x1: { const a = pop(); const b = pop(); stack.push(a, b, a); return next; }
      case OP.dup_x2: { const a = pop(); const b = pop(); const c = pop(); stack.push(a, c, b, a); return next; }
      case OP.dup2: { const a = pop(); const b = pop(); stack.push(b, a, b, a); return next; }
      case OP.dup2_x1: { const a = pop(); const b = pop(); const c = pop(); stack.push(b, a, c, b, a); return next; }
      case OP.dup2_x2: { const a = pop(); const b = pop(); const c = pop(); const d = pop(); stack.push(b, a, d, c, b, a); return next; }
      case OP.swap: { const a = pop(); const b = pop(); stack.push(a, b); return next; }
      case OP.iadd: { const b = pop(); push(I32(pop() + b)); return next; }
      case OP.isub: { const b = pop(); push(I32(pop() - b)); return next; }
      case OP.imul: { const b = pop(); push(Math.imul(pop(), b)); return next; }
      case OP.idiv: case OP.irem: {
        const b = pop();
        const a = pop();
        if (b === 0) throw new JavaThrow('java/lang/ArithmeticException', '/ by zero');
        push(op === OP.idiv ? I32(Math.trunc(a / b)) : I32(a % b));
        return next;
      }
      case OP.ladd: { const b = pop2(); push2(L64(pop2() + b)); return next; }
      case OP.lsub: { const b = pop2(); push2(L64(pop2() - b)); return next; }
      case OP.lmul: { const b = pop2(); push2(L64(pop2() * b)); return next; }
      case OP.ldiv: case OP.lrem: {
        const b = pop2();
        const a = pop2();
        if (b === 0n) throw new JavaThrow('java/lang/ArithmeticException', '/ by zero');
        push2(L64(op === OP.ldiv ? a / b : a % b));
        return next;
      }
      case OP.fadd: { const b = pop(); push(F32(pop() + b)); return next; }
      case OP.fsub: { const b = pop(); push(F32(pop() - b)); return next; }
      case OP.fmul: { const b = pop(); push(F32(pop() * b)); return next; }
      case OP.fdiv: { const b = pop(); push(F32(pop() / b)); return next; }
      case OP.frem: { const b = pop(); push(F32(pop() % b)); return next; }
      case OP.dadd: { const b = pop2(); push2(pop2() + b); return next; }
      case OP.dsub: { const b = pop2(); push2(pop2() - b); return next; }
      case OP.dmul: { const b = pop2(); push2(pop2() * b); return next; }
      case OP.ddiv: { const b = pop2(); push2(pop2() / b); return next; }
      case OP.drem: { const b = pop2(); push2(pop2() % b); return next; }
      case OP.ineg: push(I32(-pop())); return next;
      case OP.lneg: push2(L64(-pop2())); return next;
      case OP.fneg: push(-pop()); return next;
      case OP.dneg: push2(-pop2()); return next;
      case OP.ishl: { const b = pop(); push(pop() << (b & 31)); return next; }
      case OP.ishr: { const b = pop(); push(pop() >> (b & 31)); return next; }
      case OP.iushr: { const b = pop(); push(I32(pop() >>> (b & 31))); return next; }
      case OP.lshl: { const b = pop(); push2(L64(pop2() << BigInt(b & 63))); return next; }
      case OP.lshr: { const b = pop(); push2(pop2() >> BigInt(b & 63)); return next; }
      case OP.lushr: { const b = pop(); push2(L64(BigInt.asUintN(64, pop2()) >> BigInt(b & 63))); return next; }
      case OP.iand: { const b = pop(); push(pop() & b); return next; }
      case OP.ior: { const b = pop(); push(pop() | b); return next; }
      case OP.ixor: { const b = pop(); push(pop() ^ b); return next; }
      case OP.land: { const b = pop2(); push2(L64(pop2() & b)); return next; }
      case OP.lor: { const b = pop2(); push2(L64(pop2() | b)); return next; }
      case OP.lxor: { const b = pop2(); push2(L64(pop2() ^ b)); return next; }
      case OP.iinc: locals[ins.local] = I32(locals[ins.local] + ins.value); return next;
      case OP.i2l: push2(BigInt(pop())); return next;
      case OP.i2f: push(F32(pop())); return next;
      case OP.i2d: push2(pop()); return next;
      case OP.l2i: push(Number(BigInt.asIntN(32, pop2()))); return next;
      case OP.l2f: push(F32(Number(pop2()))); return next;
      case OP.l2d: push2(Number(pop2())); return next;
      case OP.f2i: push(toInt(pop())); return next;
      case OP.f2l: push2(toLong(pop())); return next;
      case OP.f2d: push2(pop()); return next;
      case OP.d2i: push(toInt(pop2())); return next;
      case OP.d2l: push2(toLong(pop2())); return next;
      case OP.d2f: push(F32(pop2())); return next;
      case OP.i2b: push((pop() << 24) >> 24); return next;
      case OP.i2c: push(pop() & 0xffff); return next;
      case OP.i2s: push((pop() << 16) >> 16); return next;
      case OP.lcmp: { const b = pop2(); const a = pop2(); push(a < b ? -1 : a > b ? 1 : 0); return next; }
      case OP.fcmpl: case OP.fcmpg: { const b = pop(); push(fcmp(pop(), b, op === OP.fcmpl ? -1 : 1)); return next; }
      case OP.dcmpl: case OP.dcmpg: { const b = pop2(); push(fcmp(pop2(), b, op === OP.dcmpl ? -1 : 1)); return next; }
      case OP.ifeq: return pop() === 0 ? ins.target : next;
      case OP.ifne: return pop() !== 0 ? ins.target : next;
      case OP.iflt: return pop() < 0 ? ins.target : next;
      case OP.ifge: return pop() >= 0 ? ins.target : next;
      case OP.ifgt: return pop() > 0 ? ins.target : next;
      case OP.ifle: return pop() <= 0 ? ins.target : next;
      case OP.if_icmpeq: { const b = pop(); return pop() === b ? ins.target : next; }
      case OP.if_icmpne: { const b = pop(); return pop() !== b ? ins.target : next; }
      case OP.if_icmplt: { const b = pop(); return pop() < b ? ins.target : next; }
      case OP.if_icmpge: { const b = pop(); return pop() >= b ? ins.target : next; }
      case OP.if_icmpgt: { const b = pop(); return pop() > b ? ins.target : next; }
      case OP.if_icmple: { const b = pop(); return pop() <= b ? ins.target : next; }
      // shortcut: dizgeler kimlik yerine değerle karşılaştırılır; çözücülerde == ile dizge karşılaştırması nadirdir
      case OP.if_acmpeq: { const b = pop(); return pop() === b ? ins.target : next; }
      case OP.if_acmpne: { const b = pop(); return pop() !== b ? ins.target : next; }
      case OP.ifnull: return pop() === null ? ins.target : next;
      case OP.ifnonnull: return pop() !== null ? ins.target : next;
      case OP.goto: case OP.goto_w: return ins.target;
      case OP.tableswitch: case OP.lookupswitch: {
        const k = pop();
        const hit = ins.cases.find((c) => c[0] === k);
        return hit ? hit[1] : ins.default;
      }
      case OP.ireturn: case OP.freturn: case OP.areturn: stack.retval = pop(); return RETURN;
      case OP.lreturn: case OP.dreturn: stack.retval = pop2(); return RETURN;
      case OP.return: stack.retval = undefined; return RETURN;
      case OP.getstatic: case OP.putstatic: {
        const r = ref(cf, ins.index);
        const fld = findField(r.owner, r.name);
        if (!fld) throw new Unsupported(`arşiv dışı statik alan: ${r.owner}.${r.name}`);
        initClass(fld.owner);
        const key = `${fld.owner}.${r.name}`;
        if (op === OP.getstatic && mutable.has(key)) throw new Unsupported(`çalışma anında değişen statik alana bağlı: ${key}`);
        if (op === OP.getstatic) {
          if (!statics.has(key)) throw new Unsupported(`statik olmayan alan: ${key}`);
          if (wide(r.desc)) push2(statics.get(key)); else push(statics.get(key));
        } else statics.set(key, wide(r.desc) ? pop2() : pop());
        return next;
      }
      case OP.getfield: case OP.putfield: throw new Unsupported('nesne alanı erişimi');
      case OP.invokestatic: case OP.invokevirtual: case OP.invokespecial: case OP.invokeinterface: {
        const r = ref(cf, ins.index);
        const { params, ret } = parseMethodDesc(r.desc);
        const args = popArgs(stack, params);
        if (op !== OP.invokestatic) args.unshift(pop());
        if (op !== OP.invokestatic && args[0] === null) throw new JavaThrow('java/lang/NullPointerException');
        let result;
        const b = builtin(r.owner, r.name, r.desc) ?? (op !== OP.invokestatic && typeof args[0] === 'string' ? builtin('java/lang/String', r.name, r.desc) : undefined);
        if (b) {
          result = b(ctx, args);
          if (r.name === '<init>') {
            // başlatılmamış nesne yerine başlatılmış değer konur (yığında ve yerellerde aynı kimlik)
            const self = args[0];
            for (let i = 0; i < stack.length; i++) if (stack[i] === self) stack[i] = result;
            for (let i = 0; i < locals.length; i++) if (locals[i] === self) locals[i] = result;
            return next;
          }
        } else if (op === OP.invokestatic && classes.has(r.owner)) {
          const target = findMethod(r.owner, r.name, r.desc);
          if (!target || !target.m.code) throw new Unsupported(`yöntem bulunamadı: ${r.owner}.${r.name}${r.desc}`);
          initClass(thisName(target.cf));
          result = execute(target.cf, target.m, args);
        } else throw new Unsupported(`desteklenmeyen çağrı: ${r.owner}.${r.name}${r.desc}`);
        if (ret !== 'V') pushValue(stack, ret, result);
        return next;
      }
      case OP.invokedynamic: concat(cf, ins, stack); return next;
      case OP.new: {
        const cls = className(cf, ins.index);
        const o = allocate(cls);
        if (o === undefined) throw new Unsupported(`new ${cls}`);
        push(o);
        return next;
      }
      case OP.newarray: push(newArray(ctx, NEWARRAY_TYPES[ins.atype], pop())); return next;
      case OP.anewarray: {
        const t = className(cf, ins.index);
        push(newArray(ctx, t.startsWith('[') ? t : `L${t};`, pop()));
        return next;
      }
      case OP.arraylength: {
        const a = pop();
        if (a === null) throw new JavaThrow('java/lang/NullPointerException');
        if (!isArray(a)) throw new Unsupported('arraylength: dizi değil');
        push(a.data.length);
        return next;
      }
      case OP.athrow: {
        const e = pop();
        if (e === null) throw new JavaThrow('java/lang/NullPointerException');
        if (e?.exc) throw new JavaThrow(e.exc);
        throw new Unsupported('athrow (istisna nesnesi oluşturulamaz)');
      }
      case OP.checkcast: case OP.instanceof: {
        const t = className(cf, ins.index);
        const v = stack.at(-1);
        let ok;
        if (v === null) ok = op === OP.checkcast;
        else if (t === 'java/lang/Object') ok = true;
        else if (t === 'java/lang/String' || t === 'java/lang/CharSequence') ok = typeof v === 'string' || (t === 'java/lang/CharSequence' && Boolean(v?.s !== undefined));
        else if (t.startsWith('[')) ok = isArray(v) && (v.arr === t.slice(1) || `[${v.arr}` === t);
        else if (v?.cls) ok = v.cls === t;
        else throw new Unsupported(`tür denetimi: ${t}`);
        if (op === OP.instanceof) { pop(); push(ok ? 1 : 0); } else if (!ok) throw new JavaThrow('java/lang/ClassCastException', t);
        return next;
      }
      case OP.monitorenter: case OP.monitorexit: pop(); return next;
      default: throw new Unsupported(`desteklenmeyen komut ${ins.name}`);
    }
  }

  return {
    /** Statik yöntemi verilen argümanlarla çalıştırır (her çağrı yeni bütçeyle) */
    invoke(owner, name, desc, args, limits2 = limits) {
      ctx = createContext(limits2);
      const target = findMethod(owner, name, desc);
      if (!target) throw new Unsupported(`yöntem yok: ${owner}.${name}${desc}`);
      if (!(target.m.access & ACC.STATIC)) throw new Unsupported('statik değil');
      initClass(thisName(target.cf));
      return execute(target.cf, target.m, args);
    },
    /** Statik alanın değeri (sınıf başlatılarak) */
    getStatic(owner, name, limits2 = limits) {
      ctx = createContext(limits2);
      const fld = findField(owner, name);
      if (!fld) throw new Unsupported(`alan yok: ${owner}.${name}`);
      initClass(fld.owner);
      return statics.get(`${fld.owner}.${name}`);
    },
    steps: () => ctx.steps,
  };
}

export { Unsupported, BudgetExceeded, JavaThrow };
