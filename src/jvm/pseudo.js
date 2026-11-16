// Yapılandırılmış sözde Java görünümü. Yığın sembolik yürütülür, ifadeler birleştirilir; dallar "if (...) goto L;" ve
// etiketlerle gösterilir (döngü/koşul yapısı geri kurulmaz). Temel blok sınırında yığın boş değilse (üçlü ifade vb.),
// jsr/ret görülürse ya da yöntem çok büyükse o yöntem için dürüstçe bytecode listesine düşülür.
import { decode, leaders, OP, NEWARRAY_TYPES, isTerminal } from './opcodes.js';
import { constant, ref, nat, className, thisName, memberName, memberDesc, parseMethodDesc, javaType, findAttr, utf8, ACC, slots } from './classfile.js';
import { javaString, classHeader, methodSignature, operand, flags } from './disasm.js';
import { Reader } from '../core/bytes.js';
import { LIMITS } from '../core/limits.js';

class Fallback extends Error {}
const BIN = { iadd: '+', ladd: '+', fadd: '+', dadd: '+', isub: '-', lsub: '-', fsub: '-', dsub: '-', imul: '*', lmul: '*', fmul: '*', dmul: '*', idiv: '/', ldiv: '/', fdiv: '/', ddiv: '/', irem: '%', lrem: '%', frem: '%', drem: '%', ishl: '<<', lshl: '<<', ishr: '>>', lshr: '>>', iushr: '>>>', lushr: '>>>', iand: '&', land: '&', ior: '|', lor: '|', ixor: '^', lxor: '^' };
const CAST = { i2l: 'long', i2f: 'float', i2d: 'double', l2i: 'int', l2f: 'float', l2d: 'double', f2i: 'int', f2l: 'long', f2d: 'double', d2i: 'int', d2l: 'long', d2f: 'float', i2b: 'byte', i2c: 'char', i2s: 'short' };
const CMP0 = { ifeq: '==', ifne: '!=', iflt: '<', ifge: '>=', ifgt: '>', ifle: '<=' };
const CMP2 = { if_icmpeq: '==', if_icmpne: '!=', if_icmplt: '<', if_icmpge: '>=', if_icmpgt: '>', if_icmple: '<=', if_acmpeq: '==', if_acmpne: '!=' };
const lbl = (pc) => `L${pc}`;
const dotted = (n) => n.replaceAll('/', '.');
const simple = (n) => dotted(n).slice(dotted(n).lastIndexOf('.') + 1);
const wrap = (e) => (e.atom ? e.s : `(${e.s})`);
const atom = (s, extra = {}) => ({ s, atom: true, ...extra });
const expr = (s, extra = {}) => ({ s, atom: false, ...extra });

function localNames(cf, m) {
  const names = new Map();
  const isStatic = Boolean(m.access & ACC.STATIC);
  const { params } = parseMethodDesc(memberDesc(cf, m));
  let slot = 0;
  if (!isStatic) names.set(slot++, 'this');
  params.forEach((p, i) => { names.set(slot, `p${i}`); slot += slots(p); });
  const lvt = findAttr(cf, m.code.attrs, 'LocalVariableTable');
  const fromTable = new Map();
  if (lvt) {
    try {
      const r = new Reader(lvt.data);
      const n = r.u2();
      for (let i = 0; i < n; i++) { r.u2(); r.u2(); const name = utf8(cf, r.u2()); r.u2(); const idx = r.u2(); if (/^[A-Za-z_$][\w$]*$/.test(name)) fromTable.set(idx, name); }
    } catch { /* bozuk tablo yok sayılır */ }
  }
  return (i) => fromTable.get(i) ?? names.get(i) ?? `v${i}`;
}

function methodPseudo(cf, m, decrypted) {
  const insns = decode(m.code.code);
  if (insns.length > LIMITS.pseudoInsns) throw new Fallback(`method too large (${insns.length} instructions)`);
  const lead = leaders(insns, m.code.exceptions);
  const targets = new Set();
  for (const ins of insns) { if (ins.target !== undefined) targets.add(ins.target); if (ins.cases) { targets.add(ins.default); for (const [, t] of ins.cases) targets.add(t); } }
  const handlers = new Map(m.code.exceptions.map((e) => [e.handler, e]));
  for (const h of handlers.keys()) targets.add(h);
  const local = localNames(cf, m);
  const out = [];
  let stack = [];
  let temp = 0;
  const pop = () => { if (!stack.length) throw new Fallback('stack underflow'); return stack.pop(); };
  const emit = (s) => out.push(`    ${s}`);
  // yan etkili ifadeler sırayı korumak için geçici değişkene alınır
  const flush = () => {
    for (let i = 0; i < stack.length; i++) {
      const e = stack[i];
      if (e.effect && !e.newObj) { const t = `t${temp++}`; emit(`${t} = ${e.s};`); stack[i] = atom(t, { cat: e.cat }); }
    }
  };
  const isStatic = Boolean(m.access & ACC.STATIC);
  // blok sınırını aşan yığın değerleri s0, s1... değişkenlerine dökülür; hedefteki yığın yüksekliği kaydedilir
  const heightAt = new Map();
  const spill = () => {
    for (let k = 0; k < stack.length; k++) {
      if (stack[k].s === `s${k}`) continue;
      emit(`s${k} = ${stack[k].s};`);
      stack[k] = atom(`s${k}`, { cat: stack[k].cat });
    }
  };
  const branchTo = (...pcs) => {
    if (stack.length) spill();
    for (const t of pcs) {
      const h = heightAt.get(t);
      if (h !== undefined && h !== stack.length) throw new Fallback(`inconsistent stack height (pc ${t})`);
      heightAt.set(t, stack.length);
    }
  };
  let prev = null;
  for (const e of m.code.exceptions) out.push(`    // try ${lbl(e.start)}..${lbl(e.end)} catch (${e.catchType ? dotted(className(cf, e.catchType)) : 'Throwable'}) -> ${lbl(e.handler)}`);
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (lead.has(ins.pc) && ins.pc !== 0) {
      if (prev && !isTerminal(prev.op)) branchTo(ins.pc);
      if (handlers.has(ins.pc)) stack = [atom('caught')];
      else {
        const h = heightAt.get(ins.pc) ?? 0;
        if (h === 0) heightAt.set(ins.pc, 0);
        stack = Array.from({ length: h }, (_, k) => atom(`s${k}`));
      }
    }
    prev = ins;
    if (targets.has(ins.pc)) out.push(`  ${lbl(ins.pc)}:`);
    const op = ins.op;
    const name = ins.name;
    const dec = decrypted?.get(ins.pc);
    if (op === OP.nop) continue;
    if (op >= OP.iconst_m1 && op <= OP.iconst_5) { stack.push(atom(String(op - OP.iconst_0))); continue; }
    if (op === OP.lconst_0 || op === OP.lconst_1) { stack.push(atom(`${op - OP.lconst_0}L`, { cat: 2 })); continue; }
    if (op >= OP.fconst_0 && op <= OP.fconst_2) { stack.push(atom(`${op - OP.fconst_0}.0f`)); continue; }
    if (op === OP.dconst_0 || op === OP.dconst_1) { stack.push(atom(`${op - OP.dconst_0}.0`, { cat: 2 })); continue; }
    if (op === OP.aconst_null) { stack.push(atom('null')); continue; }
    if (op === OP.bipush || op === OP.sipush) { stack.push(atom(String(ins.value))); continue; }
    if (op === OP.ldc || op === OP.ldc_w || op === OP.ldc2_w) {
      const c = constant(cf, ins.index);
      const s = c?.type === 'String' ? javaString(c.value) : c?.type === 'Class' ? `${dotted(c.value)}.class` : c?.type === 'J' ? `${c.value}L` : c?.type === 'F' ? `${c.value}f` : c ? String(typeof c.value === 'object' ? JSON.stringify(c.value) : c.value) : '?';
      stack.push(atom(s, { cat: c?.type === 'J' || c?.type === 'D' ? 2 : 1, decrypted: Boolean(dec) }));
      continue;
    }
    if ((op >= OP.iload && op <= OP.aload) || (op >= OP.iload_0 && op <= OP.aload_3)) {
      const k = ins.local ?? (op - OP.iload_0) % 4;
      const kind = op >= OP.iload_0 ? Math.floor((op - OP.iload_0) / 4) : op - OP.iload;
      stack.push(atom(local(k), { cat: kind === 1 || kind === 3 ? 2 : 1 }));
      continue;
    }
    if ((op >= OP.istore && op <= OP.astore) || (op >= OP.istore_0 && op <= OP.astore_3)) {
      const k = ins.local ?? (op - OP.istore_0) % 4;
      const v = pop();
      flush();
      emit(`${local(k)} = ${v.s};`);
      continue;
    }
    if (op >= OP.iaload && op <= OP.saload) { const idx = pop(); const a = pop(); stack.push(atom(`${wrap(a)}[${idx.s}]`, { cat: op === OP.laload || op === OP.daload ? 2 : 1 })); continue; }
    if (op >= OP.iastore && op <= OP.sastore) { const v = pop(); const idx = pop(); const a = pop(); flush(); emit(`${wrap(a)}[${idx.s}] = ${v.s};`); continue; }
    if (BIN[name]) { const b = pop(); const a = pop(); stack.push(expr(`${wrap(a)} ${BIN[name]} ${wrap(b)}`, { cat: name[0] === 'l' || name[0] === 'd' ? 2 : 1, effect: a.effect || b.effect })); continue; }
    if (CAST[name]) { const v = pop(); stack.push(expr(`(${CAST[name]}) ${wrap(v)}`, { cat: /2[ld]$/.test(name) ? 2 : 1, effect: v.effect })); continue; }
    switch (op) {
      case OP.ineg: case OP.lneg: case OP.fneg: case OP.dneg: { const v = pop(); stack.push(expr(`-${wrap(v)}`, { cat: v.cat })); continue; }
      case OP.iinc: case OP.wide:
        if (op === OP.wide && ins.wideOp !== OP.iinc) throw new Fallback('wide');
        flush();
        emit(`${local(ins.local)} += ${ins.value};`);
        continue;
      case OP.pop: { const v = pop(); if (v.effect || v.newObj) emit(`${v.s};`); continue; }
      case OP.pop2: { const v = pop(); if (v.cat !== 2) pop(); if (v.effect) emit(`${v.s};`); continue; }
      case OP.dup: { if (stack.at(-1)?.effect) flush(); const v = pop(); stack.push(v, v); continue; }
      case OP.dup_x1: { if (stack.at(-1)?.effect) flush(); const a = pop(); const b = pop(); stack.push(a, b, a); continue; }
      case OP.dup2: {
        const a = pop();
        if (a.cat === 2) { stack.push(a, a); continue; }
        const b = pop();
        if (a.effect || b.effect) throw new Fallback('dup2 of an expression with side effects');
        stack.push(b, a, b, a);
        continue;
      }
      case OP.swap: { const a = pop(); const b = pop(); stack.push(a, b); continue; }
      case OP.lcmp: case OP.fcmpl: case OP.fcmpg: case OP.dcmpl: case OP.dcmpg: { const b = pop(); const a = pop(); stack.push({ s: `compare(${a.s}, ${b.s})`, atom: true, cmp: [a, b] }); continue; }
      case OP.getstatic: { const r = ref(cf, ins.index); stack.push(atom(`${simple(r.owner)}.${r.name}`, { cat: slots(r.desc) })); continue; }
      case OP.putstatic: { const r = ref(cf, ins.index); const v = pop(); flush(); emit(`${simple(r.owner)}.${r.name} = ${v.s};`); continue; }
      case OP.getfield: { const r = ref(cf, ins.index); const o = pop(); stack.push(atom(`${wrap(o)}.${r.name}`, { cat: slots(r.desc) })); continue; }
      case OP.putfield: { const r = ref(cf, ins.index); const v = pop(); const o = pop(); flush(); emit(`${wrap(o)}.${r.name} = ${v.s};`); continue; }
      case OP.invokevirtual: case OP.invokespecial: case OP.invokestatic: case OP.invokeinterface: {
        const r = ref(cf, ins.index);
        const { params, ret } = parseMethodDesc(r.desc);
        const args = params.map(() => pop()).reverse();
        const recv = op === OP.invokestatic ? null : pop();
        const a = args.map((x) => x.s).join(', ');
        if (r.name === '<init>') {
          if (recv?.newObj && !recv.done) {
            recv.s = `new ${simple(r.owner)}(${a})`;
            recv.atom = false;
            recv.done = true;
            recv.effect = true;
            recv.newObj = false;
            if (!stack.includes(recv)) emit(`${recv.s};`);
          } else { flush(); emit(`${recv?.s === 'this' && !isStatic ? (r.owner === thisName(cf) ? 'this' : 'super') : recv?.s ?? '?'}(${a});`); }
          continue;
        }
        const target = op === OP.invokestatic ? simple(r.owner) : op === OP.invokespecial && recv?.s === 'this' && r.owner !== thisName(cf) ? 'super' : wrap(recv);
        const call = `${target}.${r.name}(${a})`;
        if (ret === 'V') { flush(); emit(`${call};`); } else stack.push(atom(call, { effect: true, cat: slots(ret) }));
        continue;
      }
      case OP.invokedynamic: {
        const e = cf.cp[ins.index];
        const n = nat(cf, e.natIndex);
        const { params, ret } = parseMethodDesc(n.desc);
        const args = params.map(() => pop()).reverse();
        const s = n.name === 'makeConcatWithConstants' || n.name === 'makeConcat' ? args.map((x) => wrap(x)).join(' + ') || '""' : `indy:${n.name}(${args.map((x) => x.s).join(', ')})`;
        if (ret === 'V') { flush(); emit(`${s};`); } else stack.push(expr(s, { effect: !n.name.startsWith('makeConcat'), cat: slots(ret) }));
        continue;
      }
      case OP.new: stack.push({ s: `new ${simple(className(cf, ins.index))}`, atom: false, newObj: true }); continue;
      case OP.newarray: { const n = pop(); flush(); const t = `t${temp++}`; emit(`${t} = new ${javaType(NEWARRAY_TYPES[ins.atype])}[${n.s}];`); stack.push(atom(t)); continue; }
      case OP.anewarray: { const n = pop(); flush(); const c = className(cf, ins.index); const t = `t${temp++}`; emit(`${t} = new ${c.startsWith('[') ? javaType(c) : simple(c)}[${n.s}];`); stack.push(atom(t)); continue; }
      case OP.multianewarray: { const dims = Array.from({ length: ins.dims }, () => pop()).reverse(); stack.push(atom(`new ${javaType(className(cf, ins.index)).replace(/\[\]/g, '')}${dims.map((d) => `[${d.s}]`).join('')}`)); continue; }
      case OP.arraylength: { const a = pop(); stack.push(atom(`${wrap(a)}.length`)); continue; }
      case OP.checkcast: { const v = pop(); const t = className(cf, ins.index); stack.push(expr(`(${t.startsWith('[') ? javaType(t) : simple(t)}) ${wrap(v)}`, { effect: v.effect })); continue; }
      case OP.instanceof: { const v = pop(); stack.push(expr(`${wrap(v)} instanceof ${simple(className(cf, ins.index))}`)); continue; }
      case OP.athrow: { const v = pop(); flush(); emit(`throw ${v.s};`); continue; }
      case OP.monitorenter: case OP.monitorexit: { const v = pop(); flush(); emit(`// ${name}(${v.s})`); continue; }
      case OP.ireturn: case OP.lreturn: case OP.freturn: case OP.dreturn: case OP.areturn: { const v = pop(); flush(); emit(`return ${v.s};`); continue; }
      case OP.return: flush(); emit('return;'); continue;
      case OP.goto: case OP.goto_w: flush(); branchTo(ins.target); emit(`goto ${lbl(ins.target)};`); continue;
      case OP.ifnull: case OP.ifnonnull: { const v = pop(); flush(); branchTo(ins.target); emit(`if (${wrap(v)} ${op === OP.ifnull ? '==' : '!='} null) goto ${lbl(ins.target)};`); continue; }
      case OP.tableswitch: case OP.lookupswitch: {
        const v = pop();
        flush();
        branchTo(ins.default, ...ins.cases.map((c) => c[1]));
        emit(`switch (${v.s}) {`);
        for (const [k, t] of ins.cases) emit(`  case ${k}: goto ${lbl(t)};`);
        emit(`  default: goto ${lbl(ins.default)};`);
        emit('}');
        continue;
      }
      default:
        if (CMP0[name]) {
          const v = pop();
          flush();
          branchTo(ins.target);
          const cond = v.cmp ? `${wrap(v.cmp[0])} ${CMP0[name]} ${wrap(v.cmp[1])}` : `${wrap(v)} ${CMP0[name]} 0`;
          emit(`if (${cond}) goto ${lbl(ins.target)};`);
          continue;
        }
        if (CMP2[name]) { const b = pop(); const a = pop(); flush(); branchTo(ins.target); emit(`if (${wrap(a)} ${CMP2[name]} ${wrap(b)}) goto ${lbl(ins.target)};`); continue; }
        throw new Fallback(`${name} is not supported`);
    }
  }
  return out;
}

function signature(cf, m) {
  const name = memberName(cf, m);
  if (name === '<clinit>') return 'static';
  const local = m.code ? localNames(cf, m) : null;
  const { params } = parseMethodDesc(memberDesc(cf, m));
  let slot = m.access & ACC.STATIC ? 0 : 1;
  const args = params.map((p, i) => { const n = local ? local(slot) : `p${i}`; slot += slots(p); return `${javaType(p)} ${n}`; });
  return methodSignature(cf, m).replace(/\(.*\)$/, `(${args.join(', ')})`);
}

/** Bir sınıfın sözde Java görünümü */
export function pseudoClass(cf) {
  const lines = [`${classHeader(cf)} {`];
  const stats = { methods: 0, structured: 0, fallback: 0 };
  for (const f of cf.fields) lines.push(`  ${[...flags(f.access, 'field'), javaType(memberDesc(cf, f))].join(' ')} ${memberName(cf, f)};`);
  for (const m of cf.methods) {
    lines.push('');
    if (!m.code) { lines.push(`  ${methodSignature(cf, m)};`); continue; }
    stats.methods++;
    lines.push(`  ${signature(cf, m)} {`);
    try {
      lines.push(...methodPseudo(cf, m));
      stats.structured++;
    } catch (e) {
      // bozuk ya da beklenmedik bytecode da dahil: dürüstçe bytecode listesine düşülür
      stats.fallback++;
      lines.push(`    /* Peel: no pseudo-Java for this method (${e.message}); bytecode: */`);
      try {
        for (const ins of decode(m.code.code)) if (ins.op !== OP.nop) lines.push(`    // ${String(ins.pc).padStart(4)}: ${ins.name} ${operand(cf, ins)}`.trimEnd());
      } catch (err) {
        lines.push(`    // cannot decode the body: ${err.message}`);
      }
    }
    lines.push('  }');
  }
  lines.push('}');
  return { text: lines.join('\n'), stats };
}
