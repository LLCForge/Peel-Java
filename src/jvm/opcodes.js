// JVM komut tablosu ve çözücü (JVMS 6.5). Her komut { pc, op, name, len } ve işlenen alanlarıyla döner.
import { ParseError } from '../core/bytes.js';

const NAMES = `nop aconst_null iconst_m1 iconst_0 iconst_1 iconst_2 iconst_3 iconst_4 iconst_5 lconst_0 lconst_1 fconst_0 fconst_1
fconst_2 dconst_0 dconst_1 bipush sipush ldc ldc_w ldc2_w iload lload fload dload aload iload_0 iload_1 iload_2 iload_3 lload_0
lload_1 lload_2 lload_3 fload_0 fload_1 fload_2 fload_3 dload_0 dload_1 dload_2 dload_3 aload_0 aload_1 aload_2 aload_3 iaload
laload faload daload aaload baload caload saload istore lstore fstore dstore astore istore_0 istore_1 istore_2 istore_3 lstore_0
lstore_1 lstore_2 lstore_3 fstore_0 fstore_1 fstore_2 fstore_3 dstore_0 dstore_1 dstore_2 dstore_3 astore_0 astore_1 astore_2
astore_3 iastore lastore fastore dastore aastore bastore castore sastore pop pop2 dup dup_x1 dup_x2 dup2 dup2_x1 dup2_x2 swap
iadd ladd fadd dadd isub lsub fsub dsub imul lmul fmul dmul idiv ldiv fdiv ddiv irem lrem frem drem ineg lneg fneg dneg ishl
lshl ishr lshr iushr lushr iand land ior lor ixor lxor iinc i2l i2f i2d l2i l2f l2d f2i f2l f2d d2i d2l d2f i2b i2c i2s lcmp
fcmpl fcmpg dcmpl dcmpg ifeq ifne iflt ifge ifgt ifle if_icmpeq if_icmpne if_icmplt if_icmpge if_icmpgt if_icmple if_acmpeq
if_acmpne goto jsr ret tableswitch lookupswitch ireturn lreturn freturn dreturn areturn return getstatic putstatic getfield
putfield invokevirtual invokespecial invokestatic invokeinterface invokedynamic new newarray anewarray arraylength athrow
checkcast instanceof monitorenter monitorexit wide multianewarray ifnull ifnonnull goto_w jsr_w`.split(/\s+/);

export const OP = Object.fromEntries(NAMES.map((n, i) => [n, i]));
export const opName = (op) => NAMES[op] ?? `op_${op}`;

// işlenen biçimi: b s1, s s2, c1 havuz u1, c2 havuz u2, l yerel u1, j2/j4 dal, ...
const FORMAT = new Map();
const set = (fmt, ...names) => { for (const n of names) FORMAT.set(OP[n], fmt); };
set('b', 'bipush');
set('s', 'sipush');
set('c1', 'ldc');
set('c2', 'ldc_w', 'ldc2_w', 'getstatic', 'putstatic', 'getfield', 'putfield', 'invokevirtual', 'invokespecial', 'invokestatic', 'new', 'anewarray', 'checkcast', 'instanceof');
set('l', 'iload', 'lload', 'fload', 'dload', 'aload', 'istore', 'lstore', 'fstore', 'dstore', 'astore', 'ret');
set('iinc', 'iinc');
set('j2', 'ifeq', 'ifne', 'iflt', 'ifge', 'ifgt', 'ifle', 'if_icmpeq', 'if_icmpne', 'if_icmplt', 'if_icmpge', 'if_icmpgt', 'if_icmple', 'if_acmpeq', 'if_acmpne', 'goto', 'jsr', 'ifnull', 'ifnonnull');
set('j4', 'goto_w', 'jsr_w');
set('iface', 'invokeinterface');
set('indy', 'invokedynamic');
set('newarray', 'newarray');
set('multi', 'multianewarray');

export const NEWARRAY_TYPES = { 4: 'Z', 5: 'C', 6: 'F', 7: 'D', 8: 'B', 9: 'S', 10: 'I', 11: 'J' };

/** Tek komut çözer */
export function decodeAt(code, pc) {
  const op = code[pc];
  const dv = new DataView(code.buffer, code.byteOffset, code.byteLength);
  const need = (n) => { if (pc + n > code.length) throw new ParseError(`komut gövde dışına taşıyor (pc ${pc})`); };
  const ins = { pc, op, name: opName(op), len: 1 };
  if (op > 201) throw new ParseError(`geçersiz komut 0x${op.toString(16)} (pc ${pc})`);
  switch (FORMAT.get(op)) {
    case 'b': need(2); ins.value = dv.getInt8(pc + 1); ins.len = 2; break;
    case 's': need(3); ins.value = dv.getInt16(pc + 1); ins.len = 3; break;
    case 'c1': need(2); ins.index = code[pc + 1]; ins.len = 2; break;
    case 'c2': need(3); ins.index = dv.getUint16(pc + 1); ins.len = 3; break;
    case 'l': need(2); ins.local = code[pc + 1]; ins.len = 2; break;
    case 'iinc': need(3); ins.local = code[pc + 1]; ins.value = dv.getInt8(pc + 2); ins.len = 3; break;
    case 'j2': need(3); ins.target = pc + dv.getInt16(pc + 1); ins.len = 3; break;
    case 'j4': need(5); ins.target = pc + dv.getInt32(pc + 1); ins.len = 5; break;
    case 'iface': need(5); ins.index = dv.getUint16(pc + 1); ins.count = code[pc + 3]; ins.len = 5; break;
    case 'indy': need(5); ins.index = dv.getUint16(pc + 1); ins.len = 5; break;
    case 'newarray': need(2); ins.atype = code[pc + 1]; ins.len = 2; break;
    case 'multi': need(4); ins.index = dv.getUint16(pc + 1); ins.dims = code[pc + 3]; ins.len = 4; break;
    default:
      if (op === OP.tableswitch || op === OP.lookupswitch) {
        let p = (pc + 4) & ~3;
        need(p - pc + 12);
        ins.default = pc + dv.getInt32(p);
        if (op === OP.tableswitch) {
          const low = dv.getInt32(p + 4);
          const high = dv.getInt32(p + 8);
          const n = high - low + 1;
          if (n < 0 || n > 65536) throw new ParseError(`geçersiz tableswitch (pc ${pc})`);
          need(p - pc + 12 + n * 4);
          ins.cases = [];
          for (let i = 0; i < n; i++) ins.cases.push([low + i, pc + dv.getInt32(p + 12 + i * 4)]);
          ins.len = p + 12 + n * 4 - pc;
        } else {
          const n = dv.getInt32(p + 4);
          if (n < 0 || n > 65536) throw new ParseError(`geçersiz lookupswitch (pc ${pc})`);
          need(p - pc + 8 + n * 8);
          ins.cases = [];
          for (let i = 0; i < n; i++) ins.cases.push([dv.getInt32(p + 8 + i * 8), pc + dv.getInt32(p + 12 + i * 8)]);
          ins.len = p + 8 + n * 8 - pc;
        }
      } else if (op === OP.wide) {
        need(4);
        ins.wideOp = code[pc + 1];
        ins.local = dv.getUint16(pc + 2);
        ins.name = `wide ${opName(ins.wideOp)}`;
        if (ins.wideOp === OP.iinc) { need(6); ins.value = dv.getInt16(pc + 4); ins.len = 6; } else ins.len = 4;
      }
  }
  return ins;
}

/** Gövdenin tüm komutları */
export function decode(code) {
  const out = [];
  for (let pc = 0; pc < code.length;) {
    const ins = decodeAt(code, pc);
    out.push(ins);
    pc += ins.len;
  }
  return out;
}

// komutun yereli: iload_2 → 2
export function localOf(ins) {
  if (ins.local !== undefined) return ins.local;
  const n = ins.name;
  const m = /^[ilfda](?:load|store)_(\d)$/.exec(n);
  return m ? Number(m[1]) : -1;
}

/** Akışı bitiren komutlar (sonraki komuta düşmez) */
export const isTerminal = (op) => op === OP.goto || op === OP.goto_w || op === OP.athrow || op === OP.tableswitch || op === OP.lookupswitch || op === OP.ret || (op >= OP.ireturn && op <= OP.return);

/** Dallanma hedefleri */
export function targetsOf(ins) {
  if (ins.target !== undefined) return [ins.target];
  if (ins.cases) return [ins.default, ...ins.cases.map((c) => c[1])];
  return [];
}

/** Temel blok başları: dal hedefleri, dal sonrası komutlar ve istisna işleyicileri */
export function leaders(insns, exceptions = []) {
  const set = new Set([0]);
  for (const ins of insns) {
    const t = targetsOf(ins);
    for (const x of t) set.add(x);
    if (t.length || isTerminal(ins.op)) set.add(ins.pc + ins.len);
  }
  for (const e of exceptions) { set.add(e.handler); set.add(e.start); set.add(e.end); }
  return set;
}
