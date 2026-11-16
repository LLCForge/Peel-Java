// Dalvik komut tablosu ve çözücü (Dalvik bytecode biçimleri). Konumlar 16 bitlik kod birimidir.
import { ParseError } from '../core/bytes.js';

const T = [];
const def = (op, name, fmt, kind = null) => { T[op] = { name, fmt, kind }; };
const seq = (start, names, fmt, kind = null) => names.split(' ').forEach((n, i) => def(start + i, n, fmt, kind));

def(0x00, 'nop', '10x');
seq(0x01, 'move move/from16 move/16 move-wide move-wide/from16 move-wide/16 move-object move-object/from16 move-object/16', '12x');
for (const [op, fmt] of [[0x02, '22x'], [0x03, '32x'], [0x05, '22x'], [0x06, '32x'], [0x08, '22x'], [0x09, '32x']]) T[op].fmt = fmt;
seq(0x0a, 'move-result move-result-wide move-result-object move-exception', '11x');
def(0x0e, 'return-void', '10x');
seq(0x0f, 'return return-wide return-object', '11x');
def(0x12, 'const/4', '11n');
def(0x13, 'const/16', '21s');
def(0x14, 'const', '31i');
def(0x15, 'const/high16', '21h');
def(0x16, 'const-wide/16', '21s');
def(0x17, 'const-wide/32', '31i');
def(0x18, 'const-wide', '51l');
def(0x19, 'const-wide/high16', '21h');
def(0x1a, 'const-string', '21c', 'string');
def(0x1b, 'const-string/jumbo', '31c', 'string');
def(0x1c, 'const-class', '21c', 'type');
def(0x1d, 'monitor-enter', '11x');
def(0x1e, 'monitor-exit', '11x');
def(0x1f, 'check-cast', '21c', 'type');
def(0x20, 'instance-of', '22c', 'type');
def(0x21, 'array-length', '12x');
def(0x22, 'new-instance', '21c', 'type');
def(0x23, 'new-array', '22c', 'type');
def(0x24, 'filled-new-array', '35c', 'type');
def(0x25, 'filled-new-array/range', '3rc', 'type');
def(0x26, 'fill-array-data', '31t');
def(0x27, 'throw', '11x');
def(0x28, 'goto', '10t');
def(0x29, 'goto/16', '20t');
def(0x2a, 'goto/32', '30t');
def(0x2b, 'packed-switch', '31t');
def(0x2c, 'sparse-switch', '31t');
seq(0x2d, 'cmpl-float cmpg-float cmpl-double cmpg-double cmp-long', '23x');
seq(0x32, 'if-eq if-ne if-lt if-ge if-gt if-le', '22t');
seq(0x38, 'if-eqz if-nez if-ltz if-gez if-gtz if-lez', '21t');
seq(0x44, 'aget aget-wide aget-object aget-boolean aget-byte aget-char aget-short aput aput-wide aput-object aput-boolean aput-byte aput-char aput-short', '23x');
seq(0x52, 'iget iget-wide iget-object iget-boolean iget-byte iget-char iget-short iput iput-wide iput-object iput-boolean iput-byte iput-char iput-short', '22c', 'field');
seq(0x60, 'sget sget-wide sget-object sget-boolean sget-byte sget-char sget-short sput sput-wide sput-object sput-boolean sput-byte sput-char sput-short', '21c', 'field');
seq(0x6e, 'invoke-virtual invoke-super invoke-direct invoke-static invoke-interface', '35c', 'method');
seq(0x74, 'invoke-virtual/range invoke-super/range invoke-direct/range invoke-static/range invoke-interface/range', '3rc', 'method');
seq(0x7b, 'neg-int not-int neg-long not-long neg-float neg-double int-to-long int-to-float int-to-double long-to-int long-to-float long-to-double float-to-int float-to-long float-to-double double-to-int double-to-long double-to-float int-to-byte int-to-char int-to-short', '12x');
export const BINOPS = 'add-int sub-int mul-int div-int rem-int and-int or-int xor-int shl-int shr-int ushr-int add-long sub-long mul-long div-long rem-long and-long or-long xor-long shl-long shr-long ushr-long add-float sub-float mul-float div-float rem-float add-double sub-double mul-double div-double rem-double';
seq(0x90, BINOPS, '23x');
seq(0xb0, BINOPS.split(' ').map((n) => `${n}/2addr`).join(' '), '12x');
seq(0xd0, 'add-int/lit16 rsub-int mul-int/lit16 div-int/lit16 rem-int/lit16 and-int/lit16 or-int/lit16 xor-int/lit16', '22s');
seq(0xd8, 'add-int/lit8 rsub-int/lit8 mul-int/lit8 div-int/lit8 rem-int/lit8 and-int/lit8 or-int/lit8 xor-int/lit8 shl-int/lit8 shr-int/lit8 ushr-int/lit8', '22b');
def(0xfa, 'invoke-polymorphic', '45cc', 'method');
def(0xfb, 'invoke-polymorphic/range', '4rcc', 'method');
def(0xfc, 'invoke-custom', '35c', 'callsite');
def(0xfd, 'invoke-custom/range', '3rc', 'callsite');
def(0xfe, 'const-method-handle', '21c', 'methodhandle');
def(0xff, 'const-method-type', '21c', 'proto');
for (let i = 0; i < 256; i++) if (!T[i]) def(i, `unused-${i.toString(16).padStart(2, '0')}`, '10x');

const SIZE = { '10x': 1, '12x': 1, '11n': 1, '11x': 1, '10t': 1, '20t': 2, '22x': 2, '21t': 2, '21s': 2, '21h': 2, '21c': 2, '23x': 2, '22b': 2, '22t': 2, '22s': 2, '22c': 2, '30t': 3, '32x': 3, '31i': 3, '31t': 3, '31c': 3, '35c': 3, '3rc': 3, '45cc': 4, '4rcc': 4, '51l': 5 };
export const opInfo = (op) => T[op];

/** Tek komut: { pc, op, name, fmt, len, a, b, c, regs, index, lit, target, payload } */
export function decodeAt(insns, pc) {
  const need = (n) => { if (pc + n > insns.length) throw new ParseError(`komut gövde dışına taşıyor (pc ${pc})`); };
  need(1);
  const u = insns[pc];
  const op = u & 0xff;
  const hi = u >> 8;
  // veri yükleri (switch tabloları, dizi verisi): nop + yüksek bayt
  if (op === 0 && hi >= 1 && hi <= 3) {
    need(2);
    let len;
    if (hi === 1) len = 4 + insns[pc + 1] * 2;
    else if (hi === 2) len = 2 + insns[pc + 1] * 4;
    else { need(4); const width = insns[pc + 1]; const size = insns[pc + 2] | (insns[pc + 3] << 16); len = 4 + Math.ceil((width * size) / 2); }
    need(len);
    return { pc, op, name: ['', 'packed-switch-payload', 'sparse-switch-payload', 'array-payload'][hi], fmt: 'payload', len, payloadKind: hi };
  }
  const { name, fmt, kind } = T[op];
  const len = SIZE[fmt];
  need(len);
  const ins = { pc, op, name, fmt, len, kind };
  const s16 = (x) => (x << 16) >> 16;
  const u32 = (i) => (insns[pc + i] | (insns[pc + i + 1] << 16)) >>> 0;
  switch (fmt) {
    case '10x': break;
    case '12x': ins.a = hi & 0xf; ins.b = hi >> 4; break;
    case '11n': ins.a = hi & 0xf; ins.lit = ((hi >> 4) << 28) >> 28; break;
    case '11x': ins.a = hi; break;
    case '10t': ins.target = pc + ((hi << 24) >> 24); break;
    case '20t': ins.target = pc + s16(insns[pc + 1]); break;
    case '22x': ins.a = hi; ins.b = insns[pc + 1]; break;
    case '21t': ins.a = hi; ins.target = pc + s16(insns[pc + 1]); break;
    case '21s': ins.a = hi; ins.lit = s16(insns[pc + 1]); break;
    case '21h': ins.a = hi; ins.lit = s16(insns[pc + 1]); break;
    case '21c': ins.a = hi; ins.index = insns[pc + 1]; break;
    case '23x': ins.a = hi; ins.b = insns[pc + 1] & 0xff; ins.c = insns[pc + 1] >> 8; break;
    case '22b': ins.a = hi; ins.b = insns[pc + 1] & 0xff; ins.lit = ((insns[pc + 1] >> 8) << 24) >> 24; break;
    case '22t': ins.a = hi & 0xf; ins.b = hi >> 4; ins.target = pc + s16(insns[pc + 1]); break;
    case '22s': ins.a = hi & 0xf; ins.b = hi >> 4; ins.lit = s16(insns[pc + 1]); break;
    case '22c': ins.a = hi & 0xf; ins.b = hi >> 4; ins.index = insns[pc + 1]; break;
    case '30t': ins.target = pc + (u32(1) | 0); break;
    case '32x': ins.a = insns[pc + 1]; ins.b = insns[pc + 2]; break;
    case '31i': ins.a = hi; ins.lit = u32(1) | 0; break;
    case '31t': ins.a = hi; ins.target = pc + (u32(1) | 0); break;
    case '31c': ins.a = hi; ins.index = u32(1); break;
    case '35c': case '45cc': {
      const count = hi >> 4;
      if (count > 5) throw new ParseError(`geçersiz argüman sayısı (pc ${pc})`);
      ins.index = insns[pc + 1];
      const w = insns[pc + 2];
      ins.regs = [w & 0xf, (w >> 4) & 0xf, (w >> 8) & 0xf, (w >> 12) & 0xf, hi & 0xf].slice(0, count);
      if (fmt === '45cc') ins.proto = insns[pc + 3];
      break;
    }
    case '3rc': case '4rcc': {
      ins.index = insns[pc + 1];
      const first = insns[pc + 2];
      ins.regs = Array.from({ length: hi }, (_, i) => first + i);
      if (fmt === '4rcc') ins.proto = insns[pc + 3];
      break;
    }
    case '51l': {
      ins.a = hi;
      let v = 0n;
      for (let i = 4; i >= 1; i--) v = (v << 16n) | BigInt(insns[pc + i]);
      ins.wide = BigInt.asIntN(64, v);
      break;
    }
    default: throw new ParseError(`bilinmeyen biçim ${fmt}`);
  }
  if (name === 'const/high16') ins.lit = (ins.lit << 16) | 0;
  if (name === 'const-wide/high16') ins.wide = BigInt.asIntN(64, BigInt(ins.lit) << 48n);
  else if (name.startsWith('const-wide') && ins.wide === undefined) ins.wide = BigInt(ins.lit);
  return ins;
}

export function decode(insns) {
  const out = [];
  for (let pc = 0; pc < insns.length;) {
    const ins = decodeAt(insns, pc);
    out.push(ins);
    pc += ins.len;
  }
  return out;
}

/** switch ve dizi veri yüklerinin içeriği */
export function payloadAt(insns, at) {
  const kind = insns[at] >> 8;
  const i32 = (i) => (insns[at + i] | (insns[at + i + 1] << 16)) | 0;
  if (kind === 1) {
    const size = insns[at + 1];
    const first = i32(2);
    return { kind: 'packed', cases: Array.from({ length: size }, (_, i) => [first + i, i32(4 + i * 2)]) };
  }
  if (kind === 2) {
    const size = insns[at + 1];
    return { kind: 'sparse', cases: Array.from({ length: size }, (_, i) => [i32(2 + i * 2), i32(2 + size * 2 + i * 2)]) };
  }
  if (kind === 3) {
    const width = insns[at + 1];
    const size = (insns[at + 2] | (insns[at + 3] << 16)) >>> 0;
    const bytes = new Uint8Array(insns.buffer, insns.byteOffset + (at + 4) * 2, width * size);
    return { kind: 'array', width, size, bytes };
  }
  throw new ParseError(`geçersiz veri yükü (pc ${at})`);
}

export const isDalvikTerminal = (name) => name.startsWith('return') || name.startsWith('goto') || name === 'throw';
