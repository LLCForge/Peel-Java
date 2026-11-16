// Küçük DEX derleyicisi (yalnızca fixture üretimi için; Android SDK gerekmez). Tablolar DEX belirtimindeki sıralama
// kurallarıyla yazılır, map_list, Adler-32 sağlaması ve SHA-1 imzası hesaplanır.
import { createHash } from 'node:crypto';
import { Writer, encodeMutf8, adler32 } from '../../src/core/bytes.js';

const OPS = {
  nop: 0x00, move: 0x01, 'move-object': 0x07, 'move-result': 0x0a, 'move-result-wide': 0x0b, 'move-result-object': 0x0c, 'move-exception': 0x0d,
  'return-void': 0x0e, return: 0x0f, 'return-wide': 0x10, 'return-object': 0x11, 'const/4': 0x12, 'const/16': 0x13, const: 0x14,
  'const-wide/16': 0x16, 'const-string': 0x1a, 'const-class': 0x1c, 'check-cast': 0x1f, 'array-length': 0x21, 'new-instance': 0x22,
  'new-array': 0x23, 'fill-array-data': 0x26, throw: 0x27, 'goto/16': 0x29, 'packed-switch': 0x2b,
  'if-eq': 0x32, 'if-ne': 0x33, 'if-lt': 0x34, 'if-ge': 0x35, 'if-gt': 0x36, 'if-le': 0x37,
  'if-eqz': 0x38, 'if-nez': 0x39, 'if-ltz': 0x3a, 'if-gez': 0x3b, 'if-gtz': 0x3c, 'if-lez': 0x3d,
  aget: 0x44, 'aget-object': 0x46, 'aget-byte': 0x48, 'aget-char': 0x49, aput: 0x4b, 'aput-object': 0x4d, 'aput-byte': 0x4f, 'aput-char': 0x50,
  iget: 0x52, 'iget-object': 0x54, iput: 0x59, 'iput-object': 0x5b,
  sget: 0x60, 'sget-object': 0x62, sput: 0x67, 'sput-object': 0x69,
  'invoke-virtual': 0x6e, 'invoke-super': 0x6f, 'invoke-direct': 0x70, 'invoke-static': 0x71, 'invoke-interface': 0x72,
  'int-to-byte': 0x8d, 'int-to-char': 0x8e, 'add-int': 0x90, 'sub-int': 0x91, 'mul-int': 0x92, 'rem-int': 0x94, 'xor-int': 0x97,
  'add-int/2addr': 0xb0, 'xor-int/2addr': 0xb7, 'add-int/lit8': 0xd8, 'rem-int/lit8': 0xdc, 'xor-int/lit8': 0xdf, 'and-int/lit8': 0xdd,
};
const F12X = new Set(['move', 'move-object', 'array-length', 'int-to-byte', 'int-to-char', 'add-int/2addr', 'xor-int/2addr']);
const F11X = new Set(['move-result', 'move-result-wide', 'move-result-object', 'move-exception', 'return', 'return-wide', 'return-object', 'throw']);
const F23X = new Set(['aget', 'aget-object', 'aget-byte', 'aget-char', 'aput', 'aput-object', 'aput-byte', 'aput-char', 'add-int', 'sub-int', 'mul-int', 'rem-int', 'xor-int']);
const F22B = new Set(['add-int/lit8', 'rem-int/lit8', 'xor-int/lit8', 'and-int/lit8']);

class DexAsm {
  constructor(res) {
    this.res = res;
    this.u = [];
    this.labels = new Map();
    this.fix = [];
    this.payloads = [];
  }
  get pc() { return this.u.length; }
  label(n) { this.labels.set(n, this.pc); return this; }
  e(op, hi = 0) { this.u.push((hi << 8) | op); }
  op(name, ...a) {
    const op = OPS[name];
    if (op === undefined) throw new Error(`dexgen: bilinmeyen komut ${name}`);
    if (name === 'return-void' || name === 'nop') this.e(op);
    else if (F11X.has(name)) this.e(op, a[0]);
    else if (F12X.has(name)) this.e(op, (a[1] << 4) | a[0]);
    else if (F23X.has(name)) { this.e(op, a[0]); this.u.push((a[2] << 8) | a[1]); }
    else if (F22B.has(name)) { this.e(op, a[0]); this.u.push(((a[2] & 0xff) << 8) | a[1]); }
    else throw new Error(`dexgen: biçim yok ${name}`);
    return this;
  }
  const(reg, v) {
    if (v >= -8 && v <= 7 && reg < 16) this.e(OPS['const/4'], ((v & 0xf) << 4) | reg);
    else if (v >= -32768 && v <= 32767) { this.e(OPS['const/16'], reg); this.u.push(v & 0xffff); }
    else { this.e(OPS.const, reg); this.u.push(v & 0xffff, (v >>> 16) & 0xffff); }
    return this;
  }
  str(reg, s) { this.e(OPS['const-string'], reg); this.u.push(this.res.string(s)); return this; }
  type(name, reg, t) { this.e(OPS[name], reg); this.u.push(this.res.type(t)); return this; }
  newArray(a, sizeReg, t) { this.e(OPS['new-array'], (sizeReg << 4) | a); this.u.push(this.res.type(t)); return this; }
  field(name, reg, cls, fname, type) { this.e(OPS[name], reg); this.u.push(this.res.field(cls, fname, type)); return this; }
  ifield(name, a, b, cls, fname, type) { this.e(OPS[name], (b << 4) | a); this.u.push(this.res.field(cls, fname, type)); return this; }
  invoke(name, regs, cls, mname, params, ret) {
    const r = [...regs, 0, 0, 0, 0, 0];
    this.e(OPS[name], (regs.length << 4) | r[4]);
    this.u.push(this.res.method(cls, mname, params, ret), (r[3] << 12) | (r[2] << 8) | (r[1] << 4) | r[0]);
    return this;
  }
  jump(name, label, a = 0, b = 0) {
    const at = this.pc;
    if (name === 'goto/16') this.e(OPS[name]);
    else if (name.endsWith('z')) this.e(OPS[name], a);
    else this.e(OPS[name], (b << 4) | a);
    this.fix.push({ at: this.pc, from: at, label });
    this.u.push(0);
    return this;
  }
  /** fill-array-data: veri yükü yöntem sonuna eklenir */
  fillArray(reg, width, values) {
    const at = this.pc;
    this.e(OPS['fill-array-data'], reg);
    const p = { from: at, at: this.pc, width, values };
    this.payloads.push(p);
    this.u.push(0, 0);
    return this;
  }
  done() {
    for (const p of this.payloads) {
      if (this.u.length % 2) this.u.push(0);
      const off = this.u.length - p.from;
      this.u[p.at] = off & 0xffff;
      this.u[p.at + 1] = (off >>> 16) & 0xffff;
      const bytes = [];
      for (const v of p.values) for (let i = 0; i < p.width; i++) bytes.push((v >> (8 * i)) & 0xff);
      if (bytes.length % 2) bytes.push(0);
      this.u.push(0x0300, p.width, p.values.length & 0xffff, p.values.length >>> 16);
      for (let i = 0; i < bytes.length; i += 2) this.u.push(bytes[i] | (bytes[i + 1] << 8));
    }
    for (const f of this.fix) {
      const to = this.labels.get(f.label);
      if (to === undefined) throw new Error(`dexgen: etiket yok ${f.label}`);
      this.u[f.at] = (to - f.from) & 0xffff;
    }
    return Uint16Array.from(this.u);
  }
}

const shortyOf = (t) => (t.startsWith('[') || t.startsWith('L') ? 'L' : t);
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const cmpArr = (a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };

/**
 * classes: [{ type, access, superType, interfaces, sourceFile, fields: [{ name, type, access, value }],
 *             methods: [{ name, params, ret, access, registers, ins, outs, code(asm) }] }]
 * extraStrings: yalnızca dizge havuzuna girecek dizgeler (ör. derleyici işareti)
 */
export function buildDex(classes, { extraStrings = [] } = {}) {
  // 1. tur: başvuruları topla
  const S = new Set(extraStrings);
  const T = new Set();
  const P = new Map();
  const Fd = new Map();
  const M = new Map();
  const type = (t) => { T.add(t); S.add(t); return 0; };
  const proto = (params, ret) => {
    const k = `(${params.join('')})${ret}`;
    if (!P.has(k)) P.set(k, { params, ret, shorty: shortyOf(ret) + params.map(shortyOf).join('') });
    S.add(P.get(k).shorty);
    type(ret);
    params.forEach(type);
    return k;
  };
  const collect = {
    string: (s) => { S.add(s); return 0; },
    type,
    field: (cls, name, t) => { type(cls); type(t); S.add(name); Fd.set(`${cls}|${name}|${t}`, { cls, name, type: t }); return 0; },
    method: (cls, name, params, ret) => { type(cls); S.add(name); const p = proto(params, ret); M.set(`${cls}|${name}|${p}`, { cls, name, proto: p }); return 0; },
  };
  for (const c of classes) {
    type(c.type);
    if (c.superType) type(c.superType);
    (c.interfaces ?? []).forEach(type);
    if (c.sourceFile) S.add(c.sourceFile);
    for (const f of c.fields ?? []) { collect.field(c.type, f.name, f.type); if (typeof f.value === 'string') S.add(f.value); }
    for (const m of c.methods ?? []) {
      collect.method(c.type, m.name, m.params, m.ret);
      if (m.code) { const a = new DexAsm(collect); m.code(a); }
    }
  }
  // 2. sıralama ve indeksler
  const strings = [...S].sort(cmp);
  const si = new Map(strings.map((s, i) => [s, i]));
  const types = [...T].sort((a, b) => si.get(a) - si.get(b));
  const ti = new Map(types.map((t, i) => [t, i]));
  const protos = [...P.entries()].sort(([, a], [, b]) => ti.get(a.ret) - ti.get(b.ret) || cmpArr(a.params.map((x) => ti.get(x)), b.params.map((x) => ti.get(x))));
  const pi = new Map(protos.map(([k], i) => [k, i]));
  const fields = [...Fd.values()].sort((a, b) => ti.get(a.cls) - ti.get(b.cls) || si.get(a.name) - si.get(b.name) || ti.get(a.type) - ti.get(b.type));
  const fi = new Map(fields.map((f, i) => [`${f.cls}|${f.name}|${f.type}`, i]));
  const methods = [...M.values()].sort((a, b) => ti.get(a.cls) - ti.get(b.cls) || si.get(a.name) - si.get(b.name) || pi.get(a.proto) - pi.get(b.proto));
  const mi = new Map(methods.map((m, i) => [`${m.cls}|${m.name}|${m.proto}`, i]));
  const res = {
    string: (s) => si.get(s),
    type: (t) => ti.get(t),
    field: (cls, name, t) => fi.get(`${cls}|${name}|${t}`),
    method: (cls, name, params, ret) => mi.get(`${cls}|${name}|(${params.join('')})${ret}`),
  };

  // 3. yerleşim
  const w = new Writer(true, 8192);
  w.bytes(new Uint8Array(0x70));
  const sec = {};
  const mark = (k) => { sec[k] = w.pos; };
  mark('strings'); w.bytes(new Uint8Array(strings.length * 4));
  mark('types'); for (const t of types) w.u4(si.get(t));
  mark('protos'); const protoPatch = []; for (const [, p] of protos) { w.u4(si.get(p.shorty)).u4(ti.get(p.ret)); protoPatch.push(w.pos); w.u4(0); }
  mark('fields'); for (const f of fields) w.u2(ti.get(f.cls)).u2(ti.get(f.type)).u4(si.get(f.name));
  mark('methods'); for (const m of methods) w.u2(ti.get(m.cls)).u2(pi.get(m.proto)).u4(si.get(m.name));
  mark('classes'); const classPatch = []; for (const c of classes) { classPatch.push(w.pos); w.bytes(new Uint8Array(32)); }
  mark('data');
  const map = [];
  // code_item
  w.align(4);
  const codeStart = w.pos;
  const codeOff = new Map();
  let codeCount = 0;
  for (const c of classes) for (const m of c.methods ?? []) {
    if (!m.code) continue;
    w.align(4);
    const a = new DexAsm(res);
    m.code(a);
    const insns = a.done();
    codeOff.set(m, w.pos);
    w.u2(m.registers).u2(m.ins).u2(m.outs ?? 0).u2(0).u4(0).u4(insns.length);
    for (const u of insns) w.u2(u);
    codeCount++;
  }
  if (codeCount) map.push([0x2001, codeCount, codeStart]);
  // type_list
  w.align(4);
  const tlStart = w.pos;
  const tlOff = new Map();
  const typeList = (list) => {
    const k = list.join(',');
    if (!list.length) return 0;
    if (!tlOff.has(k)) { w.align(4); tlOff.set(k, w.pos); w.u4(list.length); for (const t of list) w.u2(ti.get(t)); }
    return tlOff.get(k);
  };
  protos.forEach(([, p], i) => w.setU4(protoPatch[i], typeList(p.params)));
  const ifaceOff = classes.map((c) => typeList(c.interfaces ?? []));
  if (tlOff.size) map.push([0x1001, tlOff.size, tlStart]);
  // string_data
  const sdStart = w.pos;
  strings.forEach((s, i) => { w.setU4(sec.strings + i * 4, w.pos); w.uleb(s.length).bytes(encodeMutf8(s)).u1(0); });
  map.push([0x2002, strings.length, sdStart]);
  // class_data
  const cdStart = w.pos;
  const cdOff = classes.map((c) => {
    const fs = c.fields ?? [];
    const ms = c.methods ?? [];
    const sf = fs.filter((f) => f.access & 8).sort((a, b) => fi.get(`${c.type}|${a.name}|${a.type}`) - fi.get(`${c.type}|${b.name}|${b.type}`));
    const inf = fs.filter((f) => !(f.access & 8)).sort((a, b) => fi.get(`${c.type}|${a.name}|${a.type}`) - fi.get(`${c.type}|${b.name}|${b.type}`));
    const key = (m) => mi.get(`${c.type}|${m.name}|(${m.params.join('')})${m.ret}`);
    const direct = ms.filter((m) => m.access & (8 | 2) || m.name === '<init>' || m.name === '<clinit>').sort((a, b) => key(a) - key(b));
    const virt = ms.filter((m) => !direct.includes(m)).sort((a, b) => key(a) - key(b));
    c.sortedStatic = sf;
    if (!fs.length && !ms.length) return 0;
    const off = w.pos;
    w.uleb(sf.length).uleb(inf.length).uleb(direct.length).uleb(virt.length);
    for (const list of [sf, inf]) { let prev = 0; for (const f of list) { const i = fi.get(`${c.type}|${f.name}|${f.type}`); w.uleb(i - prev).uleb(f.access); prev = i; } }
    for (const list of [direct, virt]) { let prev = 0; for (const m of list) { const i = key(m); w.uleb(i - prev).uleb(m.access).uleb(codeOff.get(m) ?? 0); prev = i; } }
    return off;
  });
  const cdCount = cdOff.filter(Boolean).length;
  if (cdCount) map.push([0x2000, cdCount, cdStart]);
  // statik ilk değerler (yalnızca int ve dizge)
  const svStart = w.pos;
  const svOff = classes.map((c) => {
    const sf = c.sortedStatic ?? [];
    if (!sf.some((f) => f.value !== undefined)) return 0;
    const off = w.pos;
    w.uleb(sf.length);
    for (const f of sf) {
      if (typeof f.value === 'string') { w.u1(0x17 | (3 << 5)).u4(si.get(f.value)); } else { w.u1(0x04 | (3 << 5)).u4(f.value ?? 0); }
    }
    return off;
  });
  const svCount = svOff.filter(Boolean).length;
  if (svCount) map.push([0x2005, svCount, svStart]);
  classes.forEach((c, i) => {
    const at = classPatch[i];
    w.setU4(at, ti.get(c.type));
    w.setU4(at + 4, c.access ?? 1);
    w.setU4(at + 8, c.superType ? ti.get(c.superType) : 0xffffffff);
    w.setU4(at + 12, ifaceOff[i]);
    w.setU4(at + 16, c.sourceFile ? si.get(c.sourceFile) : 0xffffffff);
    w.setU4(at + 20, 0);
    w.setU4(at + 24, cdOff[i]);
    w.setU4(at + 28, svOff[i]);
  });
  // map_list
  w.align(4);
  const mapOff = w.pos;
  const items = [[0, 1, 0], [1, strings.length, sec.strings], [2, types.length, sec.types], [3, protos.length, sec.protos], [4, fields.length, sec.fields], [5, methods.length, sec.methods], [6, classes.length, sec.classes], ...map, [0x1000, 1, mapOff]]
    .filter(([, n]) => n > 0).sort((a, b) => a[2] - b[2]);
  w.u4(items.length);
  for (const [t, n, off] of items) w.u2(t).u2(0).u4(n).u4(off);
  const out = w.done();
  // başlık
  const h = new Writer(true, 0x70);
  h.bytes(Uint8Array.from([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]));
  h.u4(0).bytes(new Uint8Array(20)).u4(out.length).u4(0x70).u4(0x12345678).u4(0).u4(0).u4(mapOff);
  for (const [n, off] of [[strings.length, sec.strings], [types.length, sec.types], [protos.length, sec.protos], [fields.length, sec.fields], [methods.length, sec.methods], [classes.length, sec.classes]]) h.u4(n).u4(n ? off : 0);
  h.u4(out.length - sec.data).u4(sec.data);
  out.set(h.done(), 0);
  out.set(createHash('sha1').update(out.subarray(32)).digest(), 12);
  new DataView(out.buffer).setUint32(8, adler32(out, 12), true);
  return out;
}
