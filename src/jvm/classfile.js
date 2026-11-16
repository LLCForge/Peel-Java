// Java sınıf dosyası okuyucu/yazıcı (JVMS 4). Ayrıştırılan dosya aynen geri yazılır (bayt bayt): sabit havuzu girdileri
// özgün MUTF-8 baytlarını saklar, öznitelikler ham tutulur; yalnızca Code özniteliği yapısal ayrıştırılır ve yeniden
// kodlanır. Geçişler havuza yalnızca ekleme yapar (eski indeksler hiç kaymaz).
import { Reader, Writer, ParseError, decodeMutf8, encodeMutf8 } from '../core/bytes.js';
import { LIMITS } from '../core/limits.js';

export const TAG = { Utf8: 1, Integer: 3, Float: 4, Long: 5, Double: 6, Class: 7, String: 8, Fieldref: 9, Methodref: 10, InterfaceMethodref: 11, NameAndType: 12, MethodHandle: 15, MethodType: 16, Dynamic: 17, InvokeDynamic: 18, Module: 19, Package: 20 };
export const ACC = { PUBLIC: 0x1, PRIVATE: 0x2, PROTECTED: 0x4, STATIC: 0x8, FINAL: 0x10, SYNCHRONIZED: 0x20, SUPER: 0x20, VOLATILE: 0x40, BRIDGE: 0x40, TRANSIENT: 0x80, VARARGS: 0x80, NATIVE: 0x100, INTERFACE: 0x200, ABSTRACT: 0x400, STRICT: 0x800, SYNTHETIC: 0x1000, ANNOTATION: 0x2000, ENUM: 0x4000, MODULE: 0x8000 };
export const isClassFile = (b) => b.length >= 10 && b[0] === 0xca && b[1] === 0xfe && b[2] === 0xba && b[3] === 0xbe;

function readCp(r) {
  const count = r.u2();
  if (count === 0) throw new ParseError('sabit havuzu boş');
  const cp = [null];
  for (let i = 1; i < count; i++) {
    const tag = r.u1();
    let e;
    switch (tag) {
      case 1: { const n = r.u2(); const bytes = r.bytes(n); e = { tag, bytes, value: decodeMutf8(bytes) }; break; }
      case 3: e = { tag, value: r.s4() }; break;
      case 4: e = { tag, value: r.f4(), raw: r.b.slice(r.pos - 4, r.pos) }; break;
      case 5: e = { tag, value: r.s8() }; break;
      case 6: e = { tag, value: r.f8(), raw: r.b.slice(r.pos - 8, r.pos) }; break;
      case 7: case 8: case 16: case 19: case 20: e = { tag, index: r.u2() }; break;
      case 9: case 10: case 11: e = { tag, classIndex: r.u2(), natIndex: r.u2() }; break;
      case 12: e = { tag, nameIndex: r.u2(), descIndex: r.u2() }; break;
      case 15: e = { tag, kind: r.u1(), refIndex: r.u2() }; break;
      case 17: case 18: e = { tag, bsmIndex: r.u2(), natIndex: r.u2() }; break;
      default: throw new ParseError(`bilinmeyen sabit havuzu etiketi ${tag} (#${i})`);
    }
    cp.push(e);
    if (tag === 5 || tag === 6) { cp.push(null); i++; }
  }
  return cp;
}

function readAttrs(r) {
  const n = r.u2();
  const out = [];
  for (let i = 0; i < n; i++) {
    const nameIndex = r.u2();
    const len = r.u4();
    out.push({ nameIndex, data: r.bytes(len) });
  }
  return out;
}

export function parseCode(attr) {
  const r = new Reader(attr.data);
  const maxStack = r.u2();
  const maxLocals = r.u2();
  const len = r.u4();
  if (len > LIMITS.codeBytes) throw new ParseError(`yöntem gövdesi çok büyük (${len})`);
  const code = r.bytes(len).slice();
  const ne = r.u2();
  const exceptions = [];
  for (let i = 0; i < ne; i++) exceptions.push({ start: r.u2(), end: r.u2(), handler: r.u2(), catchType: r.u2() });
  const attrs = readAttrs(r);
  return { maxStack, maxLocals, code, exceptions, attrs };
}

const readMember = (r) => ({ access: r.u2(), nameIndex: r.u2(), descIndex: r.u2(), attrs: readAttrs(r) });

/** Sınıf dosyasını ayrıştırır. Code öznitelikleri `member.code` olarak açılır. */
export function parseClass(bytes) {
  const r = new Reader(bytes);
  if (r.u4() !== 0xcafebabe) throw new ParseError('CAFEBABE imzası yok');
  const minor = r.u2();
  const major = r.u2();
  const cp = readCp(r);
  const cf = { minor, major, cp, access: r.u2(), thisClass: r.u2(), superClass: r.u2(), interfaces: [], fields: [], methods: [], attrs: [], index: new Map() };
  const ni = r.u2();
  for (let i = 0; i < ni; i++) cf.interfaces.push(r.u2());
  const nf = r.u2();
  for (let i = 0; i < nf; i++) cf.fields.push(readMember(r));
  const nm = r.u2();
  for (let i = 0; i < nm; i++) cf.methods.push(readMember(r));
  cf.attrs = readAttrs(r);
  if (r.pos !== bytes.length) cf.trailing = bytes.length - r.pos;
  if (cp[cf.thisClass]?.tag !== 7) throw new ParseError('this_class geçersiz');
  for (const m of cf.methods) {
    const a = m.attrs.find((x) => utf8(cf, x.nameIndex) === 'Code');
    if (a) { a.code = parseCode(a); m.code = a.code; }
  }
  return cf;
}

function writeCode(c) {
  const w = new Writer(false, c.code.length + 64);
  w.u2(c.maxStack).u2(c.maxLocals).u4(c.code.length).bytes(c.code).u2(c.exceptions.length);
  for (const e of c.exceptions) w.u2(e.start).u2(e.end).u2(e.handler).u2(e.catchType);
  writeAttrs(w, c.attrs);
  return w.done();
}

function writeAttrs(w, attrs) {
  w.u2(attrs.length);
  for (const a of attrs) {
    const data = a.code ? writeCode(a.code) : a.data;
    w.u2(a.nameIndex).u4(data.length).bytes(data);
  }
}

export function writeClass(cf) {
  if (cf.cp.length > LIMITS.constantPool) throw new ParseError('sabit havuzu 65535 girdiyi aştı');
  const w = new Writer(false, 4096);
  w.u4(0xcafebabe).u2(cf.minor).u2(cf.major).u2(cf.cp.length);
  for (let i = 1; i < cf.cp.length; i++) {
    const e = cf.cp[i];
    if (!e) continue;
    w.u1(e.tag);
    switch (e.tag) {
      case 1: { const b = e.bytes ?? encodeMutf8(e.value); w.u2(b.length).bytes(b); break; }
      case 3: w.u4(e.value); break;
      case 4: if (e.raw) w.bytes(e.raw); else w.f4(e.value); break;
      case 5: w.s8(e.value); break;
      case 6: if (e.raw) w.bytes(e.raw); else w.f8(e.value); break;
      case 7: case 8: case 16: case 19: case 20: w.u2(e.index); break;
      case 9: case 10: case 11: w.u2(e.classIndex).u2(e.natIndex); break;
      case 12: w.u2(e.nameIndex).u2(e.descIndex); break;
      case 15: w.u1(e.kind).u2(e.refIndex); break;
      case 17: case 18: w.u2(e.bsmIndex).u2(e.natIndex); break;
      default: throw new ParseError(`yazılamayan etiket ${e.tag}`);
    }
  }
  w.u2(cf.access).u2(cf.thisClass).u2(cf.superClass).u2(cf.interfaces.length);
  for (const i of cf.interfaces) w.u2(i);
  for (const list of [cf.fields, cf.methods]) {
    w.u2(list.length);
    for (const m of list) { w.u2(m.access).u2(m.nameIndex).u2(m.descIndex); writeAttrs(w, m.attrs); }
  }
  writeAttrs(w, cf.attrs);
  return w.done();
}

// ── sabit havuzu erişimi ──
export function utf8(cf, i) {
  const e = cf.cp[i];
  return e?.tag === 1 ? e.value : '';
}
export const className = (cf, i) => (i && cf.cp[i]?.tag === 7 ? utf8(cf, cf.cp[i].index) : '');
export const thisName = (cf) => className(cf, cf.thisClass);
export const superName = (cf) => className(cf, cf.superClass);
export const memberName = (cf, m) => utf8(cf, m.nameIndex);
export const memberDesc = (cf, m) => utf8(cf, m.descIndex);
export function nat(cf, i) {
  const e = cf.cp[i];
  return e?.tag === 12 ? { name: utf8(cf, e.nameIndex), desc: utf8(cf, e.descIndex) } : { name: '', desc: '' };
}
export function ref(cf, i) {
  const e = cf.cp[i];
  if (!e || !(e.tag >= 9 && e.tag <= 11)) return null;
  return { owner: className(cf, e.classIndex), ...nat(cf, e.natIndex), iface: e.tag === 11 };
}
export const attrName = (cf, a) => utf8(cf, a.nameIndex);
export const findAttr = (cf, attrs, name) => attrs.find((a) => attrName(cf, a) === name);

/** Sabit havuzu girdisinin değeri (ldc ve görüntüleme için) */
export function constant(cf, i) {
  const e = cf.cp[i];
  if (!e) return null;
  switch (e.tag) {
    case 3: return { type: 'I', value: e.value };
    case 4: return { type: 'F', value: e.value };
    case 6: return { type: 'D', value: e.value };
    case 5: return { type: 'J', value: e.value };
    case 8: return { type: 'String', value: utf8(cf, e.index) };
    case 7: return { type: 'Class', value: utf8(cf, e.index) };
    case 16: return { type: 'MethodType', value: utf8(cf, e.index) };
    case 15: return { type: 'MethodHandle', value: ref(cf, e.refIndex) };
    case 17: return { type: 'Dynamic', value: nat(cf, e.natIndex) };
    default: return null;
  }
}

// ── havuza ekleme (aynı değer varsa onu kullanır) ──
const keyOf = (e) => (e.tag === 1 ? `1:${e.value}` : JSON.stringify(e, (k, v) => (typeof v === 'bigint' ? `${v}n` : k === 'bytes' || k === 'raw' ? undefined : v)));
function intern(cf, e) {
  if (!cf.index.size) for (let i = 1; i < cf.cp.length; i++) if (cf.cp[i] && !cf.index.has(keyOf(cf.cp[i]))) cf.index.set(keyOf(cf.cp[i]), i);
  const k = keyOf(e);
  const hit = cf.index.get(k);
  if (hit) return hit;
  const idx = cf.cp.length;
  if (idx + 2 > LIMITS.constantPool) throw new ParseError('sabit havuzu dolu');
  cf.cp.push(e);
  if (e.tag === 5 || e.tag === 6) cf.cp.push(null);
  cf.index.set(k, idx);
  return idx;
}
export const addUtf8 = (cf, value) => intern(cf, { tag: 1, value });
export const addString = (cf, value) => intern(cf, { tag: 8, index: addUtf8(cf, value) });
export const addClass = (cf, name) => intern(cf, { tag: 7, index: addUtf8(cf, name) });
export const addNat = (cf, name, desc) => intern(cf, { tag: 12, nameIndex: addUtf8(cf, name), descIndex: addUtf8(cf, desc) });
export const addInt = (cf, value) => intern(cf, { tag: 3, value: value | 0 });
export const addLong = (cf, value) => intern(cf, { tag: 5, value: BigInt.asIntN(64, BigInt(value)) });
export const addRef = (cf, tag, owner, name, desc) => intern(cf, { tag, classIndex: addClass(cf, owner), natIndex: addNat(cf, name, desc) });
/** Havuzdaki girdi yerinde değiştirildikten sonra arama tablosu yeniden kurulur */
export const reindex = (cf) => cf.index.clear();

// ── tanımlayıcılar ──
/** "(ILjava/lang/String;[C)V" → { params: ['I','Ljava/lang/String;','[C'], ret: 'V' } */
export function parseMethodDesc(desc) {
  const params = [];
  let i = 1;
  if (desc[0] !== '(') return { params, ret: 'V', bad: true };
  while (i < desc.length && desc[i] !== ')') {
    const s = i;
    while (desc[i] === '[') i++;
    if (desc[i] === 'L') {
      const e = desc.indexOf(';', i);
      if (e < 0) return { params, ret: 'V', bad: true };
      i = e + 1;
    } else i++;
    params.push(desc.slice(s, i));
  }
  return { params, ret: desc.slice(i + 1) };
}
export const slots = (t) => (t === 'J' || t === 'D' ? 2 : 1);

/** Tanımlayıcı ya da genel imzadaki sınıf adlarını eşler ("Lad;" ve "Lad<") */
export function mapDesc(desc, mapClass) {
  return desc.replace(/L([^;<>:]+)([;<])/g, (m, n, end) => `L${mapClass(n) ?? n}${end}`);
}

const PRIM = { B: 'byte', C: 'char', D: 'double', F: 'float', I: 'int', J: 'long', S: 'short', Z: 'boolean', V: 'void' };
/** "[Ljava/lang/String;" → "java.lang.String[]" */
export function javaType(t) {
  let dims = 0;
  while (t[dims] === '[') dims++;
  const base = t.slice(dims);
  const name = PRIM[base] ?? (base.startsWith('L') ? base.slice(1, -1).replaceAll('/', '.') : base.replaceAll('/', '.'));
  return name + '[]'.repeat(dims);
}
export const simpleName = (internal) => internal.slice(internal.lastIndexOf('/') + 1);
