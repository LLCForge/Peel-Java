// DEX okuyucu (Dalvik Executable, sürüm 035-041): başlık, dizge/tür/prototip/alan/yöntem tabloları, sınıf tanımları,
// class_data, code_item ve statik ilk değerler (encoded_array). Her tablo boyutu dosya boyutuyla denetlenir.
import { Reader, ParseError, decodeMutf8, adler32 } from '../core/bytes.js';
import { LIMITS } from '../core/limits.js';

export const NO_INDEX = 0xffffffff;
export const isDex = (b) => b.length >= 0x70 && b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a;

function table(r, size, off, itemSize, total) {
  if (size === 0) return;
  if (off + size * itemSize > r.length || off <= 0) throw new ParseError('DEX tablosu dosya dışında');
  total.n += size;
  if (total.n > LIMITS.dexItems) throw new ParseError('DEX tabloları çok büyük');
}

/** encoded_value okur (statik ilk değerler ve açıklamalar) */
export function readEncodedValue(r, dex, depth = 0) {
  if (depth > 16) throw new ParseError('iç içe değer çok derin');
  const b = r.u1();
  const type = b & 0x1f;
  const arg = b >> 5;
  const n = arg + 1;
  const uint = () => { let v = 0n; for (let i = 0; i < n; i++) v |= BigInt(r.u1()) << BigInt(8 * i); return v; };
  const sint = () => BigInt.asIntN(n * 8, uint());
  switch (type) {
    case 0x00: return { type: 'B', value: Number(sint()) };
    case 0x02: return { type: 'S', value: Number(sint()) };
    case 0x03: return { type: 'C', value: Number(uint()) };
    case 0x04: return { type: 'I', value: Number(sint()) };
    case 0x06: return { type: 'J', value: sint() };
    case 0x10: case 0x11: {
      const size = type === 0x10 ? 4 : 8;
      const buf = new Uint8Array(size);
      for (let i = 0; i < n; i++) buf[size - n + i] = r.u1();
      const dv = new DataView(buf.buffer);
      return { type: type === 0x10 ? 'F' : 'D', value: type === 0x10 ? dv.getFloat32(0, true) : dv.getFloat64(0, true) };
    }
    case 0x15: return { type: 'MethodType', value: Number(uint()) };
    case 0x16: return { type: 'MethodHandle', value: Number(uint()) };
    case 0x17: return { type: 'String', value: dex.strings[Number(uint())] ?? null };
    case 0x18: return { type: 'Class', value: dex.types[Number(uint())] ?? null };
    case 0x19: case 0x1b: return { type: type === 0x19 ? 'Field' : 'Enum', value: Number(uint()) };
    case 0x1a: return { type: 'Method', value: Number(uint()) };
    case 0x1c: return { type: 'Array', value: readEncodedArray(r, dex, depth + 1) };
    case 0x1d: {
      const typeIdx = r.uleb();
      const size = r.uleb();
      const elems = [];
      for (let i = 0; i < size; i++) elems.push([dex.strings[r.uleb()], readEncodedValue(r, dex, depth + 1)]);
      return { type: 'Annotation', value: { type: dex.types[typeIdx], elems } };
    }
    case 0x1e: return { type: 'Null', value: null };
    case 0x1f: return { type: 'Z', value: arg };
    default: throw new ParseError(`bilinmeyen encoded_value türü 0x${type.toString(16)}`);
  }
}
export function readEncodedArray(r, dex, depth = 0) {
  const size = r.uleb();
  if (size > 65536) throw new ParseError('encoded_array çok büyük');
  const out = [];
  for (let i = 0; i < size; i++) out.push(readEncodedValue(r, dex, depth));
  return out;
}

function readCode(dex, r, off) {
  const c = r.at(off);
  const registers = c.u2();
  const ins = c.u2();
  const outs = c.u2();
  const triesSize = c.u2();
  const debugOff = c.u4();
  const n = c.u4();
  if (n > 0x400000 || off + 16 + n * 2 > r.length) throw new ParseError('code_item dosya dışında');
  const insns = new Uint16Array(n);
  for (let i = 0; i < n; i++) insns[i] = c.u2();
  if (n % 2 && triesSize) c.u2();
  const tries = [];
  if (triesSize) {
    const raw = [];
    for (let i = 0; i < triesSize; i++) raw.push({ start: c.u4(), count: c.u2(), handlerOff: c.u2() });
    const base = c.pos;
    for (const t of raw) {
      const h = c.at(base + t.handlerOff);
      const size = h.sleb();
      const handlers = [];
      for (let i = 0; i < Math.abs(size) && i < 256; i++) handlers.push({ type: dex.types[h.uleb()], addr: h.uleb() });
      tries.push({ start: t.start, count: t.count, handlers, catchAll: size <= 0 ? h.uleb() : null });
    }
  }
  return { registers, ins, outs, insns, tries, debugOff };
}

/**
 * @returns {{ version, strings, types, protos, fields, methods, classes, checksumOk, size }}
 */
export function parseDex(bytes) {
  if (!isDex(bytes)) throw new ParseError('DEX imzası yok');
  const r = new Reader(bytes, true);
  const version = String.fromCharCode(bytes[4], bytes[5], bytes[6]);
  r.pos = 8;
  const checksum = r.u4();
  r.pos = 0x20;
  const fileSize = r.u4();
  const headerSize = r.u4();
  const endian = r.u4();
  if (endian !== 0x12345678) throw new ParseError('büyük sonlu DEX desteklenmiyor');
  if (headerSize < 0x70) throw new ParseError('DEX başlığı kısa');
  r.pos = 0x38;
  const h = {};
  for (const k of ['strings', 'types', 'protos', 'fields', 'methods', 'classes']) { h[k] = { size: r.u4(), off: r.u4() }; }
  const total = { n: 0 };
  table(r, h.strings.size, h.strings.off, 4, total);
  table(r, h.types.size, h.types.off, 4, total);
  table(r, h.protos.size, h.protos.off, 12, total);
  table(r, h.fields.size, h.fields.off, 8, total);
  table(r, h.methods.size, h.methods.off, 8, total);
  table(r, h.classes.size, h.classes.off, 32, total);

  const dex = { version, size: fileSize, checksumOk: adler32(bytes, 12) === checksum, strings: [], types: [], protos: [], fields: [], methods: [], classes: [] };
  const ids = r.at(h.strings.off);
  for (let i = 0; i < h.strings.size; i++) {
    const s = r.at(ids.u4());
    s.uleb();
    const start = s.pos;
    let end = start;
    while (end < bytes.length && bytes[end] !== 0) end++;
    if (end >= bytes.length) throw new ParseError(`dizge #${i} sonlanmıyor`);
    dex.strings.push(decodeMutf8(bytes.subarray(start, end)));
  }
  const str = (i) => (i === NO_INDEX ? null : dex.strings[i] ?? `<string ${i}>`);
  const tr = r.at(h.types.off);
  for (let i = 0; i < h.types.size; i++) dex.types.push(str(tr.u4()));
  const type = (i) => (i === NO_INDEX || i === 0xffff ? null : dex.types[i] ?? `<type ${i}>`);
  const typeList = (off) => {
    if (!off) return [];
    const t = r.at(off);
    const n = t.u4();
    if (n > 65536) throw new ParseError('tür listesi çok büyük');
    return Array.from({ length: n }, () => type(t.u2()));
  };
  const pr = r.at(h.protos.off);
  for (let i = 0; i < h.protos.size; i++) {
    const shorty = str(pr.u4());
    const ret = type(pr.u4());
    const params = typeList(pr.u4());
    dex.protos.push({ shorty, ret, params });
  }
  const fr = r.at(h.fields.off);
  for (let i = 0; i < h.fields.size; i++) dex.fields.push({ cls: type(fr.u2()), type: type(fr.u2()), name: str(fr.u4()) });
  const mr = r.at(h.methods.off);
  for (let i = 0; i < h.methods.size; i++) {
    const cls = type(mr.u2());
    const proto = dex.protos[mr.u2()];
    dex.methods.push({ cls, name: str(mr.u4()), proto, desc: proto ? `(${proto.params.join('')})${proto.ret}` : '()V' });
  }
  const cr = r.at(h.classes.off);
  for (let i = 0; i < h.classes.size; i++) {
    const c = { type: type(cr.u4()), access: cr.u4(), superType: type(cr.u4()), interfaces: typeList(cr.u4()), sourceFile: str(cr.u4()), annotationsOff: cr.u4(), staticFields: [], instanceFields: [], directMethods: [], virtualMethods: [], staticValues: [] };
    const dataOff = cr.u4();
    const svOff = cr.u4();
    if (dataOff) {
      const d = r.at(dataOff);
      const counts = [d.uleb(), d.uleb(), d.uleb(), d.uleb()];
      if (counts.some((n) => n > 65536)) throw new ParseError('class_data çok büyük');
      for (const [k, n] of [['staticFields', counts[0]], ['instanceFields', counts[1]]]) {
        let idx = 0;
        for (let j = 0; j < n; j++) { idx += d.uleb(); c[k].push({ idx, access: d.uleb() }); }
      }
      for (const [k, n] of [['directMethods', counts[2]], ['virtualMethods', counts[3]]]) {
        let idx = 0;
        for (let j = 0; j < n; j++) {
          idx += d.uleb();
          const access = d.uleb();
          const codeOff = d.uleb();
          c[k].push({ idx, access, code: codeOff ? readCode(dex, r, codeOff) : null });
        }
      }
    }
    if (svOff) c.staticValues = readEncodedArray(r.at(svOff), dex);
    dex.classes.push(c);
  }
  return dex;
}

/** "Lcom/a/B;" → "com/a/B" (sınıf tanımlayıcısı değilse olduğu gibi) */
export const internalOf = (desc) => (desc && desc.startsWith('L') && desc.endsWith(';') ? desc.slice(1, -1) : desc);
export const methodsOf = (c) => [...c.directMethods, ...c.virtualMethods];
