// Bayt okuma/yazma yardımcıları. Sınıf dosyaları büyük, DEX ve ZIP küçük sonlu (little-endian) okunur. Her okuma sınır
// denetimlidir: bozuk ya da kasıtlı olarak kısaltılmış dosya sonsuz döngü ya da dev ayırma yerine ParseError verir.

export class ParseError extends Error {}

export class Reader {
  constructor(bytes, little = false, pos = 0) {
    this.b = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.little = little;
    this.pos = pos;
  }
  get length() { return this.b.length; }
  need(n, at = this.pos) {
    if (n < 0 || at < 0 || at + n > this.b.length) throw new ParseError(`dosya sonu aşıldı (konum ${at}, ${n} bayt)`);
  }
  u1() { this.need(1); return this.b[this.pos++]; }
  s1() { this.need(1); return this.dv.getInt8(this.pos++); }
  u2() { this.need(2); const v = this.dv.getUint16(this.pos, this.little); this.pos += 2; return v; }
  s2() { this.need(2); const v = this.dv.getInt16(this.pos, this.little); this.pos += 2; return v; }
  u4() { this.need(4); const v = this.dv.getUint32(this.pos, this.little); this.pos += 4; return v; }
  s4() { this.need(4); const v = this.dv.getInt32(this.pos, this.little); this.pos += 4; return v; }
  s8() { this.need(8); const v = this.dv.getBigInt64(this.pos, this.little); this.pos += 8; return v; }
  f4() { this.need(4); const v = this.dv.getFloat32(this.pos, this.little); this.pos += 4; return v; }
  f8() { this.need(8); const v = this.dv.getFloat64(this.pos, this.little); this.pos += 8; return v; }
  bytes(n) { this.need(n); const v = this.b.subarray(this.pos, this.pos + n); this.pos += n; return v; }
  uleb() {
    let v = 0;
    for (let i = 0; i < 5; i++) {
      const c = this.u1();
      v |= (c & 0x7f) << (7 * i);
      if (!(c & 0x80)) return v >>> 0;
    }
    throw new ParseError('geçersiz uleb128');
  }
  sleb() {
    let v = 0;
    let shift = 0;
    for (let i = 0; i < 5; i++) {
      const c = this.u1();
      v |= (c & 0x7f) << shift;
      shift += 7;
      if (!(c & 0x80)) return shift < 32 && (c & 0x40) ? v | (-1 << shift) : v | 0;
    }
    throw new ParseError('geçersiz sleb128');
  }
  at(pos) { return new Reader(this.b, this.little, pos); }
}

export class Writer {
  constructor(little = false, size = 1024) {
    this.b = new Uint8Array(size);
    this.dv = new DataView(this.b.buffer);
    this.little = little;
    this.pos = 0;
  }
  grow(n) {
    if (this.pos + n <= this.b.length) return;
    let size = this.b.length * 2;
    while (size < this.pos + n) size *= 2;
    const nb = new Uint8Array(size);
    nb.set(this.b.subarray(0, this.pos));
    this.b = nb;
    this.dv = new DataView(nb.buffer);
  }
  u1(v) { this.grow(1); this.b[this.pos++] = v & 0xff; return this; }
  u2(v) { this.grow(2); this.dv.setUint16(this.pos, v & 0xffff, this.little); this.pos += 2; return this; }
  u4(v) { this.grow(4); this.dv.setUint32(this.pos, v >>> 0, this.little); this.pos += 4; return this; }
  s8(v) { this.grow(8); this.dv.setBigInt64(this.pos, BigInt.asIntN(64, BigInt(v)), this.little); this.pos += 8; return this; }
  f4(v) { this.grow(4); this.dv.setFloat32(this.pos, v, this.little); this.pos += 4; return this; }
  f8(v) { this.grow(8); this.dv.setFloat64(this.pos, v, this.little); this.pos += 8; return this; }
  bytes(a) { this.grow(a.length); this.b.set(a, this.pos); this.pos += a.length; return this; }
  uleb(v) {
    v >>>= 0;
    do {
      let c = v & 0x7f;
      v >>>= 7;
      if (v) c |= 0x80;
      this.u1(c);
    } while (v);
    return this;
  }
  sleb(v) {
    v |= 0;
    for (;;) {
      const c = v & 0x7f;
      v >>= 7;
      if ((v === 0 && !(c & 0x40)) || (v === -1 && c & 0x40)) { this.u1(c); return this; }
      this.u1(c | 0x80);
    }
  }
  align(n) { while (this.pos % n) this.u1(0); return this; }
  setU4(at, v) { this.dv.setUint32(at, v >>> 0, this.little); }
  setU2(at, v) { this.dv.setUint16(at, v & 0xffff, this.little); }
  done() { return this.b.slice(0, this.pos); }
}

// Java "modified UTF-8": NUL iki bayt (C0 80), ek düzlem karakterleri iki ayrı 3 baytlık vekil olarak yazılır.
export function decodeMutf8(b) {
  let s = '';
  let chunk = [];
  for (let i = 0; i < b.length;) {
    const c = b[i];
    let u;
    if (c < 0x80) { u = c; i++; }
    else if ((c & 0xe0) === 0xc0 && i + 1 < b.length) { u = ((c & 0x1f) << 6) | (b[i + 1] & 0x3f); i += 2; }
    else if ((c & 0xf0) === 0xe0 && i + 2 < b.length) { u = ((c & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f); i += 3; }
    else { u = 0xfffd; i++; }
    chunk.push(u);
    if (chunk.length > 4096) { s += String.fromCharCode(...chunk); chunk = []; }
  }
  return s + String.fromCharCode(...chunk);
}

export function encodeMutf8(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const u = s.charCodeAt(i);
    if (u >= 1 && u < 0x80) out.push(u);
    else if (u < 0x800) out.push(0xc0 | (u >> 6), 0x80 | (u & 0x3f));
    else out.push(0xe0 | (u >> 12), 0x80 | ((u >> 6) & 0x3f), 0x80 | (u & 0x3f));
  }
  return Uint8Array.from(out);
}

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
export function crc32(b) {
  let c = -1;
  for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

export function adler32(b, from = 0) {
  let a = 1;
  let s = 0;
  for (let i = from; i < b.length; i++) {
    a = (a + b[i]) % 65521;
    s = (s + a) % 65521;
  }
  return ((s << 16) | a) >>> 0;
}

export const hex = (n, w = 0) => n.toString(16).padStart(w, '0');
