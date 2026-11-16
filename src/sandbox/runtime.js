// Yorumlayıcıların (JVM ve Dalvik) ortak Java çalışma zamanı alt kümesi. Yalnızca yan etkisiz çekirdek API'ler vardır:
// String, StringBuilder/StringBuffer, Character, Integer, Math, System.arraycopy ve Base64 (java.util ve android.util).
// Listede olmayan her çağrı Unsupported fırlatır: çözücü değerlendirilmez, çağrı yeri olduğu gibi bırakılır ve raporlanır.
// Ağ, dosya, yansıma, iş parçacığı, saat ve rastgelelik bilinçli olarak yoktur.
//
// Değerler: int/char/short/byte/boolean → number, long → BigInt, float/double → number, String → JS dizgesi,
// dizi → { arr: öğe türü, data }, StringBuilder → { cls, s }, null → null.
import { LIMITS } from '../core/limits.js';

export class Unsupported extends Error {}
export class BudgetExceeded extends Error {}
/** Java istisnası (yorumlayıcı içinde yakalanabilir) */
export class JavaThrow extends Error {
  constructor(cls, msg = '') { super(`${cls}${msg ? `: ${msg}` : ''}`); this.cls = cls; }
}

// istisna sınıf hiyerarşisi (catch eşleştirmesi için)
const EXC_PARENT = {
  'java/lang/ArithmeticException': 'java/lang/RuntimeException',
  'java/lang/ArrayIndexOutOfBoundsException': 'java/lang/IndexOutOfBoundsException',
  'java/lang/StringIndexOutOfBoundsException': 'java/lang/IndexOutOfBoundsException',
  'java/lang/IndexOutOfBoundsException': 'java/lang/RuntimeException',
  'java/lang/NullPointerException': 'java/lang/RuntimeException',
  'java/lang/NegativeArraySizeException': 'java/lang/RuntimeException',
  'java/lang/ClassCastException': 'java/lang/RuntimeException',
  'java/lang/NumberFormatException': 'java/lang/IllegalArgumentException',
  'java/lang/IllegalArgumentException': 'java/lang/RuntimeException',
  'java/lang/ArrayStoreException': 'java/lang/RuntimeException',
  'java/lang/RuntimeException': 'java/lang/Exception',
  'java/lang/Exception': 'java/lang/Throwable',
};
export function excMatches(thrown, catchType) {
  if (!catchType) return true;
  for (let c = thrown; c; c = EXC_PARENT[c]) if (c === catchType) return true;
  return false;
}

export function createContext(limits = {}) {
  const lim = { ...LIMITS, ...limits };
  return {
    steps: 0,
    heap: 0,
    depth: 0,
    deadline: Date.now() + lim.interpMs,
    lim,
    tick(n = 1) {
      this.steps += n;
      if (this.steps > lim.interpSteps) throw new BudgetExceeded(`komut bütçesi aşıldı (${lim.interpSteps})`);
      if ((this.steps & 0x3fff) === 0 && Date.now() > this.deadline) throw new BudgetExceeded(`süre sınırı aşıldı (${lim.interpMs} ms)`);
    },
    alloc(n) {
      this.heap += n;
      if (this.heap > lim.interpHeap) throw new BudgetExceeded('bellek bütçesi aşıldı');
    },
  };
}

const ARRAY_CTOR = { I: Int32Array, C: Uint16Array, B: Int8Array, S: Int16Array, Z: Int8Array, J: BigInt64Array, F: Float32Array, D: Float64Array };
export function newArray(ctx, elem, n) {
  if (!Number.isInteger(n) || n < 0) throw new JavaThrow('java/lang/NegativeArraySizeException', String(n));
  ctx.alloc(n);
  const C = ARRAY_CTOR[elem];
  return { arr: elem, data: C ? new C(n) : new Array(n).fill(null) };
}
export const isArray = (v) => v !== null && typeof v === 'object' && 'arr' in v;
/** Dizi öğesi okuma/yazma: dizin denetimi ve NPE */
export function arrayLoad(a, i) {
  if (a === null) throw new JavaThrow('java/lang/NullPointerException');
  if (!isArray(a)) throw new Unsupported('dizi olmayan nesnede dizi erişimi');
  if (i < 0 || i >= a.data.length) throw new JavaThrow('java/lang/ArrayIndexOutOfBoundsException', String(i));
  return a.data[i];
}
export function arrayStore(a, i, v) {
  if (a === null) throw new JavaThrow('java/lang/NullPointerException');
  if (!isArray(a)) throw new Unsupported('dizi olmayan nesnede dizi erişimi');
  if (i < 0 || i >= a.data.length) throw new JavaThrow('java/lang/ArrayIndexOutOfBoundsException', String(i));
  a.data[i] = v;
}

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8');
const charsOf = (s) => Uint16Array.from({ length: s.length }, (_, i) => s.charCodeAt(i));
const strOf = (data, off = 0, n = data.length - off) => {
  let s = '';
  for (let i = off; i < off + n; i += 4096) s += String.fromCharCode(...data.subarray(i, Math.min(off + n, i + 4096)));
  return s;
};
const nn = (v) => { if (v === null || v === undefined) throw new JavaThrow('java/lang/NullPointerException'); return v; };
const str = (v) => { if (typeof nn(v) !== 'string') throw new Unsupported('String beklenirken başka nesne'); return v; };
const charArr = (ctx, a) => { if (!isArray(nn(a)) || a.arr !== 'C') throw new Unsupported('char[] beklenirken başka nesne'); return a; };
const byteArr = (a) => { if (!isArray(nn(a)) || a.arr !== 'B') throw new Unsupported('byte[] beklenirken başka nesne'); return a; };
const range = (len, off, n) => { if (off < 0 || n < 0 || off + n > len) throw new JavaThrow('java/lang/StringIndexOutOfBoundsException'); };
function makeString(ctx, s) {
  ctx.alloc(s.length);
  return s;
}
function charset(name) {
  const n = str(name).toUpperCase().replace(/_/g, '-');
  if (n === 'UTF-8' || n === 'UTF8') return 'utf8';
  if (n === 'ISO-8859-1' || n === 'LATIN1' || n === 'ISO8859-1') return 'latin1';
  if (n === 'US-ASCII' || n === 'ASCII') return 'ascii';
  throw new Unsupported(`desteklenmeyen karakter kümesi: ${name}`);
}
function bytesToString(ctx, b, cs = 'utf8', off = 0, n = b.data.length) {
  range(b.data.length, off, n);
  const part = new Uint8Array(b.data.buffer, b.data.byteOffset + off, n);
  if (cs === 'utf8') return makeString(ctx, dec.decode(part));
  let s = '';
  for (const x of part) s += String.fromCharCode(cs === 'ascii' && x > 0x7f ? 0xfffd : x);
  return makeString(ctx, s);
}
function stringToBytes(ctx, s, cs = 'utf8') {
  let data;
  if (cs === 'utf8') data = new Int8Array(enc.encode(s).buffer);
  else data = Int8Array.from(s, (c) => { const u = c.charCodeAt(0); return u > (cs === 'ascii' ? 0x7f : 0xff) ? 0x3f : u; });
  ctx.alloc(data.length);
  return { arr: 'B', data };
}
const toJavaString = (v, t) => {
  if (v === null) return 'null';
  if (t === 'C') return String.fromCharCode(v);
  if (t === 'Z') return v ? 'true' : 'false';
  if (t === 'F' || t === 'D') return javaFloatString(v, t);
  if (typeof v === 'bigint' || typeof v === 'number' || typeof v === 'string') return String(v);
  if (v?.cls === SB || v?.cls === SBUF) return v.s;
  if (isArray(v) && v.arr === 'C' && t === '[C') return strOf(v.data);
  throw new Unsupported('nesnenin toString() değeri bilinmiyor');
};
function javaFloatString(v, t) {
  if (Number.isNaN(v)) return 'NaN';
  if (!Number.isFinite(v)) return v > 0 ? 'Infinity' : '-Infinity';
  if (Number.isInteger(v) && Math.abs(v) < 1e7) return `${v}.0`;
  if (Math.abs(v) >= 1e-3 && Math.abs(v) < 1e7) return t === 'F' ? String(Math.fround(v)) : String(v);
  throw new Unsupported('bilimsel gösterimli kayan nokta dizgesi');
}

const SB = 'java/lang/StringBuilder';
const SBUF = 'java/lang/StringBuffer';
const B64J = 'java/util/Base64$Decoder';
const B64JE = 'java/util/Base64$Encoder';

function b64decode(ctx, s, url = false) {
  let t = str(s).replace(/[\r\n\s]/g, '');
  if (url) t = t.replace(/-/g, '+').replace(/_/g, '/');
  if (/[^A-Za-z0-9+/=]/.test(t)) throw new JavaThrow('java/lang/IllegalArgumentException', 'geçersiz Base64');
  const bin = atob(t.padEnd(Math.ceil(t.length / 4) * 4, '='));
  ctx.alloc(bin.length);
  return { arr: 'B', data: Int8Array.from(bin, (c) => (c.charCodeAt(0) << 24) >> 24) };
}
function b64encode(ctx, b) {
  const u = new Uint8Array(b.data.buffer, b.data.byteOffset, b.data.length);
  let bin = '';
  for (const x of u) bin += String.fromCharCode(x);
  return makeString(ctx, btoa(bin));
}

// anahtar: "sahip.ad tanımlayıcı"
const B = new Map();
const def = (owner, name, desc, fn) => B.set(`${owner}.${name}${desc}`, fn);

// java.lang.String
const S = 'java/lang/String';
def(S, '<init>', '()V', (ctx) => '');
def(S, '<init>', '([C)V', (ctx, [, a]) => makeString(ctx, strOf(charArr(ctx, a).data)));
def(S, '<init>', '([CII)V', (ctx, [, a, off, n]) => { charArr(ctx, a); range(a.data.length, off, n); return makeString(ctx, strOf(a.data, off, n)); });
def(S, '<init>', '([B)V', (ctx, [, b]) => bytesToString(ctx, byteArr(b)));
def(S, '<init>', '([BII)V', (ctx, [, b, off, n]) => bytesToString(ctx, byteArr(b), 'utf8', off, n));
def(S, '<init>', '([BLjava/lang/String;)V', (ctx, [, b, cs]) => bytesToString(ctx, byteArr(b), charset(cs)));
def(S, '<init>', '([BIILjava/lang/String;)V', (ctx, [, b, off, n, cs]) => bytesToString(ctx, byteArr(b), charset(cs), off, n));
def(S, '<init>', '(Ljava/lang/String;)V', (ctx, [, s]) => str(s));
def(S, '<init>', '(Ljava/lang/StringBuilder;)V', (ctx, [, sb]) => nn(sb).s);
def(S, 'length', '()I', (ctx, [s]) => str(s).length);
def(S, 'isEmpty', '()Z', (ctx, [s]) => (str(s).length === 0 ? 1 : 0));
def(S, 'charAt', '(I)C', (ctx, [s, i]) => { str(s); if (i < 0 || i >= s.length) throw new JavaThrow('java/lang/StringIndexOutOfBoundsException', String(i)); return s.charCodeAt(i); });
def(S, 'toCharArray', '()[C', (ctx, [s]) => { str(s); ctx.alloc(s.length); return { arr: 'C', data: charsOf(s) }; });
def(S, 'getBytes', '()[B', (ctx, [s]) => stringToBytes(ctx, str(s)));
def(S, 'getBytes', '(Ljava/lang/String;)[B', (ctx, [s, cs]) => stringToBytes(ctx, str(s), charset(cs)));
def(S, 'intern', '()Ljava/lang/String;', (ctx, [s]) => str(s));
def(S, 'toString', '()Ljava/lang/String;', (ctx, [s]) => str(s));
def(S, 'trim', '()Ljava/lang/String;', (ctx, [s]) => str(s).replace(/^[\x00-\x20]+|[\x00-\x20]+$/g, ''));
def(S, 'hashCode', '()I', (ctx, [s]) => { let h = 0; for (let i = 0; i < str(s).length; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) | 0; return h; });
def(S, 'equals', '(Ljava/lang/Object;)Z', (ctx, [s, o]) => (str(s) === o ? 1 : 0));
def(S, 'concat', '(Ljava/lang/String;)Ljava/lang/String;', (ctx, [s, o]) => makeString(ctx, str(s) + str(o)));
def(S, 'substring', '(I)Ljava/lang/String;', (ctx, [s, a]) => { range(str(s).length, a, s.length - a); return s.slice(a); });
def(S, 'substring', '(II)Ljava/lang/String;', (ctx, [s, a, b]) => { range(str(s).length, a, b - a); return s.slice(a, b); });
def(S, 'indexOf', '(I)I', (ctx, [s, c]) => str(s).indexOf(String.fromCharCode(c)));
def(S, 'indexOf', '(Ljava/lang/String;)I', (ctx, [s, o]) => str(s).indexOf(str(o)));
def(S, 'replace', '(CC)Ljava/lang/String;', (ctx, [s, a, b]) => makeString(ctx, str(s).split(String.fromCharCode(a)).join(String.fromCharCode(b))));
def(S, 'valueOf', '([C)Ljava/lang/String;', (ctx, [a]) => makeString(ctx, strOf(charArr(ctx, a).data)));
def(S, 'copyValueOf', '([C)Ljava/lang/String;', (ctx, [a]) => makeString(ctx, strOf(charArr(ctx, a).data)));
def(S, 'valueOf', '([CII)Ljava/lang/String;', (ctx, [a, off, n]) => { charArr(ctx, a); range(a.data.length, off, n); return makeString(ctx, strOf(a.data, off, n)); });
def(S, 'valueOf', '(C)Ljava/lang/String;', (ctx, [c]) => String.fromCharCode(c));
def(S, 'valueOf', '(I)Ljava/lang/String;', (ctx, [i]) => String(i));
def(S, 'valueOf', '(J)Ljava/lang/String;', (ctx, [i]) => String(i));
def(S, 'valueOf', '(Z)Ljava/lang/String;', (ctx, [b]) => (b ? 'true' : 'false'));
def(S, 'valueOf', '(Ljava/lang/Object;)Ljava/lang/String;', (ctx, [o]) => toJavaString(o));

// StringBuilder / StringBuffer
for (const C of [SB, SBUF]) {
  const self = (o) => { if (nn(o)?.cls !== C) throw new Unsupported(`${C} beklenirken başka nesne`); return o; };
  def(C, '<init>', '()V', (ctx, [o]) => self(o));
  def(C, '<init>', '(I)V', (ctx, [o, n]) => { if (n < 0) throw new JavaThrow('java/lang/NegativeArraySizeException'); return self(o); });
  def(C, '<init>', '(Ljava/lang/String;)V', (ctx, [o, s]) => { self(o).s = str(s); return o; });
  def(C, '<init>', '(Ljava/lang/CharSequence;)V', (ctx, [o, s]) => { self(o).s = toJavaString(s); return o; });
  const app = (t) => (ctx, [o, v]) => { self(o); const add = toJavaString(v, t); ctx.alloc(add.length); o.s += add; return o; };
  for (const [t, d] of [['C', 'C'], ['I', 'I'], ['J', 'J'], ['Z', 'Z'], ['F', 'F'], ['D', 'D'], ['L', 'Ljava/lang/String;'], ['L', 'Ljava/lang/Object;'], ['L', 'Ljava/lang/CharSequence;'], ['[C', '[C']]) {
    def(C, 'append', `(${d})L${C};`, app(t));
  }
  def(C, 'append', `(L${C};)L${C};`, app('L'));
  def(C, 'toString', '()Ljava/lang/String;', (ctx, [o]) => self(o).s);
  def(C, 'length', '()I', (ctx, [o]) => self(o).s.length);
  def(C, 'charAt', '(I)C', (ctx, [o, i]) => { if (i < 0 || i >= self(o).s.length) throw new JavaThrow('java/lang/StringIndexOutOfBoundsException'); return o.s.charCodeAt(i); });
  def(C, 'setCharAt', '(IC)V', (ctx, [o, i, c]) => { if (i < 0 || i >= self(o).s.length) throw new JavaThrow('java/lang/StringIndexOutOfBoundsException'); o.s = o.s.slice(0, i) + String.fromCharCode(c) + o.s.slice(i + 1); });
  def(C, 'reverse', `()L${C};`, (ctx, [o]) => { self(o).s = [...o.s].reverse().join(''); return o; });
  def(C, 'insert', `(IC)L${C};`, (ctx, [o, i, c]) => { range(self(o).s.length, i, 0); o.s = o.s.slice(0, i) + String.fromCharCode(c) + o.s.slice(i); return o; });
  def(C, 'insert', `(ILjava/lang/String;)L${C};`, (ctx, [o, i, s]) => { range(self(o).s.length, i, 0); o.s = o.s.slice(0, i) + toJavaString(s) + o.s.slice(i); return o; });
  def(C, 'deleteCharAt', `(I)L${C};`, (ctx, [o, i]) => { if (i < 0 || i >= self(o).s.length) throw new JavaThrow('java/lang/StringIndexOutOfBoundsException'); o.s = o.s.slice(0, i) + o.s.slice(i + 1); return o; });
  def(C, 'setLength', '(I)V', (ctx, [o, n]) => { if (n < 0) throw new JavaThrow('java/lang/StringIndexOutOfBoundsException'); self(o).s = o.s.slice(0, n).padEnd(n, '\0'); });
}

// Character, Integer, Math, System
def('java/lang/Character', 'toChars', '(I)[C', (ctx, [c]) => ({ arr: 'C', data: charsOf(String.fromCodePoint(c)) }));
def('java/lang/Character', 'toString', '(C)Ljava/lang/String;', (ctx, [c]) => String.fromCharCode(c));
def('java/lang/Character', 'isDigit', '(C)Z', (ctx, [c]) => (c >= 48 && c <= 57 ? 1 : 0));
def('java/lang/Character', 'isLetter', '(C)Z', (ctx, [c]) => (/\p{L}/u.test(String.fromCharCode(c)) ? 1 : 0));
def('java/lang/Character', 'toUpperCase', '(C)C', (ctx, [c]) => { const u = String.fromCharCode(c).toUpperCase(); return u.length === 1 ? u.charCodeAt(0) : c; });
def('java/lang/Character', 'toLowerCase', '(C)C', (ctx, [c]) => { const u = String.fromCharCode(c).toLowerCase(); return u.length === 1 ? u.charCodeAt(0) : c; });
const parseInt32 = (s, radix = 10) => {
  str(s);
  const ok = radix === 16 ? /^[+-]?[0-9a-fA-F]+$/ : radix === 10 ? /^[+-]?\d+$/ : /^[+-]?[0-9a-zA-Z]+$/;
  const v = ok.test(s) ? parseInt(s, radix) : NaN;
  if (!Number.isFinite(v) || v > 2147483647 || v < -2147483648) throw new JavaThrow('java/lang/NumberFormatException', s);
  return v;
};
def('java/lang/Integer', 'parseInt', '(Ljava/lang/String;)I', (ctx, [s]) => parseInt32(s));
def('java/lang/Integer', 'parseInt', '(Ljava/lang/String;I)I', (ctx, [s, r]) => parseInt32(s, r));
def('java/lang/Integer', 'toString', '(I)Ljava/lang/String;', (ctx, [i]) => String(i));
def('java/lang/Integer', 'toHexString', '(I)Ljava/lang/String;', (ctx, [i]) => (i >>> 0).toString(16));
def('java/lang/Math', 'abs', '(I)I', (ctx, [i]) => Math.abs(i) | 0);
def('java/lang/Math', 'min', '(II)I', (ctx, [a, b]) => Math.min(a, b));
def('java/lang/Math', 'max', '(II)I', (ctx, [a, b]) => Math.max(a, b));
def('java/lang/System', 'arraycopy', '(Ljava/lang/Object;ILjava/lang/Object;II)V', (ctx, [src, sp, dst, dp, n]) => {
  if (src === null || dst === null) throw new JavaThrow('java/lang/NullPointerException');
  if (!isArray(src) || !isArray(dst)) throw new Unsupported('arraycopy: dizi değil');
  if (src.arr !== dst.arr) throw new JavaThrow('java/lang/ArrayStoreException');
  if (sp < 0 || dp < 0 || n < 0 || sp + n > src.data.length || dp + n > dst.data.length) throw new JavaThrow('java/lang/ArrayIndexOutOfBoundsException');
  ctx.tick(n >> 4);
  dst.data.set(src.data.slice(sp, sp + n), dp);
});
def('java/lang/Object', '<init>', '()V', (ctx, [o]) => o);

// Base64
def('java/util/Base64', 'getDecoder', `()L${B64J};`, () => ({ cls: B64J, url: false }));
def('java/util/Base64', 'getUrlDecoder', `()L${B64J};`, () => ({ cls: B64J, url: true }));
def('java/util/Base64', 'getMimeDecoder', `()L${B64J};`, () => ({ cls: B64J, url: false }));
def('java/util/Base64', 'getEncoder', `()L${B64JE};`, () => ({ cls: B64JE }));
def(B64J, 'decode', '(Ljava/lang/String;)[B', (ctx, [d, s]) => b64decode(ctx, s, nn(d).url));
def(B64J, 'decode', '([B)[B', (ctx, [d, b]) => b64decode(ctx, bytesToString(ctx, byteArr(b), 'latin1'), nn(d).url));
def(B64JE, 'encodeToString', '([B)Ljava/lang/String;', (ctx, [, b]) => b64encode(ctx, byteArr(b)));
def('android/util/Base64', 'decode', '(Ljava/lang/String;I)[B', (ctx, [s, flags]) => b64decode(ctx, s, Boolean(flags & 8)));
def('android/util/Base64', 'decode', '([BI)[B', (ctx, [b, flags]) => b64decode(ctx, bytesToString(ctx, byteArr(b), 'latin1'), Boolean(flags & 8)));
def('android/util/Base64', 'encodeToString', '([BI)Ljava/lang/String;', (ctx, [b]) => b64encode(ctx, byteArr(b)));

/** new ile oluşturulabilen sınıflar: yeni nesnenin ilk hâli */
export function allocate(cls) {
  if (cls === SB || cls === SBUF) return { cls, s: '' };
  if (cls === S) return { uninit: S };
  if (cls === 'java/lang/Object') return { cls };
  return undefined;
}

export const builtin = (owner, name, desc) => B.get(`${owner}.${name}${desc}`);
export const BUILTINS = () => [...B.keys()];
export { charsOf, strOf };
