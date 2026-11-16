// Küçük JVM sınıf dosyası derleyicisi (yalnızca fixture üretimi için; JDK gerekmez). Etiketli dallar, tableswitch,
// invokedynamic ve özel öznitelikler desteklenir. Sınıflar 50 (Java 6) sürümüyle yazılır: bu sürümde StackMapTable
// zorunlu değildir, yani üretilen dosyalar gerçek bir JVM'de de doğrulanır.
import { OP } from '../../src/jvm/opcodes.js';
import { addUtf8, addString, addClass, addNat, addInt, addLong, addRef, writeClass, TAG } from '../../src/jvm/classfile.js';
import { Writer } from '../../src/core/bytes.js';

class Asm {
  constructor(cf) {
    this.cf = cf;
    this.out = [];
    this.labels = new Map();
    this.fixups = [];
  }
  get pc() { return this.out.length; }
  u1(v) { this.out.push(v & 0xff); }
  u2(v) { this.out.push((v >> 8) & 0xff, v & 0xff); }
  u4(v) { this.out.push((v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff); }
  op(name, ...a) {
    const op = OP[name];
    if (op === undefined) throw new Error(`bilinmeyen komut ${name}`);
    this.u1(op);
    if (name === 'bipush' || name === 'newarray') this.u1(a[0]);
    else if (name === 'sipush') this.u2(a[0]);
    else if (name === 'iinc') { this.u1(a[0]); this.u1(a[1]); } else if (/^[ilfda](load|store)$/.test(name)) this.u1(a[0]);
    return this;
  }
  label(name) { this.labels.set(name, this.pc); return this; }
  jump(name, label) {
    const at = this.pc;
    this.u1(OP[name]);
    this.fixups.push({ at: this.pc, from: at, label, size: 2 });
    this.u2(0);
    return this;
  }
  iconst(n) {
    if (n >= -1 && n <= 5) return this.op(`iconst_${n === -1 ? 'm1' : n}`);
    if (n >= -128 && n <= 127) return this.op('bipush', n);
    if (n >= -32768 && n <= 32767) return this.op('sipush', n);
    return this.ldcIndex(addInt(this.cf, n));
  }
  ldcIndex(i) {
    if (i < 256) { this.u1(OP.ldc); this.u1(i); } else { this.u1(OP.ldc_w); this.u2(i); }
    return this;
  }
  ldc(s) { return this.ldcIndex(addString(this.cf, s)); }
  lconst(v) { this.u1(OP.ldc2_w); this.u2(addLong(this.cf, v)); return this; }
  field(name, owner, fname, desc) { this.u1(OP[name]); this.u2(addRef(this.cf, TAG.Fieldref, owner, fname, desc)); return this; }
  invoke(name, owner, mname, desc, iface = false) {
    this.u1(OP[name]);
    this.u2(addRef(this.cf, iface ? TAG.InterfaceMethodref : TAG.Methodref, owner, mname, desc));
    if (name === 'invokeinterface') {
      let n = 1;
      const params = desc.slice(1, desc.indexOf(')')).match(/\[*(?:L[^;]+;|[BCDFIJSZ])/g) ?? [];
      for (const p of params) n += p === 'J' || p === 'D' ? 2 : 1;
      this.u1(n);
      this.u1(0);
    }
    return this;
  }
  cls(name, cname) { this.u1(OP[name]); this.u2(addClass(this.cf, cname)); return this; }
  indy(bsm, name, desc) {
    this.u1(OP.invokedynamic);
    this.cf.cp.push({ tag: TAG.InvokeDynamic, bsmIndex: bsm, natIndex: addNat(this.cf, name, desc) });
    this.u2(this.cf.cp.length - 1);
    this.u2(0);
    return this;
  }
  tableswitch(low, labels, dflt) {
    const at = this.pc;
    this.u1(OP.tableswitch);
    while (this.pc % 4) this.u1(0);
    this.fixups.push({ at: this.pc, from: at, label: dflt, size: 4 });
    this.u4(0);
    this.u4(low);
    this.u4(low + labels.length - 1);
    for (const l of labels) { this.fixups.push({ at: this.pc, from: at, label: l, size: 4 }); this.u4(0); }
    return this;
  }
  bytes() {
    const b = Uint8Array.from(this.out);
    const dv = new DataView(b.buffer);
    for (const f of this.fixups) {
      const to = this.labels.get(f.label);
      if (to === undefined) throw new Error(`etiket yok: ${f.label}`);
      if (f.size === 2) dv.setInt16(f.at, to - f.from); else dv.setInt32(f.at, to - f.from);
    }
    return b;
  }
}

export class ClassBuilder {
  constructor(name, { access = 0x21, superName = 'java/lang/Object', interfaces = [], major = 50 } = {}) {
    this.cf = { minor: 0, major, cp: [null], index: new Map(), access, thisClass: 0, superClass: 0, interfaces: [], fields: [], methods: [], attrs: [] };
    this.cf.thisClass = addClass(this.cf, name);
    this.cf.superClass = superName ? addClass(this.cf, superName) : 0;
    this.cf.interfaces = interfaces.map((i) => addClass(this.cf, i));
    this.bsms = [];
    this.name = name;
  }
  field(access, name, desc, constantValue) {
    const f = { access, nameIndex: addUtf8(this.cf, name), descIndex: addUtf8(this.cf, desc), attrs: [] };
    if (constantValue !== undefined) {
      const idx = typeof constantValue === 'string' ? addString(this.cf, constantValue) : addInt(this.cf, constantValue);
      f.attrs.push({ nameIndex: addUtf8(this.cf, 'ConstantValue'), data: Uint8Array.of(idx >> 8, idx & 0xff) });
    }
    this.cf.fields.push(f);
    return this;
  }
  method(access, name, desc, body, { maxStack = 12, maxLocals = 12, exceptions = [] } = {}) {
    const m = { access, nameIndex: addUtf8(this.cf, name), descIndex: addUtf8(this.cf, desc), attrs: [] };
    if (body) {
      const a = new Asm(this.cf);
      body(a);
      const code = { maxStack, maxLocals, code: a.bytes(), exceptions: exceptions.map((e) => ({ start: a.labels.get(e.start), end: a.labels.get(e.end), handler: a.labels.get(e.handler), catchType: e.type ? addClass(this.cf, e.type) : 0 })), attrs: [] };
      m.attrs.push({ nameIndex: addUtf8(this.cf, 'Code'), code });
      m.code = code;
    }
    this.cf.methods.push(m);
    return this;
  }
  /** Önyükleme yöntemi ekler, indeksini döner (invokedynamic için) */
  bootstrap(kind, owner, name, desc, args = []) {
    this.cf.cp.push({ tag: TAG.MethodHandle, kind, refIndex: addRef(this.cf, TAG.Methodref, owner, name, desc) });
    const mh = this.cf.cp.length - 1;
    this.bsms.push({ mh, args: args.map((x) => (typeof x === 'string' ? addString(this.cf, x) : x)) });
    return this.bsms.length - 1;
  }
  sourceFile(name) {
    const i = addUtf8(this.cf, name);
    this.cf.attrs.push({ nameIndex: addUtf8(this.cf, 'SourceFile'), data: Uint8Array.of(i >> 8, i & 0xff) });
    return this;
  }
  bytes() {
    if (this.bsms.length) {
      const w = new Writer();
      w.u2(this.bsms.length);
      for (const b of this.bsms) { w.u2(b.mh).u2(b.args.length); for (const x of b.args) w.u2(x); }
      this.cf.attrs.push({ nameIndex: addUtf8(this.cf, 'BootstrapMethods'), data: w.done() });
      this.bsms = [];
    }
    return writeClass(this.cf);
  }
}
