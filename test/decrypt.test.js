// Dizge çözme ve yorumlayıcı testleri: her gizleyicinin çözücüsü kendi şifreleyicisinin tersini vermeli; JVM ve Dalvik
// aritmetiği Java anlamında olmalı; desteklenmeyen davranış çağrı yerini değiştirmeden raporlanmalı.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadProgram } from '../src/core/program.js';
import { createJvm, Unsupported } from '../src/jvm/interp.js';
import { createDalvik } from '../src/dex/interp.js';
import { parseClass } from '../src/jvm/classfile.js';
import { decryptJvm, decryptDex } from '../src/passes/strings.js';
import { ENCODERS } from '../scripts/lib/samples.js';
import { ClassBuilder } from '../scripts/lib/jasm.js';
import { buildDex } from '../scripts/lib/dexgen.js';
import { parseDex } from '../src/dex/dex.js';
import { builtin, createContext, JavaThrow } from '../src/sandbox/runtime.js';

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const S = 'Ljava/lang/String;';

// Allatori: ALLATORIxDEMO(enc(x)) === x, rastgele dizgelerle
const allatori = loadProgram(fx('allatori.jar'), 'allatori.jar');
const vm = createJvm(allatori.classMap);
for (const s of ['', 'a', 'ab', 'Merhaba dünya ğüşıöç', 'https://x.invalid/?q=1&r=2', '\u0000￿']) {
  assert.equal(vm.invoke('com/peel/demo/IiIiIIiIiI', 'ALLATORIxDEMO', `(${S})${S}`, [ENCODERS.allatoriEnc(s)]), s);
}
// ZKM: <clinit> çalışır, statik tablo okunur
const zkm = loadProgram(fx('zkm.jar'), 'zkm.jar');
const zvm = createJvm(zkm.classMap);
const table = zvm.getStatic('a/a', 'z');
assert.deepEqual([...table.data], ['Connecting to config server', 'http://203.0.113.7:8080/beacon', 'Done']);
assert.equal(zvm.invoke('a/a', 'z', `([C)${S}`, [{ arr: 'C', data: Uint16Array.from(ENCODERS.zkmEnc('xy'), (c) => c.charCodeAt(0)) }]), 'xy');
// Stringer: anahtar tablosu + uzunluk; yığın izi isteyen çözücü desteklenmez
const st = loadProgram(fx('stringer.jar'), 'stringer.jar');
const svm = createJvm(st.classMap);
assert.equal(svm.invoke('com/peel/s/a', 'a', `(Ljava/lang/Object;)${S}`, [ENCODERS.stringerEnc('çok gizli')]), 'çok gizli');
assert.throws(() => svm.invoke('com/peel/s/a', 'b', `(Ljava/lang/Object;)${S}`, ['x']), Unsupported);

// geçiş: çağrı yerleri ldc_w + nop olur, çözülemeyen yer değişmez
const r = decryptJvm(st);
assert.equal(r.stats.strings, 2);
assert.equal(r.failures.length, 1);
assert.match(r.failures[0].reason, /java\/lang\/Thread\.currentThread/);
const dec = r.decryptors.find((d) => d.name === 'b');
assert.deepEqual([dec.sites, dec.decoded, dec.failed], [1, 0, 1]);

// JVM anlamı: tamsayı taşması, bölme, istisna işleyici, long, char, kaydırma, dizi sınırı
const t = new ClassBuilder('t/M');
t.method(9, 'ov', '()I', (a) => a.iconst(0x7fffffff).iconst(1).op('iadd').op('ireturn'));
t.method(9, 'div', '(II)I', (a) => a.label('s').op('iload', 0).op('iload', 1).op('idiv').op('ireturn').label('e').label('h').op('pop').iconst(-7).op('ireturn'), { exceptions: [{ start: 's', end: 'e', handler: 'h', type: 'java/lang/ArithmeticException' }] });
t.method(9, 'lng', '(J)J', (a) => a.op('lload', 0).lconst(-3n).op('lmul').iconst(65).op('lushr').op('lreturn'));
t.method(9, 'chr', '(I)C', (a) => a.op('iload', 0).op('i2c').op('ireturn'));
t.method(9, 'shr', '(I)I', (a) => a.op('iload', 0).iconst(33).op('iushr').op('ireturn'));
t.method(9, 'oob', '()I', (a) => a.iconst(2).op('newarray', 10).iconst(5).op('iaload').op('ireturn'));
t.method(9, 'sb', `()${S}`, (a) => a.cls('new', 'java/lang/StringBuilder').op('dup').invoke('invokespecial', 'java/lang/StringBuilder', '<init>', '()V')
  .iconst(72).invoke('invokevirtual', 'java/lang/StringBuilder', 'append', '(C)Ljava/lang/StringBuilder;')
  .iconst(-5).invoke('invokevirtual', 'java/lang/StringBuilder', 'append', '(I)Ljava/lang/StringBuilder;')
  .invoke('invokevirtual', 'java/lang/StringBuilder', 'reverse', '()Ljava/lang/StringBuilder;')
  .invoke('invokevirtual', 'java/lang/StringBuilder', 'toString', `()${S}`).op('areturn'));
t.method(9, 'b64', `()${S}`, (a) => a.cls('new', 'java/lang/String').op('dup').invoke('invokestatic', 'java/util/Base64', 'getDecoder', '()Ljava/util/Base64$Decoder;')
  .ldc('cGVlbA==').invoke('invokevirtual', 'java/util/Base64$Decoder', 'decode', `(${S})[B`).invoke('invokespecial', 'java/lang/String', '<init>', '([B)V').op('areturn'));
t.method(9, 'io', `()${S}`, (a) => a.invoke('invokestatic', 'java/lang/System', 'currentTimeMillis', '()J').op('pop2').ldc('x').op('areturn'));
const tvm = createJvm(new Map([['t/M', parseClass(t.bytes())]]));
assert.equal(tvm.invoke('t/M', 'ov', '()I', []), -2147483648);
assert.equal(tvm.invoke('t/M', 'div', '(II)I', [7, 2]), 3);
assert.equal(tvm.invoke('t/M', 'div', '(II)I', [-7, 2]), -3);
assert.equal(tvm.invoke('t/M', 'div', '(II)I', [1, 0]), -7, 'ArithmeticException işleyiciye gitmeli');
assert.equal(tvm.invoke('t/M', 'div', '(II)I', [-2147483648, -1]), -2147483648);
assert.equal(tvm.invoke('t/M', 'lng', '(J)J', [5n]), BigInt.asIntN(64, BigInt.asUintN(64, -15n) >> 1n));
assert.equal(tvm.invoke('t/M', 'chr', '(I)C', [-1]), 0xffff);
assert.equal(tvm.invoke('t/M', 'shr', '(I)I', [-8]), (-8 >>> 1) | 0);
assert.throws(() => tvm.invoke('t/M', 'oob', '()I', []), JavaThrow);
assert.equal(tvm.invoke('t/M', 'sb', `()${S}`, []), '5-H');
assert.equal(tvm.invoke('t/M', 'b64', `()${S}`, []), 'peel');
assert.throws(() => tvm.invoke('t/M', 'io', `()${S}`, []), Unsupported, 'saat erişimi desteklenmemeli');

// çalışma zamanı: yan etkili API'ler listede yok
for (const [o, n, d] of [['java/lang/System', 'exit', '(I)V'], ['java/lang/Runtime', 'exec', `(${S})Ljava/lang/Process;`], ['java/lang/Class', 'forName', `(${S})Ljava/lang/Class;`], ['java/io/File', '<init>', `(${S})V`]]) {
  assert.equal(builtin(o, n, d), undefined, `${o}.${n} sandbox'ta olmamalı`);
}
assert.equal(builtin('java/lang/String', 'charAt', '(I)C')(createContext(), ['abc', 1]), 98);

// Dalvik: DexGuard benzeri çözücü, statik değerler, mutable statik koruması
const apk = loadProgram(fx('dexguard.apk'), 'dexguard.apk');
const dvm = createDalvik(apk.dexes.map((d) => d.dex));
assert.equal(dvm.getStatic('Lo/b;', '$$b'), 9);
const d = decryptDex(apk);
assert.equal(d.stats.strings, 4);
assert.deepEqual(d.values.map((v) => v.value), ['Welcome to the Peel demo', 'https://config.peel-demo.invalid/v1/flags', 'dalvik.system.DexClassLoader', 'peelcore']);
const marks = [...d.notes.values()][0];
assert.equal(marks.size, 4);
for (const m of marks.values()) assert.equal(m.reg, 3);

// Dalvik aritmetiği: lit8, rem, xor, int-to-char
const ddex = parseDex(buildDex([{ type: 'Lt/D;', superType: 'Ljava/lang/Object;', methods: [
  { name: 'f', params: ['I', 'I'], ret: 'I', access: 9, registers: 3, ins: 2, code: (a) => a.op('rem-int', 0, 1, 2).op('xor-int/lit8', 0, 0, 0x55).op('add-int/lit8', 0, 0, -1).op('int-to-char', 0, 0).op('return', 0) },
] }]));
const dd = createDalvik([ddex]);
assert.equal(dd.invoke('Lt/D;', 'f', '(II)I', [-7, 3]), ((((-7 % 3) ^ 0x55) - 1) & 0xffff));
// sput ile <clinit> dışında yazılan statik alana bağlı çözücü değerlendirilmez
const mutDex = parseDex(buildDex([{ type: 'Lt/K;', superType: 'Ljava/lang/Object;', fields: [{ name: 'k', type: S, access: 9 }], methods: [
  { name: 'set', params: [S], ret: 'V', access: 9, registers: 1, ins: 1, code: (a) => a.field('sput-object', 0, 'Lt/K;', 'k', S).op('return-void') },
  { name: 'get', params: [S], ret: S, access: 9, registers: 2, ins: 1, code: (a) => a.field('sget-object', 0, 'Lt/K;', 'k', S).op('return-object', 0) },
  { name: 'use', params: [], ret: 'V', access: 9, registers: 2, ins: 0, outs: 1, code: (a) => a.str(0, 'q').invoke('invoke-static', [0], 'Lt/K;', 'get', [S], S).op('move-result-object', 1).op('return-void') },
] }]));
const mut = decryptDex({ dexes: [{ dex: mutDex }] });
assert.equal(mut.stats.strings, 0);
assert.match(mut.failures[0].reason, /değişen statik/);

console.log(`decrypt: Allatori, ZKM, Stringer, DexGuard çözücüleri; JVM ${tvm.steps()} adım son çağrı; desteklenmeyen ${r.failures.length + mut.failures.length} çağrı raporlandı`);
