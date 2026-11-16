// Ölçüm: büyük, sentetik (zararsız) girdilerde tam hattın süresi. Sınıflar fixture üreticisiyle bayt olarak yazılır.
//   npm run bench
import { ClassBuilder } from '../scripts/lib/jasm.js';
import { buildDex } from '../scripts/lib/dexgen.js';
import { writeZip } from '../src/core/zip.js';
import { peel } from '../src/index.js';
import { ENCODERS } from '../scripts/lib/samples.js';

const S = 'Ljava/lang/String;';
// ProGuard biçimli adlar: a, b, ..., z, aa, ab, ... (paket başına en çok 500 sınıf)
const short = (n) => { let s = ''; for (n++; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(97 + ((n - 1) % 26)) + s; return s; };
const nameOf = (i) => `${short(Math.floor(i / 500))}/${short(i % 500)}`;

// N sınıf: her biri Allatori biçimli çözücüye K çağrı yapar, ProGuard biçimli kısa adlar
function bigJar(n, k) {
  const D = 'z/IiIiIIiIiI';
  const dec = new ClassBuilder(D);
  dec.method(9, 'ALLATORIxDEMO', `(${S})${S}`, (a) => a
    .op('aload', 0).invoke('invokevirtual', 'java/lang/String', 'length', '()I').op('istore', 1)
    .op('iload', 1).op('newarray', 5).op('astore', 2)
    .op('iload', 1).iconst(1).op('isub').op('istore', 3)
    .label('loop').op('iload', 3).jump('iflt', 'done')
    .op('aload', 2).op('iload', 3).op('aload', 0).op('iload', 3).invoke('invokevirtual', 'java/lang/String', 'charAt', '(I)C').iconst(0x58).op('ixor').op('i2c').op('castore')
    .op('iinc', 3, -1).op('iload', 3).jump('iflt', 'done')
    .op('aload', 2).op('iload', 3).op('aload', 0).op('iload', 3).invoke('invokevirtual', 'java/lang/String', 'charAt', '(I)C').iconst(0x2f).op('ixor').op('i2c').op('castore')
    .op('iinc', 3, -1).jump('goto', 'loop')
    .label('done').cls('new', 'java/lang/String').op('dup').op('aload', 2).invoke('invokespecial', 'java/lang/String', '<init>', '([C)V').op('areturn'));
  const files = [[`${D}.class`, dec.bytes()]];
  for (let i = 0; i < n; i++) {
    const name = nameOf(i);
    const c = new ClassBuilder(name);
    c.field(2, 'a', S).field(10, 'b', 'I');
    c.method(9, 'a', `()${S}`, (a) => {
      for (let j = 0; j < k; j++) a.ldc(ENCODERS.allatoriEnc(`message ${i}.${j} https://host${i % 7}.peel-demo.invalid/p/${j}`)).invoke('invokestatic', D, 'ALLATORIxDEMO', `(${S})${S}`).op('pop');
      a.ldc('').op('areturn');
    });
    c.method(9, 'b', '(I)I', (a) => a.op('iload', 0).iconst(3).op('imul').op('ireturn'));
    files.push([`${name}.class`, c.bytes()]);
  }
  return writeZip(files);
}

// N sınıflık DEX: her sınıfta K çözücü çağrısı (DexGuard biçimli (III)String)
function bigDex(n, k) {
  const text = 'Peel synthetic payload for benchmark runs';
  const data = [...new TextEncoder().encode(text)].map((b, i) => ((b ^ (0x5d + i)) << 24) >> 24);
  const classes = [{ type: 'Lo/a;', superType: 'Ljava/lang/Object;', fields: [{ name: '$$a', type: '[B', access: 0x1a }], methods: [
    { name: '<clinit>', params: [], ret: 'V', access: 0x10008, registers: 2, ins: 0, code: (a) => a.const(0, data.length).newArray(1, 0, '[B').fillArray(1, 1, data).field('sput-object', 1, 'Lo/a;', '$$a', '[B').op('return-void') },
    { name: '$', params: ['I', 'I', 'I'], ret: S, access: 8, registers: 8, ins: 3, code: (a) => a.newArray(0, 6, '[B').field('sget-object', 3, 'Lo/a;', '$$a', '[B').const(1, 0)
      .label('L').jump('if-ge', 'E', 1, 6).op('add-int', 2, 5, 1).op('aget-byte', 2, 3, 2).op('add-int', 4, 7, 1).op('xor-int/2addr', 2, 4).op('int-to-byte', 2, 2).op('aput-byte', 2, 0, 1)
      .op('add-int/lit8', 1, 1, 1).jump('goto/16', 'L').label('E').type('new-instance', 1, S).invoke('invoke-direct', [1, 0], S, '<init>', ['[B'], 'V').op('return-object', 1) },
  ] }];
  for (let i = 0; i < n; i++) {
    classes.push({ type: `Lo/${nameOf(i)};`, superType: 'Ljava/lang/Object;', methods: [{ name: 'a', params: [], ret: 'V', access: 9, registers: 4, ins: 0, outs: 3, code: (a) => {
      for (let j = 0; j < k; j++) a.const(0, 0).const(1, 4 + (j % 30)).const(2, 0x5d).invoke('invoke-static', [0, 1, 2], 'Lo/a;', '$', ['I', 'I', 'I'], S).op('move-result-object', 3);
      a.op('return-void');
    } }] });
  }
  return writeZip([['classes.dex', buildDex(classes)], ['AndroidManifest.xml', new Uint8Array(0)]]);
}

async function measure(label, bytes, name) {
  const times = [];
  let r;
  for (let i = 0; i < 3; i++) {
    const t = performance.now();
    r = await peel(bytes, { name, timeline: false });
    times.push(performance.now() - t);
  }
  times.sort((a, b) => a - b);
  const rep = r.report;
  console.log(`| ${label} | ${(bytes.length / 1024).toFixed(0)} KB | ${rep.info.classes} | ${rep.strings.decrypted}/${rep.strings.sites} | ${rep.metrics.renamed} | ${Math.round(times[1])} ms |`);
}

console.log('| Girdi / Input | Boyut / Size | Sınıf / Classes | Dizge / Strings | Ad / Names | Süre / Time (medyan) |');
console.log('|---|---|---|---|---|---|');
await measure('JAR, 1 000 sınıf × 10 çağrı', bigJar(1000, 10), 'big.jar');
await measure('JAR, 5 000 sınıf × 4 çağrı', bigJar(5000, 4), 'huge.jar');
await measure('APK, 2 000 sınıf × 10 çağrı', bigDex(2000, 10), 'big.apk');
console.log(`\nNode ${process.version}, ${process.platform}/${process.arch}`);
