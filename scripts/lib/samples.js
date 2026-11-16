// Zararsız örnek programlar: her gizleyicinin bilinen kalıbını taklit eden küçük JAR/APK/AAR/sınıf dosyaları.
// Hiçbiri ağa bağlanmaz, dosya yazmaz ya da komut çalıştırmaz; adresler .invalid alan adları ve belgeleme IP aralığıdır
// (203.0.113.0/24). Şifreleme algoritmaları gerçek gizleyicilerin yayımlanmış kalıplarıyla aynı biçimdedir.
import { ClassBuilder } from './jasm.js';
import { buildDex } from './dexgen.js';
import { buildAxml } from './axmlgen.js';
import { rawZip } from './rawzip.js';
import { writeZip } from '../../src/core/zip.js';

const OBJ = 'java/lang/Object';
const STR = 'Ljava/lang/String;';
const PS = 'java/io/PrintStream';
const enc = new TextEncoder();
const manifestMf = (main) => enc.encode(`Manifest-Version: 1.0\r\nCreated-By: peel-fixtures\r\n${main ? `Main-Class: ${main}\r\n` : ''}\r\n`);
const ctor = (c, sup = OBJ) => c.method(1, '<init>', '()V', (a) => a.op('aload', 0).invoke('invokespecial', sup, '<init>', '()V').op('return'));
const println = (a, emit) => { a.field('getstatic', 'java/lang/System', 'out', `L${PS};`); emit(a); return a.invoke('invokevirtual', PS, 'println', `(${STR})V`); };

// ── ProGuard / R8 ──
export function proguardJar() {
  const main = new ClassBuilder('com/example/app/Main').sourceFile('SourceFile');
  ctor(main);
  main.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    a.cls('new', 'a/a').op('dup').invoke('invokespecial', 'a/a', '<init>', '()V').op('astore', 1);
    println(a, (x) => x.op('aload', 1).ldc('status').invoke('invokevirtual', 'a/a', 'a', `(${STR})${STR}`));
    a.op('aload', 1).invoke('invokevirtual', 'a/a', 'b', '()V');
    a.cls('new', 'a/c').op('dup').invoke('invokespecial', 'a/c', '<init>', '()V').op('astore', 2);
    a.op('aload', 2).invoke('invokeinterface', 'a/b', 'a', '()V', true);
    a.op('return');
  });
  const client = new ClassBuilder('a/a').sourceFile('SourceFile');
  client.field(2, 'a', STR).field(2, 'b', 'I');
  client.method(1, '<init>', '()V', (a) => a.op('aload', 0).invoke('invokespecial', OBJ, '<init>', '()V')
    .op('aload', 0).ldc('https://api.peel-demo.invalid/v1/').field('putfield', 'a/a', 'a', STR)
    .op('aload', 0).iconst(3).field('putfield', 'a/a', 'b', 'I').op('return'));
  client.method(1, 'a', `(${STR})${STR}`, (a) => a.cls('new', 'java/lang/StringBuilder').op('dup').invoke('invokespecial', 'java/lang/StringBuilder', '<init>', '()V')
    .op('aload', 0).field('getfield', 'a/a', 'a', STR).invoke('invokevirtual', 'java/lang/StringBuilder', 'append', `(${STR})Ljava/lang/StringBuilder;`)
    .op('aload', 1).invoke('invokevirtual', 'java/lang/StringBuilder', 'append', `(${STR})Ljava/lang/StringBuilder;`)
    .invoke('invokevirtual', 'java/lang/StringBuilder', 'toString', `()${STR}`).op('areturn'));
  client.method(1, 'b', '()V', (a) => a.op('aload', 0).iconst(0).field('putfield', 'a/a', 'b', 'I').op('return'));
  const task = new ClassBuilder('a/b', { access: 0x601 }).sourceFile('SourceFile');
  task.method(0x401, 'a', '()V');
  const ping = new ClassBuilder('a/c', { interfaces: ['a/b'] }).sourceFile('SourceFile');
  ctor(ping);
  ping.method(1, 'a', '()V', (a) => println(a, (x) => x.ldc('ping')).op('return'));
  const jar = writeZip([
    ['META-INF/MANIFEST.MF', manifestMf('com.example.app.Main')],
    ['com/example/app/Main.class', main.bytes()],
    ['a/a.class', client.bytes()],
    ['a/b.class', task.bytes()],
    ['a/c.class', ping.bytes()],
  ]);
  const mapping = `# compiler: R8
# compiler_version: 8.5.35
com.example.app.Main -> com.example.app.Main:
    1:4:void main(java.lang.String[]):10:13 -> main
com.example.app.net.UpdateClient -> a.a:
    java.lang.String endpoint -> a
    int retries -> b
    1:3:void <init>():5:7 -> <init>
    1:1:java.lang.String fetch(java.lang.String):12:12 -> a
    1:1:void reset():16:16 -> b
com.example.app.net.Task -> a.b:
    void execute() -> a
com.example.app.net.PingTask -> a.c:
    1:1:void <init>():3:3 -> <init>
    1:1:void execute():6:6 -> a
`;
  return { jar, mapping };
}

// ── Allatori ──
const allatoriEnc = (s, k1 = 0x58, k2 = 0x2f) => {
  const a = [...s].map((c) => c.charCodeAt(0));
  for (let i = a.length - 1, t = 0; i >= 0; i--, t++) a[i] ^= t % 2 ? k2 : k1;
  return String.fromCharCode(...a);
};
export function allatoriJar() {
  const D = 'com/peel/demo/IiIiIIiIiI';
  const dec = new ClassBuilder(D, { access: 0x31 });
  ctor(dec);
  // Allatori: sondan başa, iki anahtarı sırayla kullanan XOR
  dec.method(9, 'ALLATORIxDEMO', `(${STR})${STR}`, (a) => a
    .op('aload', 0).invoke('invokevirtual', 'java/lang/String', 'length', '()I').op('istore', 1)
    .op('iload', 1).op('newarray', 5).op('astore', 2)
    .op('iload', 1).iconst(1).op('isub').op('istore', 3)
    .label('loop').op('iload', 3).jump('iflt', 'done')
    .op('aload', 2).op('iload', 3).op('aload', 0).op('iload', 3).invoke('invokevirtual', 'java/lang/String', 'charAt', '(I)C').iconst(0x58).op('ixor').op('i2c').op('castore')
    .op('iinc', 3, -1).op('iload', 3).jump('iflt', 'done')
    .op('aload', 2).op('iload', 3).op('aload', 0).op('iload', 3).invoke('invokevirtual', 'java/lang/String', 'charAt', '(I)C').iconst(0x2f).op('ixor').op('i2c').op('castore')
    .op('iinc', 3, -1).jump('goto', 'loop')
    .label('done').cls('new', 'java/lang/String').op('dup').op('aload', 2).invoke('invokespecial', 'java/lang/String', '<init>', '([C)V').op('areturn'));
  const util = new ClassBuilder('com/peel/demo/iIiIiIIiIi', { access: 0x31 });
  util.field(0x1a, 'IIiIiIIiIi', 'I', 7);
  ctor(util);
  util.method(9, 'iIIiIiIiII', '(II)I', (a) => a.op('iload', 0).op('iload', 1).op('iadd').field('getstatic', 'com/peel/demo/iIiIiIIiIi', 'IIiIiIIiIi', 'I').op('imul').op('ireturn'));
  const main = new ClassBuilder('com/peel/demo/Launcher');
  ctor(main);
  const msgs = ['Peel demo ready', 'https://cdn.peel-demo.invalid/update.json', 'Checking for updates...', 'Allatori Obfuscator DEMO'];
  main.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    for (const m of msgs) println(a, (x) => x.ldc(allatoriEnc(m)).invoke('invokestatic', D, 'ALLATORIxDEMO', `(${STR})${STR}`));
    a.iconst(2).iconst(3).invoke('invokestatic', 'com/peel/demo/iIiIiIIiIi', 'iIIiIiIiII', '(II)I').op('pop');
    a.op('return');
  });
  return writeZip([
    ['META-INF/MANIFEST.MF', manifestMf('com.peel.demo.Launcher')],
    ['com/peel/demo/Launcher.class', main.bytes()],
    [`${D}.class`, dec.bytes()],
    ['com/peel/demo/iIiIiIIiIi.class', util.bytes()],
  ]);
}

// ── Zelix KlassMaster ──
const ZKM_KEYS = [0x11, 0x4b, 0x33, 0x7c, 0x5e];
const zkmEnc = (s) => {
  const c = [...s].map((x) => x.charCodeAt(0));
  for (let i = 0; i < c.length; i++) c[i] ^= ZKM_KEYS[i % 5];
  if (c.length < 2) c[0] ^= 0x2a;
  return String.fromCharCode(...c);
};
export function zkmJar() {
  const T = 'a/a';
  const strs = ['Connecting to config server', 'http://203.0.113.7:8080/beacon', 'Done'];
  const t = new ClassBuilder(T, { access: 0x31 });
  t.field(0x1a, 'z', `[${STR}`);
  ctor(t);
  t.method(8, '<clinit>', '()V', (a) => {
    a.iconst(strs.length).cls('anewarray', 'java/lang/String');
    strs.forEach((s, i) => a.op('dup').iconst(i).ldc(zkmEnc(s)).invoke('invokestatic', T, 'z', `(${STR})[C`).invoke('invokestatic', T, 'z', `([C)${STR}`).op('aastore'));
    a.field('putstatic', T, 'z', `[${STR}`).op('return');
  });
  t.method(0xa, 'z', `(${STR})[C`, (a) => a.op('aload', 0).invoke('invokevirtual', 'java/lang/String', 'toCharArray', '()[C').op('dup').op('arraylength').iconst(2).jump('if_icmpge', 'ok')
    .op('dup').iconst(0).op('dup2').op('caload').iconst(0x2a).op('ixor').op('i2c').op('castore').label('ok').op('areturn'));
  t.method(0xa, 'z', `([C)${STR}`, (a) => a.iconst(0).op('istore', 1)
    .label('loop').op('iload', 1).op('aload', 0).op('arraylength').jump('if_icmpge', 'end')
    .op('iload', 1).iconst(5).op('irem')
    .tableswitch(0, ['k0', 'k1', 'k2', 'k3'], 'k4')
    .label('k0').iconst(0x11).op('istore', 2).jump('goto', 'apply')
    .label('k1').iconst(0x4b).op('istore', 2).jump('goto', 'apply')
    .label('k2').iconst(0x33).op('istore', 2).jump('goto', 'apply')
    .label('k3').iconst(0x7c).op('istore', 2).jump('goto', 'apply')
    .label('k4').iconst(0x5e).op('istore', 2)
    .label('apply').op('aload', 0).op('iload', 1).op('dup2').op('caload').op('iload', 2).op('ixor').op('i2c').op('castore')
    .op('iinc', 1, 1).jump('goto', 'loop')
    .label('end').cls('new', 'java/lang/String').op('dup').op('aload', 0).invoke('invokespecial', 'java/lang/String', '<init>', '([C)V').invoke('invokevirtual', 'java/lang/String', 'intern', `()${STR}`).op('areturn'));
  const main = new ClassBuilder('a/b');
  ctor(main);
  main.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    for (let i = 0; i < strs.length; i++) println(a, (x) => x.field('getstatic', T, 'z', `[${STR}`).iconst(i).op('aaload'));
    a.op('return');
  });
  return writeZip([['META-INF/MANIFEST.MF', manifestMf('a.b')], ['a/a.class', t.bytes()], ['a/b.class', main.bytes()]]);
}

// ── Stringer ──
const STRINGER_KEY = [0x1f, 0x52, 0x0c, 0x39];
const stringerEnc = (s) => String.fromCharCode(...[...s].map((c, i) => c.charCodeAt(0) ^ STRINGER_KEY[i & 3] ^ (s.length & 0xff)));
export function stringerJar() {
  const K = 'com/peel/s/a';
  const k = new ClassBuilder(K, { access: 0x31 });
  k.field(0x1a, 'k', '[I');
  ctor(k);
  k.method(8, '<clinit>', '()V', (a) => {
    a.iconst(4).op('newarray', 10);
    STRINGER_KEY.forEach((v, i) => a.op('dup').iconst(i).iconst(v).op('iastore'));
    a.field('putstatic', K, 'k', '[I').op('return');
  });
  // Object → String: anahtar tablosu ve dizge uzunluğu
  k.method(9, 'a', `(Ljava/lang/Object;)${STR}`, (a) => a
    .op('aload', 0).cls('checkcast', 'java/lang/String').invoke('invokevirtual', 'java/lang/String', 'toCharArray', '()[C').op('astore', 1)
    .iconst(0).op('istore', 2)
    .label('loop').op('iload', 2).op('aload', 1).op('arraylength').jump('if_icmpge', 'end')
    .op('aload', 1).op('iload', 2).op('dup2').op('caload')
    .field('getstatic', K, 'k', '[I').op('iload', 2).iconst(3).op('iand').op('iaload').op('ixor')
    .op('aload', 1).op('arraylength').iconst(255).op('iand').op('ixor')
    .op('i2c').op('castore')
    .op('iinc', 2, 1).jump('goto', 'loop')
    .label('end').cls('new', 'java/lang/String').op('dup').op('aload', 1).invoke('invokespecial', 'java/lang/String', '<init>', '([C)V').op('areturn'));
  // çağıran yönteme bağlı anahtar: yığın izi gerekir, sandbox bunu taklit etmez (bilinçli olarak çözülmez)
  k.method(9, 'b', `(Ljava/lang/Object;)${STR}`, (a) => a
    .invoke('invokestatic', 'java/lang/Thread', 'currentThread', '()Ljava/lang/Thread;')
    .invoke('invokevirtual', 'java/lang/Thread', 'getStackTrace', '()[Ljava/lang/StackTraceElement;')
    .iconst(1).op('aaload').invoke('invokevirtual', 'java/lang/StackTraceElement', 'getMethodName', `()${STR}`)
    .invoke('invokevirtual', 'java/lang/String', 'hashCode', '()I').op('pop')
    .op('aload', 0).cls('checkcast', 'java/lang/String').op('areturn'));
  const B = 'com/peel/s/b';
  const boot = new ClassBuilder(B, { major: 51, access: 0x31 });
  ctor(boot);
  boot.method(9, 'bsm', '(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;', (a) => a.op('aconst_null').op('areturn'));
  const main = new ClassBuilder('com/peel/s/Main', { major: 51 });
  ctor(main);
  const bsm = main.bootstrap(6, B, 'bsm', '(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;');
  main.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    println(a, (x) => x.ldc(stringerEnc('License check passed')).invoke('invokestatic', K, 'a', `(Ljava/lang/Object;)${STR}`));
    println(a, (x) => x.ldc(stringerEnc('mailto:support@peel-demo.invalid')).invoke('invokestatic', K, 'a', `(Ljava/lang/Object;)${STR}`));
    println(a, (x) => x.ldc('context-bound secret').invoke('invokestatic', K, 'b', `(Ljava/lang/Object;)${STR}`));
    a.indy(bsm, 'run', '()V').op('return');
  });
  return writeZip([['META-INF/MANIFEST.MF', manifestMf('com.peel.s.Main')], ['com/peel/s/Main.class', main.bytes()], [`${K}.class`, k.bytes()], [`${B}.class`, boot.bytes()]]);
}

// ── DexGuard benzeri APK ──
const DG_TEXT = ['https://config.peel-demo.invalid/v1/flags', 'dalvik.system.DexClassLoader', 'Welcome to the Peel demo', 'peelcore'];
const DG_KEY = 0x5d;
function dgLayout() {
  const parts = [];
  const data = [];
  for (const s of DG_TEXT) {
    const b = enc.encode(s);
    parts.push([data.length, b.length]);
    b.forEach((x, i) => data.push((((x ^ (DG_KEY + i)) << 24) >> 24)));
  }
  return { parts, data };
}
export function dexguardApk() {
  const A = 'Lo/a;';
  const S = 'Ljava/lang/String;';
  const { parts, data } = dgLayout();
  const call = (asm, [off, len], reg) => asm.const(0, off).const(1, len).const(2, DG_KEY).invoke('invoke-static', [0, 1, 2], A, '$', ['I', 'I', 'I'], S).op('move-result-object', reg);
  const dex = buildDex([
    { type: A, access: 0x11, superType: 'Ljava/lang/Object;', sourceFile: 'a', fields: [{ name: '$$a', type: '[B', access: 0x1a }], methods: [
      { name: '<clinit>', params: [], ret: 'V', access: 0x10008, registers: 2, ins: 0, code: (a) => a.const(0, data.length).newArray(1, 0, '[B').fillArray(1, 1, data).field('sput-object', 1, A, '$$a', '[B').op('return-void') },
      { name: '$', params: ['I', 'I', 'I'], ret: S, access: 0x8, registers: 8, ins: 3, outs: 2, code: (a) => a
        .newArray(0, 6, '[B').field('sget-object', 3, A, '$$a', '[B').const(1, 0)
        .label('L').jump('if-ge', 'E', 1, 6)
        .op('add-int', 2, 5, 1).op('aget-byte', 2, 3, 2).op('add-int', 4, 7, 1).op('xor-int/2addr', 2, 4).op('int-to-byte', 2, 2).op('aput-byte', 2, 0, 1)
        .op('add-int/lit8', 1, 1, 1).jump('goto/16', 'L')
        .label('E').type('new-instance', 1, S).invoke('invoke-direct', [1, 0], S, '<init>', ['[B'], 'V').op('return-object', 1) },
    ] },
    { type: 'Lo/b;', access: 0x11, superType: 'Ljava/lang/Object;', sourceFile: 'b', fields: [{ name: '$$b', type: 'I', access: 0x1a, value: 9 }], methods: [
      { name: '$', params: ['I'], ret: 'I', access: 0x8, registers: 2, ins: 1, code: (a) => a.field('sget', 0, 'Lo/b;', '$$b', 'I').op('xor-int/2addr', 0, 1).op('return', 0) },
    ] },
    { type: 'Lcom/peel/demo/Ui;', access: 0x1, superType: 'Ljava/lang/Object;', methods: [
      { name: 'show', params: [S], ret: 'V', access: 0x9, registers: 1, ins: 1, code: (a) => a.op('return-void') },
    ] },
    { type: 'Lcom/peel/demo/MainActivity;', access: 0x1, superType: 'Landroid/app/Activity;', sourceFile: 'MainActivity.java', methods: [
      { name: '<init>', params: [], ret: 'V', access: 0x10001, registers: 1, ins: 1, outs: 1, code: (a) => a.invoke('invoke-direct', [0], 'Landroid/app/Activity;', '<init>', [], 'V').op('return-void') },
      { name: 'onCreate', params: ['Landroid/os/Bundle;'], ret: 'V', access: 0x4, registers: 6, ins: 2, outs: 3, code: (a) => {
        a.invoke('invoke-super', [4, 5], 'Landroid/app/Activity;', 'onCreate', ['Landroid/os/Bundle;'], 'V');
        call(a, parts[2], 3);
        a.invoke('invoke-static', [3], 'Lcom/peel/demo/Ui;', 'show', [S], 'V');
        call(a, parts[0], 3);
        a.invoke('invoke-static', [3], 'Lcom/peel/demo/Ui;', 'show', [S], 'V');
        call(a, parts[1], 3);
        a.invoke('invoke-static', [3], 'Ljava/lang/Class;', 'forName', [S], 'Ljava/lang/Class;').op('move-result-object', 3);
        call(a, parts[3], 3);
        a.invoke('invoke-static', [3], 'Ljava/lang/System;', 'loadLibrary', [S], 'V');
        a.op('return-void');
      } },
    ] },
    { type: 'Lcom/peel/demo/BootReceiver;', access: 0x1, superType: 'Landroid/content/BroadcastReceiver;', methods: [
      { name: '<init>', params: [], ret: 'V', access: 0x10001, registers: 1, ins: 1, outs: 1, code: (a) => a.invoke('invoke-direct', [0], 'Landroid/content/BroadcastReceiver;', '<init>', [], 'V').op('return-void') },
      { name: 'onReceive', params: ['Landroid/content/Context;', 'Landroid/content/Intent;'], ret: 'V', access: 0x1, registers: 3, ins: 3, code: (a) => a.op('return-void') },
    ] },
  ], { extraStrings: ['~~R8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":24,"version":"8.5.35"}'] });
  const N = true;
  const manifest = buildAxml({ name: 'manifest', attrs: [['versionCode', 3, N], ['versionName', '1.2.0', N], ['package', 'com.peel.demo']], children: [
    { name: 'uses-sdk', attrs: [['minSdkVersion', 24, N], ['targetSdkVersion', 34, N]] },
    { name: 'uses-permission', attrs: [['name', 'android.permission.INTERNET', N]] },
    { name: 'uses-permission', attrs: [['name', 'android.permission.ACCESS_NETWORK_STATE', N]] },
    { name: 'uses-permission', attrs: [['name', 'android.permission.RECEIVE_BOOT_COMPLETED', N]] },
    { name: 'application', attrs: [['label', 'Peel Demo', N], ['debuggable', false, N]], children: [
      { name: 'activity', attrs: [['name', '.MainActivity', N], ['exported', true, N]], children: [
        { name: 'intent-filter', children: [{ name: 'action', attrs: [['name', 'android.intent.action.MAIN', N]] }, { name: 'category', attrs: [['name', 'android.intent.category.LAUNCHER', N]] }] },
      ] },
      { name: 'receiver', attrs: [['name', '.BootReceiver', N], ['exported', false, N]], children: [
        { name: 'intent-filter', children: [{ name: 'action', attrs: [['name', 'android.intent.action.BOOT_COMPLETED', N]] }] },
      ] },
    ] },
  ] });
  // yalnızca ELF başlığı: çalıştırılabilir kod içermez
  const elf = new Uint8Array(64);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  elf.set([3, 0, 0xb7, 0], 16);
  const flags = Uint8Array.from({ length: 96 }, (_, i) => (i * 73 + 41) & 0xff);
  return writeZip([
    ['AndroidManifest.xml', manifest],
    ['classes.dex', dex],
    ['lib/arm64-v8a/libpeelcore.so', elf],
    ['assets/flags.bin', flags],
    ['META-INF/MANIFEST.MF', manifestMf(null)],
  ]);
}

// ── Paramorphism benzeri arşiv hileleri ──
export function paramorphismJar() {
  const main = new ClassBuilder('Main');
  main.field(0xa, 'for', 'I');
  ctor(main);
  main.method(0xa, 'do', '()I', (a) => a.field('getstatic', 'Main', 'for', 'I').iconst(1).op('iadd').op('ireturn'));
  main.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    a.invoke('invokestatic', 'Main', 'do', '()I').field('putstatic', 'Main', 'for', 'I');
    a.invoke('invokestatic', 'if', 'ඞ', '()V');
    println(a, (x) => x.ldc('Paramorphism-style sample'));
    a.op('return');
  });
  const odd = new ClassBuilder('if');
  ctor(odd);
  odd.method(9, 'ඞ', '()V', (a) => a.op('return'));
  const junk = Uint8Array.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0xff, 0xff, 1, 2, 3]);
  return rawZip([
    ['META-INF/MANIFEST.MF', manifestMf('Main')],
    ['Main.class/', new Uint8Array(0)],
    ['Main.class', junk],
    ['Main.class', main.bytes()],
    ['if.class', odd.bytes()],
    ['Junk.class', Uint8Array.from([0xde, 0xad, 0xbe, 0xef])],
  ]);
}

// ── düz sınıf dosyası ──
export function helloClass() {
  const c = new ClassBuilder('demo/Hello').sourceFile('Hello.java');
  c.field(0x19, 'GREETING', STR, 'Hello from Peel');
  ctor(c);
  c.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    println(a, (x) => x.field('getstatic', 'demo/Hello', 'GREETING', STR));
    a.iconst(0).op('istore', 1).label('l').op('iload', 1).iconst(3).jump('if_icmpge', 'e');
    println(a, (x) => x.ldc('tick'));
    a.op('iinc', 1, 1).jump('goto', 'l').label('e').op('return');
  });
  c.method(9, 'sum', '(JJ)J', (a) => a.op('lload', 0).op('lload', 2).op('ladd').op('lreturn'));
  return c.bytes();
}

// ── AAR: iç classes.jar ──
export function libraryAar() {
  const { jar } = proguardJar();
  return writeZip([
    ['AndroidManifest.xml', enc.encode('<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.lib">\n  <uses-sdk android:minSdkVersion="21" />\n  <uses-permission android:name="android.permission.INTERNET" />\n</manifest>\n')],
    ['classes.jar', jar],
    ['R.txt', enc.encode('int string app_name 0x7f010001\n')],
  ]);
}

// ── sınır testleri: sonsuz döngü, sınırsız özyineleme, büyüyen dizge ──
export function limitsJar() {
  const c = new ClassBuilder('x/Loop');
  ctor(c);
  c.method(9, 'spin', `(${STR})${STR}`, (a) => a.label('s').jump('goto', 's'));
  c.method(9, 'deep', `(${STR})${STR}`, (a) => a.op('aload', 0).invoke('invokestatic', 'x/Loop', 'deep', `(${STR})${STR}`).op('areturn'));
  c.method(9, 'grow', `(${STR})${STR}`, (a) => a.op('aload', 0).op('astore', 1).label('g').op('aload', 1).op('aload', 1).invoke('invokevirtual', 'java/lang/String', 'concat', `(${STR})${STR}`).op('astore', 1).jump('goto', 'g'));
  c.method(9, 'main', '([Ljava/lang/String;)V', (a) => {
    for (const m of ['spin', 'deep', 'grow']) println(a, (x) => x.ldc('payload').invoke('invokestatic', 'x/Loop', m, `(${STR})${STR}`));
    a.op('return');
  });
  return writeZip([['x/Loop.class', c.bytes()]]);
}

export const ENCODERS = { allatoriEnc, zkmEnc, stringerEnc };

