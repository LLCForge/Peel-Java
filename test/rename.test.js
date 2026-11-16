// Yeniden adlandırma testleri: mapping.txt ayrıştırma ve uygulama, üretilmiş adların belirlenimciliği, geçersiz kılma
// grupları, korunan adlar, temiz JAR'ın tutarlılığı (her başvuru arşivdeki bir üyeye çözülür).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseMapping } from '../src/core/mapping.js';
import { loadProgram } from '../src/core/program.js';
import { planRename, applyToClass, looksObfuscated } from '../src/passes/rename.js';
import { rewrite } from '../src/core/rewrite.js';
import { deobfuscate } from '../src/index.js';
import { thisName, superName, memberName, memberDesc, ref, TAG } from '../src/jvm/classfile.js';
import { listZip, readEntry } from '../src/core/zip.js';

const fx = (n) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const mappingText = readFileSync(new URL('./fixtures/proguard-mapped.mapping.txt', import.meta.url), 'utf8');

// mapping.txt
const map = parseMapping(mappingText);
assert.equal(map.classes.get('a/a'), 'com/example/app/net/UpdateClient');
assert.equal(map.methods.get('a/a.a(Ljava/lang/String;)Ljava/lang/String;'), 'fetch');
assert.equal(map.fields.get('a/a.a:Ljava/lang/String;'), 'endpoint');
assert.equal(map.methods.get('a/c.a()V'), 'execute');
assert.equal(map.errors, 0);
const inline = parseMapping('x.Y -> a:\n    1:2:void z.Other.inlined():5:6 -> b\n    int[] arr -> c\n    garbage line\n');
assert.equal(inline.methods.size, 0, 'satır içi gömülü başka sınıfın yöntemi atlanır');
assert.equal(inline.fields.get('a.c:[I'), 'arr');
assert.equal(inline.errors, 1);

// bir arşivdeki her Fieldref/Methodref, arşivdeki bir sınıfa aitse orada (ya da üst türlerinde) tanımlı olmalı
function consistent(bytes) {
  const prog = loadProgram(bytes, 'x.jar');
  const by = prog.classMap;
  const has = (owner, name, desc, field) => {
    for (let c = owner, k = 0; c && by.has(c) && k < 32; k++) {
      const cf = by.get(c);
      const list = field ? cf.fields : cf.methods;
      if (list.some((m) => memberName(cf, m) === name && memberDesc(cf, m) === desc)) return true;
      for (const i of cf.interfaces) if (has(cf.cp[cf.cp[i].index] ? cf.cp[cf.cp[i].index].value : '', name, desc, field)) return true;
      c = superName(cf);
    }
    return !by.has(owner);
  };
  let refs = 0;
  for (const { cf } of prog.classes) {
    for (let i = 1; i < cf.cp.length; i++) {
      const e = cf.cp[i];
      if (!e || e.tag < TAG.Fieldref || e.tag > TAG.InterfaceMethodref) continue;
      const r = ref(cf, i);
      if (!by.has(r.owner)) continue;
      refs++;
      assert.ok(has(r.owner, r.name, r.desc, e.tag === TAG.Fieldref), `${thisName(cf)}: çözülmeyen başvuru ${r.owner}.${r.name}${r.desc}`);
    }
  }
  return { prog, refs };
}

const mapped = await deobfuscate(fx('proguard.jar'), { name: 'proguard.jar', mapping: mappingText, timeline: false });
const m1 = consistent(mapped.bytes);
assert.deepEqual([...m1.prog.classMap.keys()].sort(), ['com/example/app/Main', 'com/example/app/net/PingTask', 'com/example/app/net/Task', 'com/example/app/net/UpdateClient']);
assert.ok(m1.refs >= 5);
const manifest = new TextDecoder().decode(readEntry(mapped.bytes, listZip(mapped.bytes).entries.find((e) => e.name === 'META-INF/MANIFEST.MF')).data);
assert.match(manifest, /Main-Class: com\.example\.app\.Main/);

// üretilmiş adlar: belirlenimci, arayüz ve uygulama aynı adı alır, Main korunur (Main-Class)
const g1 = await deobfuscate(fx('proguard.jar'), { name: 'proguard.jar', timeline: false });
const g2 = await deobfuscate(fx('proguard.jar'), { name: 'proguard.jar', timeline: false });
assert.deepEqual(g1.bytes, g2.bytes, 'aynı girdi aynı çıktıyı vermeli');
const gen = consistent(g1.bytes).prog;
assert.ok(gen.classMap.has('com/example/app/Main'));
const iface = [...gen.classMap.values()].find((cf) => cf.access & 0x200);
const impl = [...gen.classMap.values()].find((cf) => cf.interfaces.length);
const ifName = memberName(iface, iface.methods[0]);
assert.match(ifName, /^method\d+$/);
assert.ok(impl.methods.some((m) => memberName(impl, m) === ifName), 'uygulama arayüzle aynı adı almalı');

// Allatori: çözücü decryptString1, okunur adlar değişmez
const al = await deobfuscate(fx('allatori.jar'), { name: 'allatori.jar', timeline: false });
assert.match(al.code, /decryptString1/);
assert.match(al.code, /class com\.peel\.demo\.Launcher/);
consistent(al.bytes);

// Paramorphism: anahtar sözcük ve geçersiz adlar okunur olur, hileler temizlenir
const pm = await deobfuscate(fx('paramorphism.jar'), { name: 'paramorphism.jar', timeline: false });
const pmProg = consistent(pm.bytes).prog;
for (const { cf } of pmProg.classes) {
  assert.ok(!looksObfuscated(thisName(cf).split('/').pop()), `sınıf adı: ${thisName(cf)}`);
  for (const m of cf.methods) assert.ok(!looksObfuscated(memberName(cf, m)), `yöntem adı: ${memberName(cf, m)}`);
}
assert.equal(listZip(pm.bytes).entries.filter((e) => e.name.endsWith('.class/')).length, 0);

// manifest/yansıma dizgesinde geçen sınıf korunur
const prog = loadProgram(fx('proguard.jar'), 'p.jar');
const kept = planRename(prog, { strings: ['a.a'] });
assert.equal(kept.cls('a/a'), 'a/a', 'dizgede geçen sınıf adı korunmalı');
assert.notEqual(kept.cls('a/c'), 'a/c');
const plan = planRename(prog, { keepNames: ['a.c'] });
assert.equal(plan.cls('a/c'), 'a/c');
// yeniden yazılan sınıf adı, kayıt yolunu izler
for (const c of prog.classes) c.name = applyToClass(c.cf, plan);
prog.classMap = new Map(prog.classes.map((c) => [c.name, c.cf]));
const out = rewrite(prog, plan);
assert.ok(out.verified, out.errors.join('; '));
assert.ok(listZip(out.bytes).entries.some((e) => e.name === `${plan.cls('a/a')}.class`));

console.log(`rename: mapping ${map.classes.size} sınıf / ${map.methods.size} yöntem / ${map.fields.size} alan, ${m1.refs} başvuru tutarlı, üretilmiş adlar belirlenimci`);
