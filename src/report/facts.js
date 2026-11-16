// Programdan rapor için olgular: başvurulan API'ler (sahip.ad), dizge sabitleri, adların okunurluğu, paketler, kripto
// sabitleri, yansıma ve dinamik yükleme çağrıları, yerel kod. Sınıf dosyası ve DEX için aynı biçim üretilir.
import { decode as decodeJvm, OP } from '../jvm/opcodes.js';
import { utf8, ref, constant, thisName, memberName, findAttr, TAG } from '../jvm/classfile.js';
import { decode as decodeDex, payloadAt } from '../dex/opcodes.js';
import { methodsOf, internalOf } from '../dex/dex.js';
import { modelOf, isInvalidName, looksReadable } from '../passes/rename.js';
import { Reader } from '../core/bytes.js';

const MAX_STRINGS = 200_000;
const AES_SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5];
const AES_INV = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38];
const INT_CONSTANTS = new Map([
  [0x67452301, ['md5-sha1', 'MD5/SHA-1 başlangıç değeri (0x67452301)']], [0xefcdab89 | 0, ['md5-sha1', 'MD5/SHA-1 başlangıç değeri (0xefcdab89)']],
  [0xc3d2e1f0 | 0, ['sha1', 'SHA-1 başlangıç değeri (0xc3d2e1f0)']], [0x428a2f98, ['sha256', 'SHA-256 tur sabiti (0x428a2f98)']],
  [0x6a09e667, ['sha256', 'SHA-256 başlangıç değeri (0x6a09e667)']], [0xedb88320 | 0, ['crc32', 'CRC-32 polinomu (0xedb88320)']],
  [0x9e3779b9 | 0, ['tea', 'TEA/XTEA delta (0x9e3779b9)']], [0x61c88647, ['tea', 'TEA/XTEA delta (-0x61c88647)']],
  [0xd76aa478 | 0, ['md5', 'MD5 tur sabiti (0xd76aa478)']], [0x01000193, ['fnv', 'FNV-1 asal sayısı (0x01000193)']], [0x811c9dc5 | 0, ['fnv', 'FNV-1 başlangıç (0x811c9dc5)']],
]);
const CRYPTO_NAMES = { aes: 'AES', 'md5-sha1': 'MD5 / SHA-1', sha1: 'SHA-1', sha256: 'SHA-256', crc32: 'CRC-32', tea: 'TEA / XTEA', md5: 'MD5', fnv: 'FNV hash', rc4: 'RC4', cipher: 'javax.crypto', algo: 'Algoritma adları' };
const ALGO = /^(AES|DES|DESede|RSA|Blowfish|RC4|ARCFOUR|ChaCha20|HmacSHA\d+|HmacMD5|MD5|SHA-?1|SHA-?256|SHA-?512|PBKDF2WithHmacSHA\d+)(\/[\w-]+\/[\w-]+)?$/i;

const REFLECT = [
  ['dynamic-loading', /^(dalvik\/system\/(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DelegateLastClassLoader)\.<init>|java\/net\/URLClassLoader\.<init>|java\/lang\/ClassLoader\.(defineClass|loadClass)|dalvik\/system\/DexFile\.(loadDex|<init>))$/],
  ['reflection', /^(java\/lang\/Class\.(forName|getMethod|getDeclaredMethod|getField|getDeclaredField|newInstance|getDeclaredConstructor)|java\/lang\/reflect\/(Method\.invoke|Field\.(get|set)|Constructor\.newInstance))$/],
  ['native', /^java\/lang\/(System|Runtime)\.(loadLibrary|load)$/],
  ['exec', /^(java\/lang\/Runtime\.exec|java\/lang\/ProcessBuilder\.(<init>|start))$/],
];

function addRef(refs, key, where) {
  let s = refs.get(key);
  if (!s) { s = new Set(); refs.set(key, s); }
  if (s.size < 5) s.add(where);
}

/**
 * @param {object} prog
 * @param {{ extraStrings?: string[] }} [o]
 */
export function collectFacts(prog, { extraStrings = [] } = {}) {
  const refs = new Map(); // "sahip.ad" → nerelerde
  const strings = new Set();
  const crypto = new Map();
  const sourceFiles = new Set();
  let customIndy = 0;
  const addCrypto = (id, ev) => { if (!crypto.has(id)) crypto.set(id, new Set()); if (crypto.get(id).size < 4) crypto.get(id).add(ev); };
  const scanBytes = (vals, where) => {
    for (const [sig, id, ev] of [[AES_SBOX, 'aes', 'AES S-kutusu'], [AES_INV, 'aes', 'AES ters S-kutusu']]) {
      for (let i = 0; i + sig.length <= vals.length; i++) {
        if (sig.every((b, k) => (vals[i + k] & 0xff) === b)) { addCrypto(id, `${ev} (${where})`); break; }
      }
    }
  };
  for (const { cf } of prog.classes) {
    try { scanClass(cf); } catch { /* bozuk sınıf: olgular atlanır */ }
  }
  function scanClass(cf) {
    const owner = thisName(cf);
    const sf = findAttr(cf, cf.attrs, 'SourceFile');
    if (sf && sf.data.length >= 2) sourceFiles.add(utf8(cf, new Reader(sf.data).u2()));
    for (let i = 1; i < cf.cp.length; i++) {
      const e = cf.cp[i];
      if (!e) continue;
      if (e.tag === TAG.String && strings.size < MAX_STRINGS) strings.add(utf8(cf, e.index));
      if (e.tag === TAG.Integer && INT_CONSTANTS.has(e.value)) addCrypto(...INT_CONSTANTS.get(e.value).map((x, k) => (k ? `${x} · ${owner}` : x)));
    }
    const bsm = findAttr(cf, cf.attrs, 'BootstrapMethods');
    if (bsm) {
      try {
        const r = new Reader(bsm.data);
        const n = r.u2();
        for (let k = 0; k < n; k++) {
          const h = constant(cf, r.u2())?.value;
          const argc = r.u2();
          r.pos += argc * 2;
          if (h && !/^java\/lang\/(invoke\/(LambdaMetafactory|StringConcatFactory|ObjectMethods)|runtime\/(SwitchBootstraps|ObjectMethods))$/.test(h.owner)) customIndy++;
        }
      } catch { /* bozuk tablo */ }
    }
    for (const m of cf.methods) {
      if (!m.code) continue;
      const where = `${owner}.${memberName(cf, m)}`;
      let insns;
      try { insns = decodeJvm(m.code.code); } catch { continue; }
      // dizi ilk değerleri: her *astore'dan önce yüklenen son sabit (javac dizinleri iconst/bipush ile karışık yükler)
      const pushes = [];
      let last = null;
      for (const ins of insns) {
        if (ins.op === OP.bipush || ins.op === OP.sipush) last = ins.value;
        else if (ins.op >= OP.iconst_m1 && ins.op <= OP.iconst_5) last = ins.op - OP.iconst_0;
        else if (ins.op === OP.ldc || ins.op === OP.ldc_w) { const k = constant(cf, ins.index); last = k?.type === 'I' ? k.value : null; }
        else if ((ins.op === OP.bastore || ins.op === OP.iastore || ins.op === OP.castore || ins.op === OP.sastore) && last !== null) pushes.push(last);
        if (ins.op >= OP.invokevirtual && ins.op <= OP.invokeinterface) { const r = ref(cf, ins.index); if (r) addRef(refs, `${r.owner}.${r.name}`, where); }
        if (ins.op === OP.getstatic) { const r = ref(cf, ins.index); if (r) addRef(refs, `${r.owner}.${r.name}`, where); }
      }
      if (pushes.length >= 8) scanBytes(pushes, where);
    }
  }
  for (const { dex } of prog.dexes) {
    try { scanDex(dex); } catch { /* bozuk DEX: olgular atlanır */ }
  }
  function scanDex(dex) {
    // yalnızca kodun yüklediği dizgeler (havuzda ad ve tanımlayıcılar da vardır) ve derleyici işaretleri
    for (const s of dex.strings) if (s.startsWith('~~')) strings.add(s);
    for (const c of dex.classes) {
      if (c.sourceFile) sourceFiles.add(c.sourceFile);
      for (const v of c.staticValues) if (v.type === 'String' && v.value) strings.add(v.value);
      for (const m of methodsOf(c)) {
        if (!m.code) continue;
        const where = `${internalOf(c.type)}.${dex.methods[m.idx]?.name}`;
        let insns;
        try { insns = decodeDex(m.code.insns); } catch { continue; }
        for (const ins of insns) {
          if (ins.kind === 'string' && strings.size < MAX_STRINGS) strings.add(dex.strings[ins.index]);
          if (ins.kind === 'method' && ins.name.startsWith('invoke')) { const mm = dex.methods[ins.index]; if (mm) addRef(refs, `${internalOf(mm.cls)}.${mm.name}`, where); }
          if (ins.kind === 'field' && ins.name.startsWith('sget')) { const f = dex.fields[ins.index]; if (f) addRef(refs, `${internalOf(f.cls)}.${f.name}`, where); }
          if (ins.name === 'const' || ins.name === 'const/high16') { const hit = INT_CONSTANTS.get(ins.lit); if (hit) addCrypto(hit[0], `${hit[1]} · ${internalOf(c.type)}`); }
          if (ins.name === 'fill-array-data') { try { const p = payloadAt(m.code.insns, ins.target); if (p.width === 1 && p.size >= 8) scanBytes(p.bytes, where); if (p.width === 4) for (let k = 0; k < Math.min(p.size, 64); k++) { const v = new DataView(p.bytes.buffer, p.bytes.byteOffset + k * 4, 4).getInt32(0, true); const hit = INT_CONSTANTS.get(v); if (hit) addCrypto(hit[0], `${hit[1]} · ${where}`); } } catch { /* bozuk */ } }
        }
      }
    }
  }
  for (const s of extraStrings) strings.add(s);
  for (const s of strings) if (ALGO.test(s)) addCrypto('algo', s);
  if ([...refs.keys()].some((k) => /^javax\/crypto\/(Cipher|Mac|spec\/SecretKeySpec)\./.test(k))) addCrypto('cipher', [...refs.keys()].filter((k) => k.startsWith('javax/crypto/')).slice(0, 4).join(', '));

  const reflection = [];
  for (const [kind, re] of REFLECT) {
    for (const [k, where] of refs) if (re.test(k)) reflection.push({ kind, api: k.replaceAll('/', '.'), where: [...where].map((w) => w.replaceAll('/', '.')) });
  }
  const model = modelOf(prog);
  return {
    refs, strings: [...strings], sourceFiles, customIndy, model,
    crypto: [...crypto].map(([id, ev]) => ({ id, name: CRYPTO_NAMES[id] ?? id, evidence: [...ev] })),
    reflection,
    packages: packagesOf(model),
    names: namesOf(model),
  };
}

function packagesOf(model) {
  const count = new Map();
  for (const n of model.keys()) {
    const i = n.lastIndexOf('/');
    const p = i < 0 ? '(default)' : n.slice(0, i).replaceAll('/', '.');
    count.set(p, (count.get(p) ?? 0) + 1);
  }
  return [...count].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).map(([name, classes]) => ({ name, classes }));
}

/** Ad istatistikleri: okunur oran, kısa, geçersiz, Allatori biçimli ad sayıları */
export function namesOf(model) {
  let total = 0;
  let readable = 0;
  let short = 0;
  let invalid = 0;
  let allatori = 0;
  let classShort = 0;
  const all = [];
  for (const c of model.values()) {
    const simple = c.name.slice(c.name.lastIndexOf('/') + 1).replace(/^.*\$/, '');
    all.push(simple);
    if (/^[a-z][a-z0-9]?$/.test(simple) && !isInvalidName(simple)) classShort++;
    for (const m of c.methods) if (!m.name.startsWith('<')) all.push(m.name);
    for (const f of c.fields) all.push(f.name);
  }
  for (const n of all) {
    total++;
    if (looksReadable(n)) readable++;
    if (/^[a-z][a-z0-9]?$/.test(n)) short++;
    if (isInvalidName(n)) invalid++;
    if (/^[iIl1]{4,}$/.test(n) && /[iI]/.test(n) && /[lI]/.test(n)) allatori++;
  }
  return { total, readable, short, invalid, allatori, classes: model.size, classShort, ratio: total ? readable / total : 1 };
}

