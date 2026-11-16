// Gizleyici parmak izleri: ProGuard/R8, Allatori, Zelix KlassMaster, Stringer, DexGuard, Paramorphism ve genel ad
// gizleme; teknikler (dizge şifreleme, yansıma, dinamik yükleme, yerel kod, invokedynamic gizleme, arşiv hileleri) ve
// bilinen Android paketleyicileri (yalnızca tanınır). Her tespit güven (0-1) ve kanıt listesiyle döner.
import { pick, t } from './text.js';
import { translate } from './en.js';

const NAMES = {
  proguard: t('ProGuard / R8', 'ProGuard / R8'),
  r8: t('R8 (Android)', 'R8 (Android)'),
  allatori: t('Allatori', 'Allatori'),
  zkm: t('Zelix KlassMaster', 'Zelix KlassMaster'),
  stringer: t('Stringer', 'Stringer'),
  dexguard: t('DexGuard', 'DexGuard'),
  paramorphism: t('Paramorphism (arşiv hileleri)', 'Paramorphism (archive tricks)'),
  'generic-names': t('Genel ad gizleme', 'Generic name obfuscation'),
  'string-encryption': t('Dizge şifreleme', 'String encryption'),
  reflection: t('Yansıma (reflection)', 'Reflection'),
  'dynamic-loading': t('Dinamik kod yükleme', 'Dynamic code loading'),
  'native-code': t('Yerel kod (JNI)', 'Native code (JNI)'),
  'indy-obfuscation': t('invokedynamic gizleme', 'invokedynamic obfuscation'),
  'archive-tricks': t('Arşiv hileleri', 'Archive tricks'),
};
// bilinen Android paketleyicileri/koruyucuları: yerel kütüphane adından tanınır, çözülmez
const PACKERS = [
  ['jiagu', /libjiagu/i, '360 Jiagu'], ['bangcle', /libsecexe|libsecmain|libDexHelper/i, 'Bangcle / SecNeo'], ['legu', /libshell[a-z]|libtup\.so|liblegu/i, 'Tencent Legu'],
  ['ijiami', /libexec\.so|libexecmain/i, 'ijiami'], ['alibaba', /libmobisec|libsgmain/i, 'Alibaba'], ['baidu', /libbaiduprotect/i, 'Baidu'],
  ['dexprotector', /libdexprotector|libdp\.so/i, 'DexProtector'], ['apkprotect', /libAPKProtect/i, 'APKProtect'],
];
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
const clamp = (x) => Math.max(0, Math.min(0.99, Math.round(x * 100) / 100));

/**
 * @param {object} prog
 * @param {object} facts collectFacts (geçişlerden önce)
 * @param {{ decryptors?: object[], mapping?: object|null, lang?: string }} o
 */
export function detect(prog, facts, { decryptors = [], mapping = null, lang = 'tr' } = {}) {
  const en = lang === 'en';
  const L = (tr, e) => (en ? e : tr);
  const out = [];
  const add = (id, kind, confidence, evidence, extra = {}) => {
    if (confidence < 0.3 || !evidence.length) return;
    out.push({ id, name: pick(NAMES[id] ?? t(extra.name ?? id), lang), kind, confidence: clamp(confidence), decodable: extra.decodable ?? true, evidence: evidence.slice(0, 6), ...(extra.version ? { version: extra.version } : {}) });
  };
  const n = facts.names;
  const strs = facts.strings;
  const model = facts.model;
  const methods = [...model.values()].flatMap((c) => c.methods.map((m) => ({ ...m, owner: c.name })));
  const fields = [...model.values()].flatMap((c) => c.fields.map((f) => ({ ...f, owner: c.name })));
  const refs = facts.refs;
  const hasRef = (re) => [...refs.keys()].filter((k) => re.test(k));
  const dec = decryptors.filter((d) => d.sites);

  // ProGuard / R8
  {
    const ev = [];
    let c = 0;
    const shortCls = pct(n.classShort, n.classes);
    if (shortCls >= 30) { c += 0.35 + Math.min(0.25, shortCls / 400); ev.push(L(`sınıfların %${shortCls}'i 1-2 harfli adlı`, `${shortCls}% of classes have 1-2 letter names`)); }
    const shortAll = pct(n.short, n.total);
    if (shortAll >= 30) { c += 0.15; ev.push(L(`adların %${shortAll}'i 1-2 harfli`, `${shortAll}% of identifiers are 1-2 letters`)); }
    const pkgs = facts.packages.filter((p) => /^([a-z]{1,2}\.)*[a-z]{1,2}$/.test(p.name));
    if (pkgs.length) { c += 0.1; ev.push(L(`kısa paket adları: ${pkgs.slice(0, 3).map((p) => p.name).join(', ')}`, `short package names: ${pkgs.slice(0, 3).map((p) => p.name).join(', ')}`)); }
    const sf = [...facts.sourceFiles];
    const r8 = sf.filter((s) => /^r8-map-id-/.test(s));
    const marker = strs.find((s) => /^~~R8\{/.test(s));
    if (sf.includes('SourceFile') || r8.length) { c += 0.2; ev.push(L(`SourceFile özniteliği "${r8[0] ?? 'SourceFile'}"`, `SourceFile attribute "${r8[0] ?? 'SourceFile'}"`)); }
    if (mapping) { c += 0.4; ev.push(L(`mapping.txt verildi (${mapping.classes.size} sınıf)`, `mapping.txt supplied (${mapping.classes.size} classes)`)); }
    if (marker) { ev.push(L(`derleyici işareti: ${marker.slice(0, 60)}`, `compiler marker: ${marker.slice(0, 60)}`)); }
    add(marker || r8.length ? 'r8' : 'proguard', 'obfuscator', c + (marker && c > 0 ? 0.15 : 0), ev);
  }
  // Allatori
  {
    const ev = [];
    let c = 0;
    const demo = methods.filter((m) => /ALLATORI/i.test(m.name));
    if (demo.length) { c += 0.7; ev.push(L(`yöntem adı ${demo[0].name} (${demo.length})`, `method name ${demo[0].name} (${demo.length})`)); }
    const mark = strs.find((s) => /allatori/i.test(s));
    if (mark) { c += 0.5; ev.push(L(`dizge: "${mark.slice(0, 50)}"`, `string: "${mark.slice(0, 50)}"`)); }
    if (n.allatori >= 3) { c += 0.25; ev.push(L(`${n.allatori} ad iIl karışımı (Allatori biçimi)`, `${n.allatori} names mixing i/I/l (Allatori style)`)); }
    const xs = dec.filter((d) => d.desc === '(Ljava/lang/String;)Ljava/lang/String;');
    if (xs.length && c > 0) { c += 0.1; ev.push(L(`String(String) çözücü: ${xs[0].name}`, `String(String) decryptor: ${xs[0].name}`)); }
    add('allatori', 'obfuscator', c, ev);
  }
  // Zelix KlassMaster
  {
    const ev = [];
    let c = 0;
    const zArr = fields.filter((f) => /^(z|z\d*|[a-z])$/.test(f.name) && (f.desc === '[Ljava/lang/String;' || f.desc === 'Ljava/lang/String;') && f.access & 0x8);
    const zMeth = methods.filter((m) => (m.desc === '(Ljava/lang/String;)[C' || m.desc === '([C)Ljava/lang/String;') && m.access & 0x8);
    if (zMeth.length >= 2) { c += 0.45; ev.push(L(`ZKM çözücü çifti: ${zMeth.slice(0, 2).map((m) => `${m.name}${m.desc}`).join(', ')}`, `ZKM decryptor pair: ${zMeth.slice(0, 2).map((m) => `${m.name}${m.desc}`).join(', ')}`)); }
    if (zArr.length && (zMeth.length || dec.some((d) => d.array))) { c += 0.25; ev.push(L(`statik dizge tablosu: ${zArr[0].owner}.${zArr[0].name}`, `static string table: ${zArr[0].owner}.${zArr[0].name}`)); }
    const mark = strs.find((s) => /\bZKM\d|KlassMaster/i.test(s));
    if (mark) { c += 0.4; ev.push(L(`dizge: "${mark.slice(0, 50)}"`, `string: "${mark.slice(0, 50)}"`)); }
    add('zkm', 'obfuscator', c, ev);
  }
  // Stringer
  {
    const ev = [];
    let c = 0;
    const obj = methods.filter((m) => m.desc === '(Ljava/lang/Object;)Ljava/lang/String;' && m.access & 0x8);
    if (obj.length) { c += 0.35; ev.push(L(`Object→String statik çözücü: ${obj[0].owner}.${obj[0].name}`, `Object→String static decryptor: ${obj[0].owner}.${obj[0].name}`)); }
    const st = hasRef(/\.getStackTrace$/);
    if (st.length && obj.length) { c += 0.2; ev.push(L('çağıran yığın izinden anahtar türetme (getStackTrace)', 'key derived from the caller stack trace (getStackTrace)')); }
    if (facts.customIndy && obj.length) { c += 0.25; ev.push(L(`${facts.customIndy} özel invokedynamic önyükleyicisi`, `${facts.customIndy} custom invokedynamic bootstrap(s)`)); }
    const mark = strs.find((s) => /stringer/i.test(s) && s.length < 80);
    if (mark) { c += 0.35; ev.push(L(`dizge: "${mark}"`, `string: "${mark}"`)); }
    add('stringer', 'obfuscator', c, ev);
  }
  // DexGuard
  if (prog.dexes.length) {
    const ev = [];
    let c = 0;
    const oCls = [...model.keys()].filter((k) => /^o\/[^/]+$/.test(k));
    if (oCls.length >= 2) { c += 0.3; ev.push(L(`"o" paketinde ${oCls.length} sınıf`, `${oCls.length} classes in package "o"`)); }
    const dollar = [...methods.filter((m) => /^\$+[a-zA-Z]?$/.test(m.name)), ...fields.filter((f) => /^\$+[a-zA-Z]?$/.test(f.name))];
    if (dollar.length) { c += 0.25; ev.push(L(`$ biçimli üye adları: ${[...new Set(dollar.map((x) => x.name))].slice(0, 4).join(', ')}`, `$-style member names: ${[...new Set(dollar.map((x) => x.name))].slice(0, 4).join(', ')}`)); }
    const ints = dec.filter((d) => /^\([ISB]{2,3}\)Ljava\/lang\/String;$/.test(d.desc));
    if (ints.length) { c += 0.25; ev.push(L(`sayısal argümanlı çözücü: ${ints[0].name}${ints[0].desc}`, `integer-argument decryptor: ${ints[0].name}${ints[0].desc}`)); }
    const lib = prog.nativeLibs.find((l) => /dexguard/i.test(l.name));
    if (lib) { c += 0.5; ev.push(L(`yerel kütüphane: ${lib.name}`, `native library: ${lib.name}`)); }
    const mark = strs.find((s) => /dexguard|guardsquare/i.test(s) && s.length < 100);
    if (mark) { c += 0.4; ev.push(L(`dizge: "${mark}"`, `string: "${mark}"`)); }
    add('dexguard', 'obfuscator', c, ev);
  }
  // Paramorphism / arşiv hileleri
  {
    const tr = prog.tricks;
    const ev = [];
    let kinds = 0;
    if (tr.dupEntries.length) { kinds++; ev.push(L(`${tr.dupEntries.length} yinelenen kayıt adı (${tr.dupEntries[0]})`, `${tr.dupEntries.length} duplicate entry name(s) (${tr.dupEntries[0]})`)); }
    if (tr.classDirs.length) { kinds++; ev.push(L(`".class/" dizin kaydı: ${tr.classDirs[0]}`, `".class/" directory entry: ${tr.classDirs[0]}`)); }
    if (tr.badClasses.length) { kinds++; ev.push(L(`${tr.badClasses.length} ayrıştırılamayan sınıf kaydı`, `${tr.badClasses.length} unparsable class entr(ies)`)); }
    if (tr.nameMismatch.length) { kinds++; ev.push(L(`kayıt adı/sınıf adı uyuşmazlığı: ${tr.nameMismatch[0]}`, `entry/class name mismatch: ${tr.nameMismatch[0]}`)); }
    const mark = strs.find((s) => /paramorphism/i.test(s) && s.length < 100);
    if (mark) ev.push(L(`dizge: "${mark}"`, `string: "${mark}"`));
    if (kinds) add('archive-tricks', 'technique', 0.6 + kinds * 0.1, ev);
    if (kinds >= 2 || mark) add('paramorphism', 'obfuscator', (mark ? 0.5 : 0) + kinds * 0.2, ev);
  }
  // genel ad gizleme
  if (n.invalid >= 3) {
    const sample = [...methods.map((m) => m.name), ...fields.map((f) => f.name)].filter((x) => /[^\w$]|^(if|do|for|int|new|try)$/.test(x)).slice(0, 3);
    add('generic-names', 'technique', 0.5 + Math.min(0.4, n.invalid / 50), [L(`${n.invalid} geçersiz ya da anahtar sözcük ad`, `${n.invalid} invalid or keyword identifiers`), ...(sample.length ? [L(`örnek: ${sample.map((s) => JSON.stringify(s)).join(', ')}`, `e.g. ${sample.map((s) => JSON.stringify(s)).join(', ')}`)] : [])]);
  }
  // teknikler
  if (dec.length) {
    const okd = dec.filter((d) => d.decoded);
    add('string-encryption', 'technique', 0.6 + Math.min(0.35, dec.reduce((s, d) => s + d.sites, 0) / 40), dec.slice(0, 4).map((d) => `${d.owner.replace(/^L|;$/g, '')}.${d.name}${d.array ? '[]' : d.desc}: ${d.decoded}/${d.sites}${d.failed ? L(` (çözülemedi: ${d.reasons[0] ?? '?'})`, ` (not decoded: ${translate(d.reasons[0] ?? '?', 'en')})`) : ''}`), { decodable: okd.length > 0 });
  }
  const refl = facts.reflection;
  const by = (k) => refl.filter((r) => r.kind === k);
  if (by('reflection').length) add('reflection', 'technique', 0.7, by('reflection').slice(0, 4).map((r) => `${r.api} (${r.where[0] ?? ''})`));
  if (by('dynamic-loading').length) add('dynamic-loading', 'technique', 0.85, by('dynamic-loading').slice(0, 4).map((r) => `${r.api} (${r.where[0] ?? ''})`));
  const nativeEv = [...by('native').map((r) => r.api), ...prog.nativeLibs.slice(0, 4).map((l) => l.path)];
  const natives = methods.filter((m) => m.access & 0x100);
  if (natives.length) nativeEv.push(L(`${natives.length} native yöntem`, `${natives.length} native method(s)`));
  if (nativeEv.length) add('native-code', 'technique', 0.6 + (prog.nativeLibs.length ? 0.2 : 0), nativeEv);
  if (facts.customIndy) add('indy-obfuscation', 'technique', 0.55, [L(`${facts.customIndy} özel önyükleme yöntemi (LambdaMetafactory/StringConcatFactory dışı)`, `${facts.customIndy} custom bootstrap method(s) (not LambdaMetafactory/StringConcatFactory)`)]);
  for (const [id, re, name] of PACKERS) {
    const libs = prog.nativeLibs.filter((l) => re.test(l.name));
    if (libs.length) out.push({ id, name, kind: 'packer', confidence: 0.9, decodable: false, evidence: libs.slice(0, 3).map((l) => l.path) });
  }
  // başka bir gizleyicinin özgül kanıtı varsa kısa adlar ondan da gelebilir: ProGuard güveni düşürülür
  const specific = out.some((d) => ['allatori', 'zkm', 'stringer', 'dexguard', 'paramorphism'].includes(d.id) && d.confidence >= 0.6);
  for (const d of out) if (specific && (d.id === 'proguard' || d.id === 'r8') && !mapping) d.confidence = clamp(d.confidence - 0.25);
  return out.sort((a, b) => (a.kind === b.kind ? b.confidence - a.confidence : ['packer', 'obfuscator', 'technique'].indexOf(a.kind) - ['packer', 'obfuscator', 'technique'].indexOf(b.kind)));
}
