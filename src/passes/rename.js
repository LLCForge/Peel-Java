// Yeniden adlandırma. mapping.txt verilmişse özgün adlar geri konur; verilmemişse gizlenmiş görünen adlara okunur,
// belirlenimci adlar üretilir (Class3, ActivityImpl4, method12, decryptString2, strField5). Aynı imzayı geçersiz kılan ya
// da arayüzü uygulayan yöntemler tek grup olarak aynı adı alır. Manifestte, Main-Class'ta, yerel (native) yöntemlerde
// ya da dizge sabitlerinde (yansıma) geçen adlar korunur. Sınıf dosyalarında bütün başvurular (sabit havuzu, imzalar,
// LocalVariableTable, açıklamalar, InnerClasses, EnclosingMethod, BootstrapMethods üzerinden lambda adları) yeniden
// yazılır; DEX'te ad eşlemesi yalnızca ayrıştırma çıktısına uygulanır.
import { utf8, className, nat, ref, thisName, superName, memberName, memberDesc, addUtf8, addNat, reindex, mapDesc, parseMethodDesc, ACC, TAG, simpleName } from '../jvm/classfile.js';
import { Reader, Writer } from '../core/bytes.js';
import { methodsOf } from '../dex/dex.js';

const KEYWORDS = new Set('abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null var record yield'.split(' '));
const VALID = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const KEEP_METHODS = new Set(['<init>', '<clinit>', 'main', 'values', 'valueOf', 'toString', 'hashCode', 'equals', 'finalize', 'clone', 'run', 'call', 'close', 'compareTo', 'iterator', 'get', 'set', 'apply', 'accept', 'test', 'invoke']);

/** Ad okunaksız mı? short: programda kısa adlar yaygınsa (ProGuard) 1-2 harfli adlar da sayılır */
export function looksObfuscated(name, short = false) {
  if (!name || name.startsWith('<')) return false;
  if (!VALID.test(name) || KEYWORDS.has(name)) return true;
  if (/^[Il1]{3,}$/.test(name) || /^[iIl1]{5,}$/.test(name) || /^[Oo0]{3,}$/.test(name)) return true;
  if (/^\$+[a-zA-Z0-9]?$/.test(name) || /^_+$/.test(name)) return true;
  if (/ALLATORI|^[a-zA-Z]{1,2}\$[a-zA-Z]{1,2}$/.test(name)) return true;
  return short && /^[a-z][a-z0-9]?$/.test(name);
}
/** Okunurluk için: ad anlamlı görünüyor mu */
/** Java'da geçersiz ad ya da anahtar sözcük */
export const isInvalidName = (name) => Boolean(name) && !name.startsWith('<') && (!VALID.test(name) || KEYWORDS.has(name));
export const looksReadable = (name) => !looksObfuscated(name, true) && name.length >= 3 && /[aeiouy]/i.test(name);

// ── ortak sınıf modeli (JVM ve DEX) ──
/** { name, super, interfaces, access, fields: [{ name, desc, access }], methods: [{ name, desc, access }], external: false } */
export function modelOf(prog) {
  const map = new Map();
  for (const { cf } of prog.classes) {
    const name = thisName(cf);
    map.set(name, {
      name, super: superName(cf) || null, interfaces: cf.interfaces.map((i) => className(cf, i)), access: cf.access, kind: 'jvm',
      fields: cf.fields.map((f) => ({ name: memberName(cf, f), desc: memberDesc(cf, f), access: f.access })),
      methods: cf.methods.map((m) => ({ name: memberName(cf, m), desc: memberDesc(cf, m), access: m.access })),
    });
  }
  const strip = (t) => (t && t.startsWith('L') ? t.slice(1, -1) : t);
  for (const { dex } of prog.dexes) for (const c of dex.classes) {
    const name = strip(c.type);
    if (map.has(name)) continue;
    map.set(name, {
      name, super: strip(c.superType), interfaces: c.interfaces.map(strip), access: c.access, kind: 'dex',
      fields: [...c.staticFields, ...c.instanceFields].map((f) => ({ name: dex.fields[f.idx].name, desc: dex.fields[f.idx].type, access: f.access })),
      methods: methodsOf(c).map((m) => ({ name: dex.methods[m.idx].name, desc: dex.methods[m.idx].desc, access: m.access })),
    });
  }
  return map;
}

function ancestors(model, name) {
  const out = [];
  const seen = new Set();
  const walk = (n) => {
    const c = model.get(n);
    if (!c) return;
    for (const p of [c.super, ...c.interfaces]) {
      if (!p || seen.has(p)) continue;
      seen.add(p);
      out.push(p);
      walk(p);
    }
  };
  walk(name);
  return out;
}

const TYPE_HINT = { 'Ljava/lang/String;': 'str', I: 'int', Z: 'bool', J: 'long', B: 'byte', C: 'char', S: 'short', F: 'float', D: 'double' };
function fieldHint(desc) {
  let t = desc;
  let arr = '';
  while (t.startsWith('[')) { t = t.slice(1); arr = 'Arr'; }
  const h = TYPE_HINT[t] ?? (t.startsWith('Ljava/util/') ? simpleName(t.slice(1, -1)).replace(/^./, (c) => c.toLowerCase()).replace(/[^A-Za-z0-9]/g, '') : 'obj');
  return `${h}${arr}`;
}

/**
 * @param {object} prog
 * @param {{ mapping?: object|null, decryptors?: object[], strings?: string[], keepNames?: string[] }} o
 */
export function planRename(prog, { mapping = null, decryptors = [], strings = [], keepNames = [] } = {}) {
  const model = modelOf(prog);
  const names = [...model.keys()].sort();
  const short = names.length > 0 && names.filter((n) => /^[a-z][a-z0-9]?$/.test(simpleName(n).replace(/^.*\$/, ''))).length / names.length >= 0.3;
  const reflection = strings.length > 0 && hasReflection(prog);
  const strSet = new Set(strings);
  // korunacak sınıflar: manifest, Main-Class, dizge sabitleri (nokta ya da eğik çizgi biçimi), yerel yöntem sahipleri
  const keepClass = new Set(keepNames.map((n) => n.replaceAll('.', '/')));
  for (const s of strings) if (/^[\w$]+([./][\w$]+)+$/.test(s) && s.length < 300) keepClass.add(s.replaceAll('.', '/'));
  for (const c of model.values()) if (c.methods.some((m) => m.access & ACC.NATIVE)) keepClass.add(c.name);

  // yöntem grupları (birleşim-bul): geçersiz kılma ve arayüz uygulama
  const parent = new Map();
  const find = (k) => { let r = k; while (parent.get(r) !== r) r = parent.get(r); parent.set(k, r); return r; };
  const union = (a, b) => { const ra = find(a); const rb = find(b); if (ra !== rb) parent.set(ra < rb ? rb : ra, ra < rb ? ra : rb); };
  const mkey = (o, n, d) => `${o}.${n}${d}`;
  const virtual = (m) => !(m.access & (ACC.STATIC | ACC.PRIVATE)) && !m.name.startsWith('<');
  for (const c of model.values()) for (const m of c.methods) parent.set(mkey(c.name, m.name, m.desc), mkey(c.name, m.name, m.desc));
  const externalSuper = new Set();
  for (const c of model.values()) {
    const anc = ancestors(model, c.name);
    if ([c.super, ...c.interfaces].some((p) => p && p !== 'java/lang/Object' && !model.has(p)) || anc.some((a) => !model.has(a) && a !== 'java/lang/Object')) externalSuper.add(c.name);
    for (const m of c.methods) {
      if (!virtual(m)) continue;
      for (const a of anc) {
        const ac = model.get(a);
        const am = ac?.methods.find((x) => x.name === m.name && x.desc === m.desc && virtual(x));
        if (am) union(mkey(c.name, m.name, m.desc), mkey(a, m.name, m.desc));
      }
    }
    // üst sınıftan miras alınan uygulama arayüzü karşılıyorsa
    for (const i of anc.filter((a) => model.get(a)?.access & ACC.INTERFACE)) {
      for (const im of model.get(i).methods) {
        if (!virtual(im)) continue;
        for (let s = c.super; s && model.has(s); s = model.get(s).super) {
          const sm = model.get(s).methods.find((x) => x.name === im.name && x.desc === im.desc && virtual(x));
          if (sm) { union(mkey(s, im.name, im.desc), mkey(i, im.name, im.desc)); break; }
        }
      }
    }
  }
  // grup dış bir türün yöntemini geçersiz kılıyor olabilir mi: üyelerinden biri dış üst türlü sınıftaysa ve ad okunurdur
  const groups = new Map();
  for (const c of model.values()) for (const m of c.methods) {
    const k = mkey(c.name, m.name, m.desc);
    const r = find(k);
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r).push({ owner: c.name, m });
  }

  const classMap = new Map();
  const methodMap = new Map();
  const fieldMap = new Map();
  const stats = { classes: 0, methods: 0, fields: 0, kept: 0, source: mapping ? 'mapping' : 'generated' };

  if (mapping) {
    for (const n of names) {
      const orig = mapping.classes.get(n);
      if (orig && orig !== n) { classMap.set(n, orig); stats.classes++; }
    }
    for (const [, members] of groups) {
      const hit = members.map(({ owner, m }) => mapping.methods.get(mkey(owner, m.name, m.desc))).find(Boolean);
      if (!hit) continue;
      for (const { owner, m } of members) if (hit !== m.name) { methodMap.set(mkey(owner, m.name, m.desc), hit); stats.methods++; }
    }
    for (const c of model.values()) for (const f of c.fields) {
      const orig = mapping.fields.get(`${c.name}.${f.name}:${f.desc}`);
      if (orig && orig !== f.name) { fieldMap.set(`${c.name}.${f.name}:${f.desc}`, orig); stats.fields++; }
    }
  } else {
    const used = new Set(names);
    let ci = 0;
    const roleOf = (c) => {
      if (c.access & ACC.ANNOTATION) return 'Annotation';
      if (c.access & ACC.INTERFACE) return 'Interface';
      if (c.access & ACC.ENUM) return 'Enum';
      const sup = c.super && !model.has(c.super) && c.super !== 'java/lang/Object' ? simpleName(c.super).replace(/^.*\$/, '') : null;
      if (sup && /^[A-Z][A-Za-z0-9]+$/.test(sup)) return sup.endsWith('Impl') ? sup : `${sup}Impl`;
      if (c.access & ACC.ABSTRACT) return 'AbstractClass';
      return 'Class';
    };
    // dış sınıflar önce: iç sınıf adı dış sınıfın yeni adını izler
    for (const n of [...names].sort((a, b) => a.split('$').length - b.split('$').length || (a < b ? -1 : 1))) {
      if (keepClass.has(n)) { stats.kept++; continue; }
      const c = model.get(n);
      const slash = n.lastIndexOf('/');
      const pkg = n.slice(0, slash + 1);
      const simple = n.slice(slash + 1);
      const d = simple.lastIndexOf('$');
      const outer = d > 0 ? pkg + simple.slice(0, d) : null;
      const inner = d > 0 ? simple.slice(d + 1) : simple;
      const newOuter = outer ? classMap.get(outer) ?? outer : null;
      let base = inner;
      if (looksObfuscated(inner, short)) {
        let cand;
        do { cand = `${roleOf(c)}${++ci}`; } while (used.has((newOuter ? `${newOuter}$` : pkg) + cand));
        base = cand;
      }
      const next = newOuter ? `${newOuter}$${base}` : pkg + base;
      if (next !== n) { classMap.set(n, next); used.add(next); stats.classes++; }
    }
    const decSet = new Set(decryptors.filter((d) => d.decoded && !d.array).map((d) => mkey(d.owner.replace(/^L|;$/g, ''), d.name, d.desc)));
    let mi = 0;
    let di = 0;
    const taken = new Map(); // sınıf → kullanılan yöntem adları
    for (const c of model.values()) taken.set(c.name, new Set(c.methods.map((m) => m.name)));
    for (const r of [...groups.keys()].sort()) {
      const members = groups.get(r);
      const name = members[0].m.name;
      if (KEEP_METHODS.has(name) || !looksObfuscated(name, short)) continue;
      if (members.some(({ m }) => m.access & ACC.NATIVE)) { stats.kept++; continue; }
      if (reflection && strSet.has(name)) { stats.kept++; continue; }
      // dış üst türlü sınıfta okunur adlı, kısa olmayan ad: kütüphane yöntemini geçersiz kılıyor olabilir
      if (members.some(({ owner }) => externalSuper.has(owner)) && !looksObfuscated(name, false) && name.length > 2) continue;
      const isDec = members.some(({ owner, m }) => decSet.has(mkey(owner, m.name, m.desc)));
      let cand;
      do { cand = isDec ? `decryptString${++di}` : `method${++mi}`; } while (members.some(({ owner }) => taken.get(owner)?.has(cand)));
      for (const { owner, m } of members) { methodMap.set(mkey(owner, m.name, m.desc), cand); taken.get(owner)?.add(cand); stats.methods++; }
    }
    let fi = 0;
    for (const n of names) {
      const c = model.get(n);
      const existing = new Set(c.fields.map((f) => f.name));
      for (const f of c.fields) {
        if (!looksObfuscated(f.name, short)) continue;
        if (reflection && strSet.has(f.name)) { stats.kept++; continue; }
        let cand;
        do { cand = `${fieldHint(f.desc)}Field${++fi}`; } while (existing.has(cand));
        fieldMap.set(`${n}.${f.name}:${f.desc}`, cand);
        stats.fields++;
      }
    }
  }

  const mapClass = (n) => {
    if (!n) return n;
    if (n.startsWith('[')) return mapDesc(n, (x) => classMap.get(x));
    return classMap.get(n) ?? n;
  };
  const resolveMethod = (owner, name, desc) => {
    if (methodMap.size === 0) return name;
    const direct = methodMap.get(mkey(owner, name, desc));
    if (direct) return direct;
    for (const a of ancestors(model, owner)) {
      const hit = methodMap.get(mkey(a, name, desc));
      if (hit) return hit;
    }
    return name;
  };
  const resolveField = (owner, name, desc) => {
    if (fieldMap.size === 0) return name;
    const direct = fieldMap.get(`${owner}.${name}:${desc}`);
    if (direct) return direct;
    for (const a of ancestors(model, owner)) {
      const hit = fieldMap.get(`${a}.${name}:${desc}`);
      if (hit) return hit;
    }
    return name;
  };
  return {
    stats, classMap, methodMap, fieldMap, model,
    cls: mapClass,
    desc: (d) => mapDesc(d, (x) => classMap.get(x)),
    method: resolveMethod,
    field: resolveField,
    /** lambda/invokedynamic: arayüz yöntemi adı (dönüş türü arşivdeki bir arayüzse) */
    samName(name, desc) {
      const { ret } = parseMethodDesc(desc);
      if (!ret.startsWith('L')) return name;
      const iface = ret.slice(1, -1);
      for (const t of [iface, ...ancestors(model, iface)]) {
        const c = model.get(t);
        const m = c?.methods.find((x) => x.name === name && x.access & ACC.ABSTRACT);
        if (m) return methodMap.get(mkey(t, m.name, m.desc)) ?? name;
      }
      return name;
    },
    get changed() { return classMap.size + methodMap.size + fieldMap.size > 0; },
  };
}

const REFLECT = /^(getMethod|getDeclaredMethod|getField|getDeclaredField|forName|loadClass|getMethods|getDeclaredMethods)$/;
function hasReflection(prog) {
  for (const { cf } of prog.classes) for (let i = 1; i < cf.cp.length; i++) {
    const e = cf.cp[i];
    if (e?.tag === 10 && REFLECT.test(nat(cf, e.natIndex).name)) return true;
  }
  for (const { dex } of prog.dexes) if (dex.methods.some((m) => REFLECT.test(m.name) && /^Ljava\/lang\/(Class|ClassLoader);$/.test(m.cls))) return true;
  return false;
}

// ── sınıf dosyalarına uygulama ──
const u2 = (b, i) => (b[i] << 8) | b[i + 1];
const setU2 = (b, i, v) => { b[i] = v >> 8; b[i + 1] = v & 0xff; };

function remapAnnotations(cf, data, plan, kind) {
  const b = data.slice();
  const r = new Reader(b);
  const value = (depth) => {
    if (depth > 32) throw new Error('derin açıklama');
    const tag = String.fromCharCode(r.u1());
    if ('BCDFIJSZs'.includes(tag)) r.u2();
    else if (tag === 'e') { const at = r.pos; setU2(b, at, addUtf8(cf, plan.desc(utf8(cf, r.u2())))); r.u2(); }
    else if (tag === 'c') { const at = r.pos; setU2(b, at, addUtf8(cf, plan.desc(utf8(cf, r.u2())))); }
    else if (tag === '@') annotation(depth + 1);
    else if (tag === '[') { const n = r.u2(); for (let i = 0; i < n; i++) value(depth + 1); }
    else throw new Error(`bilinmeyen açıklama değeri ${tag}`);
  };
  const annotation = (depth) => {
    const at = r.pos;
    setU2(b, at, addUtf8(cf, plan.desc(utf8(cf, r.u2()))));
    const n = r.u2();
    for (let i = 0; i < n; i++) { r.u2(); value(depth); }
  };
  if (kind === 'default') value(0);
  else if (kind === 'param') { const np = r.u1(); for (let p = 0; p < np; p++) { const n = r.u2(); for (let i = 0; i < n; i++) annotation(0); } }
  else { const n = r.u2(); for (let i = 0; i < n; i++) annotation(0); }
  return b;
}

function remapAttrs(cf, attrs, plan, owner) {
  for (const a of attrs) {
    const name = utf8(cf, a.nameIndex);
    try {
      if (name === 'Signature') a.data = Uint8Array.of(...u2be(addUtf8(cf, plan.desc(utf8(cf, u2(a.data, 0))))));
      else if (name === 'RuntimeVisibleAnnotations' || name === 'RuntimeInvisibleAnnotations') a.data = remapAnnotations(cf, a.data, plan, 'plain');
      else if (name === 'RuntimeVisibleParameterAnnotations' || name === 'RuntimeInvisibleParameterAnnotations') a.data = remapAnnotations(cf, a.data, plan, 'param');
      else if (name === 'AnnotationDefault') a.data = remapAnnotations(cf, a.data, plan, 'default');
      else if (name === 'EnclosingMethod') {
        const b = a.data.slice();
        const ni = u2(b, 2);
        if (ni) {
          const { name: mn, desc } = nat(cf, ni);
          const encl = className(cf, u2(b, 0));
          setU2(b, 2, addNat(cf, plan.method(encl, mn, desc), plan.desc(desc)));
        }
        a.data = b;
      } else if (name === 'InnerClasses') {
        const b = a.data.slice();
        const n = u2(b, 0);
        for (let i = 0; i < n; i++) {
          const at = 2 + i * 8;
          const inner = className(cf, u2(b, at));
          const nameIdx = u2(b, at + 4);
          const mapped = plan.cls(inner);
          if (nameIdx && mapped !== inner) setU2(b, at + 4, addUtf8(cf, mapped.slice(mapped.lastIndexOf('$') + 1)));
        }
        a.data = b;
      } else if (name === 'LocalVariableTable' || name === 'LocalVariableTypeTable') {
        const b = a.data.slice();
        const n = u2(b, 0);
        for (let i = 0; i < n; i++) { const at = 2 + i * 10 + 6; setU2(b, at, addUtf8(cf, plan.desc(utf8(cf, u2(b, at))))); }
        a.data = b;
      } else if (name === 'Record') {
        const r = new Reader(a.data);
        const w = new Writer();
        const n = r.u2();
        w.u2(n);
        for (let i = 0; i < n; i++) {
          const cname = utf8(cf, r.u2());
          const cdesc = utf8(cf, r.u2());
          w.u2(addUtf8(cf, plan.field(owner, cname, cdesc))).u2(addUtf8(cf, plan.desc(cdesc)));
          const na = r.u2();
          const sub = [];
          for (let k = 0; k < na; k++) { const ni = r.u2(); const len = r.u4(); sub.push({ nameIndex: ni, data: r.bytes(len).slice() }); }
          remapAttrs(cf, sub, plan, owner);
          w.u2(sub.length);
          for (const s of sub) w.u2(s.nameIndex).u4(s.data.length).bytes(s.data);
        }
        a.data = w.done();
      }
    } catch {
      // bozuk öznitelik olduğu gibi kalır (JVM yalnızca yansımada okur)
    }
    if (a.code) remapAttrs(cf, a.code.attrs, plan, owner);
  }
}
const u2be = (v) => [v >> 8, v & 0xff];

/** Sınıf dosyasını plana göre yerinde yeniden yazar */
export function applyToClass(cf, plan) {
  const owner = thisName(cf);
  const orig = cf.cp.map((e, i) => {
    if (!e) return null;
    if (e.tag === TAG.Class) return { name: utf8(cf, e.index) };
    if (e.tag >= 9 && e.tag <= 11) return ref(cf, i);
    if (e.tag === TAG.InvokeDynamic || e.tag === TAG.Dynamic) return nat(cf, e.natIndex);
    if (e.tag === TAG.MethodType) return { desc: utf8(cf, e.index) };
    return null;
  });
  const len = cf.cp.length;
  for (let i = 1; i < len; i++) {
    const e = cf.cp[i];
    const o = orig[i];
    if (!e || !o) continue;
    if (e.tag === TAG.Class) { const n = plan.cls(o.name); if (n !== o.name) e.index = addUtf8(cf, n); }
    else if (e.tag === TAG.Fieldref) {
      const n = plan.field(o.owner, o.name, o.desc);
      const d = plan.desc(o.desc);
      if (n !== o.name || d !== o.desc) e.natIndex = addNat(cf, n, d);
    } else if (e.tag === TAG.Methodref || e.tag === TAG.InterfaceMethodref) {
      const n = o.owner.startsWith('[') ? o.name : plan.method(o.owner, o.name, o.desc);
      const d = plan.desc(o.desc);
      if (n !== o.name || d !== o.desc) e.natIndex = addNat(cf, n, d);
    } else if (e.tag === TAG.InvokeDynamic || e.tag === TAG.Dynamic) {
      const n = e.tag === TAG.InvokeDynamic ? plan.samName(o.name, o.desc) : o.name;
      const d = plan.desc(o.desc);
      if (n !== o.name || d !== o.desc) e.natIndex = addNat(cf, n, d);
    } else if (e.tag === TAG.MethodType) { const d = plan.desc(o.desc); if (d !== o.desc) e.index = addUtf8(cf, d); }
  }
  for (const f of cf.fields) {
    const n = memberName(cf, f);
    const d = memberDesc(cf, f);
    const nn = plan.field(owner, n, d);
    if (nn !== n) f.nameIndex = addUtf8(cf, nn);
    if (plan.desc(d) !== d) f.descIndex = addUtf8(cf, plan.desc(d));
    remapAttrs(cf, f.attrs, plan, owner);
  }
  for (const m of cf.methods) {
    const n = memberName(cf, m);
    const d = memberDesc(cf, m);
    const nn = n.startsWith('<') ? n : plan.method(owner, n, d);
    if (nn !== n) m.nameIndex = addUtf8(cf, nn);
    if (plan.desc(d) !== d) m.descIndex = addUtf8(cf, plan.desc(d));
    remapAttrs(cf, m.attrs, plan, owner);
  }
  remapAttrs(cf, cf.attrs, plan, owner);
  reindex(cf);
  return plan.cls(owner);
}

