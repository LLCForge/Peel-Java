// Temizlenmiş çıktı: sınıf dosyaları yeniden yazılır, JAR/AAR yeniden paketlenir. Kayıt yolları yeni sınıf adlarını
// izler; Main-Class ve META-INF/services eşlenir; imza dosyaları (.SF/.RSA/.DSA/.EC) değişen içerikle geçersiz kalacağı
// için çıkarılır; arşiv hileleri (aynı adlı kayıtlar, ".class/" dizinleri, ayrıştırılamayan sınıflar) temizlenir.
// Her yazılan sınıf yeniden ayrıştırılır ve tüm yöntem gövdeleri çözülür (yapısal doğrulama).
import { writeClass, parseClass, thisName } from '../jvm/classfile.js';
import { decode } from '../jvm/opcodes.js';
import { writeZip } from './zip.js';

const SIG = /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i;

function verifyClass(bytes) {
  const cf = parseClass(bytes);
  for (const m of cf.methods) if (m.code) decode(m.code.code);
  return thisName(cf);
}

/**
 * @param {object} prog
 * @param {object|null} plan yeniden adlandırma planı (yoksa adlar değişmez)
 * @returns {{ bytes: Uint8Array, ext: string, verified: boolean, errors: string[], removed: string[] }}
 */
export function rewrite(prog, plan = null) {
  const errors = [];
  const removed = [];
  const cls = (n) => (plan ? plan.cls(n) : n);
  if (prog.kind === 'class') {
    const bytes = writeClass(prog.classes[0].cf);
    try { verifyClass(bytes); } catch (e) { errors.push(e.message); }
    return { bytes, ext: '.class', verified: !errors.length, errors, removed };
  }
  const chosen = new Map(prog.classes.map((c) => [c.entry, c]));
  const dotted = (n) => n.replaceAll('/', '.');
  const mapDotted = (s) => dotted(cls(s.replaceAll('.', '/')));

  const build = (container) => {
    const files = [];
    const seen = new Set();
    for (const e of container.entries) {
      const full = container.prefix + e.name;
      if (e.dir) {
        if (/\.class\/$/i.test(e.name)) { removed.push(full); continue; }
        if (!seen.has(e.name)) { seen.add(e.name); files.push([e.name, new Uint8Array(0)]); }
        continue;
      }
      if (/\.class$/i.test(e.name)) {
        const c = chosen.get(e);
        if (!c) { removed.push(full); continue; }
        let bytes;
        try {
          bytes = writeClass(c.cf);
          const name = verifyClass(bytes);
          if (name !== cls(c.name)) errors.push(`${full}: sınıf adı ${name}`);
        } catch (err) {
          errors.push(`${full}: ${err.message}`);
          continue;
        }
        const path = `${cls(c.name)}.class`;
        if (seen.has(path)) { removed.push(full); continue; }
        seen.add(path);
        files.push([path, bytes]);
        continue;
      }
      if (!e.data) { removed.push(full); continue; }
      if (SIG.test(e.name)) { removed.push(full); continue; }
      if (seen.has(e.name)) { removed.push(full); continue; }
      let name = e.name;
      let data = e.data;
      if (e.nested) {
        const inner = prog.containers.find((x) => x.prefix === `${full}!/`);
        if (inner) data = writeZip(build(inner));
      } else if (plan && /^META-INF\/MANIFEST\.MF$/i.test(e.name)) {
        const t = new TextDecoder().decode(data).replace(/^(Main-Class:\s*)(\S+)/im, (m, k, v) => k + mapDotted(v));
        data = new TextEncoder().encode(t);
      } else if (plan && /^META-INF\/services\/[^/]+$/.test(e.name)) {
        name = `META-INF/services/${mapDotted(e.name.slice(18))}`;
        const t = new TextDecoder().decode(data).split(/\r?\n/).map((l) => (/^\s*[\w$.]+\s*$/.test(l) ? mapDotted(l.trim()) : l)).join('\n');
        data = new TextEncoder().encode(t);
      }
      seen.add(name);
      files.push([name, data]);
    }
    return files;
  };
  const bytes = writeZip(build(prog.containers[0]));
  return { bytes, ext: prog.kind === 'aar' ? '.aar' : '.jar', verified: !errors.length, errors, removed };
}
