// Girdi yükleyici: tek sınıf dosyası, DEX, JAR, APK, AAR (iç classes.jar ve libs/*.jar dahil). Sonuç tek bir "program"
// modelidir; geçişler ve rapor bununla çalışır. Ayrıştırılamayan parçalar atlanır ve notlara yazılır, hiçbiri tüm
// işlemi düşürmez. Arşiv hileleri (aynı adlı kayıtlar, ".class/" dizinleri, ad/sınıf uyuşmazlığı) ayrıca toplanır.
import { listZip, readEntry, isZip } from './zip.js';
import { parseClass, isClassFile, thisName } from '../jvm/classfile.js';
import { parseDex, isDex } from '../dex/dex.js';
import { parseAxml, manifestSummary } from '../dex/axml.js';
import { ParseError } from './bytes.js';
import { LIMITS } from './limits.js';

const text = new TextDecoder('utf-8');

/** Arşivi okur; kayıtlar { name, data?, error?, size, dup, dir } */
function openZip(bytes, prefix, prog, depth) {
  const { entries } = listZip(bytes);
  const budget = prog.budget;
  const out = { prefix, entries: [], order: [] };
  for (const e of entries) {
    const rec = { name: e.name, size: e.size, csize: e.csize, dup: e.dup, dir: e.dir };
    if (!e.dir) {
      const r = readEntry(bytes, e, budget);
      if (r.error) rec.error = r.error; else rec.data = r.data;
    }
    out.entries.push(rec);
  }
  prog.containers.push(out);
  const dupNames = [...new Set(entries.filter((e) => e.dup).map((e) => e.name))];
  if (dupNames.length) prog.tricks.dupEntries.push(...dupNames.map((n) => prefix + n));
  for (const e of entries) if (e.dir && /\.class\/$/i.test(e.name)) prog.tricks.classDirs.push(prefix + e.name);
  for (const e of out.entries) if (e.error && e.error !== 'dizin') prog.notes.push({ level: 'warn', msg: `${prefix}${e.name}: ${e.error}` });

  for (const e of out.entries) {
    if (!e.data) continue;
    const path = prefix + e.name;
    if (/\.class$/i.test(e.name)) {
      if (prog.classes.length >= LIMITS.classes) { prog.notes.push({ level: 'warn', msg: `sınıf sınırı (${LIMITS.classes}) aşıldı, kalanlar atlandı` }); break; }
      try {
        const cf = parseClass(e.data);
        const name = thisName(cf);
        const expected = e.name.replace(/\.class$/i, '');
        if (name !== expected) prog.tricks.nameMismatch.push(`${path} → ${name}`);
        prog.classes.push({ path, entry: e, container: out, cf, name });
      } catch (err) {
        prog.tricks.badClasses.push(`${path}: ${err.message}`);
      }
    } else if (/^classes\d*\.dex$/i.test(e.name) || (isDex(e.data) && /\.dex$/i.test(e.name))) {
      try { prog.dexes.push({ path, dex: parseDex(e.data), size: e.data.length }); } catch (err) { prog.notes.push({ level: 'warn', msg: `${path}: ${err.message}` }); }
    } else if (e.name === 'AndroidManifest.xml' && !prefix) {
      try {
        const m = parseAxml(e.data);
        prog.manifest = { xml: m.xml, summary: manifestSummary(m.root) };
      } catch (err) {
        // AAR'da metin manifest bulunur
        const t = text.decode(e.data.subarray(0, 200_000));
        if (t.trimStart().startsWith('<')) prog.manifest = { xml: t, summary: textManifest(t) };
        else prog.notes.push({ level: 'warn', msg: `AndroidManifest.xml: ${err.message}` });
      }
    } else if (/^META-INF\/MANIFEST\.MF$/i.test(e.name) && !prefix) {
      prog.jarManifest = text.decode(e.data.subarray(0, 100_000));
    } else if (/^lib\/[^/]+\/[^/]+\.so$/i.test(e.name) || /^jni\/[^/]+\/[^/]+\.so$/i.test(e.name)) {
      const [, abi, file] = e.name.split('/');
      prog.nativeLibs.push({ path, abi, name: file, size: e.size, elf: e.data[0] === 0x7f && e.data[1] === 0x45 });
    } else if (/\.(jar|zip)$/i.test(e.name) && depth < 1 && isZip(e.data) && prog.nested < LIMITS.nestedArchives) {
      prog.nested++;
      try { openZip(e.data, `${path}!/`, prog, depth + 1); e.nested = true; } catch (err) { prog.notes.push({ level: 'warn', msg: `${path}: ${err.message}` }); }
    } else if (/^assets\//.test(e.name) || /^res\/raw\//.test(e.name)) {
      prog.assets.push({ path, size: e.size, data: e.data.length <= 256 * 1024 ? e.data : null });
    }
  }
  for (const e of out.entries) if (/\.so$/i.test(e.name) && !prog.nativeLibs.some((l) => l.path === prefix + e.name) && e.data) {
    prog.nativeLibs.push({ path: prefix + e.name, abi: '', name: e.name.split('/').pop(), size: e.size, elf: e.data[0] === 0x7f && e.data[1] === 0x45 });
  }
}

function textManifest(t) {
  const pkg = /package="([^"]+)"/.exec(t)?.[1] ?? '';
  return { package: pkg, versionName: null, versionCode: null, minSdk: /minSdkVersion="([^"]+)"/.exec(t)?.[1] ?? null, targetSdk: null, permissions: [...t.matchAll(/uses-permission[^>]*android:name="([^"]+)"/g)].map((m) => m[1]), application: null, components: [], debuggable: false, allowBackup: null, cleartext: null };
}

/**
 * @param {Uint8Array} bytes
 * @param {string} name dosya adı (tür tahmini için)
 */
export function loadProgram(bytes, name = 'input') {
  if (bytes.length > LIMITS.inputBytes) throw new ParseError(`girdi çok büyük (${bytes.length} bayt)`);
  const prog = {
    name, kind: 'unknown', size: bytes.length, containers: [], classes: [], dexes: [], manifest: null, jarManifest: null,
    nativeLibs: [], assets: [], notes: [], nested: 0, budget: { left: LIMITS.zipTotalBytes },
    tricks: { dupEntries: [], classDirs: [], badClasses: [], nameMismatch: [] },
  };
  if (isClassFile(bytes)) {
    prog.kind = 'class';
    const cf = parseClass(bytes);
    prog.classes.push({ path: `${thisName(cf)}.class`, cf, name: thisName(cf) });
  } else if (isDex(bytes)) {
    prog.kind = 'dex';
    prog.dexes.push({ path: name, dex: parseDex(bytes), size: bytes.length });
  } else if (isZip(bytes)) {
    openZip(bytes, '', prog, 0);
    const names = new Set(prog.containers[0].entries.map((e) => e.name));
    prog.kind = names.has('AndroidManifest.xml') && [...names].some((n) => /^classes\d*\.dex$/.test(n)) ? 'apk'
      : names.has('classes.jar') && names.has('AndroidManifest.xml') ? 'aar'
      : prog.classes.length ? 'jar' : prog.dexes.length ? 'apk' : 'zip';
    if (/\.aar$/i.test(name) && names.has('classes.jar')) prog.kind = 'aar';
  } else {
    throw new ParseError('Tanınan bir biçim değil (.class, .jar, .apk, .aar, .dex bekleniyor)');
  }
  // aynı ada sahip birden çok sınıf: ayrıştırılabilen son kayıt geçerlidir (JVM arşiv aramasıyla aynı)
  prog.classMap = new Map();
  for (const c of prog.classes) prog.classMap.set(c.name, c.cf);
  prog.classes = prog.classes.filter((c) => prog.classMap.get(c.name) === c.cf);
  if (!prog.classes.length && !prog.dexes.length) throw new ParseError(prog.tricks.badClasses.length ? `hiçbir sınıf ayrıştırılamadı (${prog.tricks.badClasses[0]})` : 'arşivde sınıf ya da DEX yok');
  return prog;
}

export const mainClassOf = (prog) => /^Main-Class:\s*(\S+)/im.exec(prog.jarManifest ?? '')?.[1]?.replaceAll('.', '/') ?? null;
