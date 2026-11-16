// peel-java komut satırı: tarayıcıdakiyle aynı hat, Node'da izin modeliyle yalıtılmış alt süreçte (bekçili).
import { readFile, writeFile, mkdir, readdir, stat } from 'node:fs/promises';
import { dirname, join, relative, resolve, basename, extname } from 'node:path';
import { passes } from '../index.js';
import { createNodeSandbox } from '../sandbox/node-host.js';
import { reportText } from '../report/text.js';
import { parseArgs, UsageError } from './args.js';

export const EXIT = { OK: 0, ERROR: 1, USAGE: 2, THREAT: 4 };
export const MAX_INPUT = 128 * 1024 * 1024;
const MAX_MAPPING = 64 * 1024 * 1024;
const LEVELS = ['none', 'low', 'medium', 'high', 'critical'];
const JAVA_FILE = /\.(?:class|jar|apk|aar|dex)$/i;

const SPEC = {
  out: { alias: 'o', type: 'string' },
  'out-dir': { alias: 'd', type: 'string' },
  jar: { alias: 'j', type: 'string' },
  mapping: { alias: 'm', type: 'string' },
  view: { type: 'string' },
  report: { alias: 'r', type: 'string' },
  json: { type: 'bool' },
  lang: { type: 'string' },
  only: { type: 'list' },
  'fail-on': { type: 'string' },
  quiet: { alias: 'q', type: 'bool' },
  help: { alias: 'h', type: 'bool' },
};

const HELP = {
  tr: `peel-java <dosya|dizin|-> [seçenekler]

Java ve Android bytecode'unu (.class, .jar, .apk, .aar, .dex) çözer: gizleyiciyi tanır (ProGuard/R8, Allatori, Zelix
KlassMaster, Stringer, DexGuard, Paramorphism), dizge çözücülerini sınırlı ve yan etkisiz bir yorumlayıcıda çalıştırıp
sonuçları sabit olarak yazar, adları mapping.txt ile ya da okunur adlarla değiştirir. Çıktı javap/smali biçimi ayrıştırma
ya da sözde Java'dır; sınıf dosyası içeren girdiler için temiz JAR/AAR/.class da üretilir (DEX yeniden yazılmaz).

  -o, --out <dosya>        çıktıyı dosyaya yaz (tek girdi; yoksa stdout)
  -d, --out-dir <dizin>    çıktıları dizine yaz (dizin girdisinde yapı korunur)
  -j, --jar <dosya>        temiz arşivi/sınıf dosyasını yaz (tek girdi; APK/DEX için yok)
  -m, --mapping <dosya>    ProGuard/R8 mapping.txt ile özgün adları geri koy
      --view disasm|java   çıktı: ayrıştırma (varsayılan) ya da sözde Java
  -r, --report <hedef>     rapor: json | text (stdout'a, kod yazılmaz) ya da dosya yolu (.txt ise metin, değilse JSON;
                           dizin girdisinde JSON dizi)
      --json               --report json ile aynı
      --only <geçiş,...>   yalnızca bu geçişler (${passes().map((p) => p.id).join(', ')})
      --lang tr|en         rapor dili (varsayılan tr)
      --fail-on <düzey>    tehdit düzeyi bu eşiğe ulaşırsa çıkış kodu 4: low | medium | high | critical
  -q, --quiet              ilerleme ve özet yazma
  -h, --help               bu yardım

Çıkış kodları: 0 tamam, 1 hata, 2 kullanım hatası, 4 --fail-on eşiğine ulaşıldı (hatadan önceliklidir).
Bilinen Android paketleyicileri (Jiagu, Bangcle, Legu...) tanınır ama açılmaz; yalnızca raporlanır.`,
  en: `peel-java <file|dir|-> [options]

Deobfuscates Java and Android bytecode (.class, .jar, .apk, .aar, .dex): fingerprints the obfuscator (ProGuard/R8,
Allatori, Zelix KlassMaster, Stringer, DexGuard, Paramorphism), runs string decryptors in a bounded, side-effect-free
interpreter and writes the results back as constants, and renames symbols from a mapping.txt or to readable names. Output
is a javap/smali-style disassembly or pseudo-Java; inputs with class files also get a clean JAR/AAR/.class (DEX is not
rewritten).

  -o, --out <file>         write the output to a file (single input; otherwise stdout)
  -d, --out-dir <dir>      write outputs to a directory (directory input keeps its structure)
  -j, --jar <file>         write the clean archive/class file (single input; not for APK/DEX)
  -m, --mapping <file>     restore original names from a ProGuard/R8 mapping.txt
      --view disasm|java   output: disassembly (default) or pseudo-Java
  -r, --report <target>    report: json | text (to stdout, no code) or a file path (.txt gives text, anything else JSON;
                           a JSON array for directory input)
      --json               same as --report json
      --only <pass,...>    run only these passes (${passes().map((p) => p.id).join(', ')})
      --lang tr|en         report language (default tr)
      --fail-on <level>    exit with code 4 when the threat level reaches: low | medium | high | critical
  -q, --quiet              no progress or summary output
  -h, --help               this help

Exit codes: 0 ok, 1 error, 2 usage error, 4 --fail-on threshold reached (takes precedence over errors).
Known Android packers (Jiagu, Bangcle, Legu...) are identified but not unpacked; they are reported only.`,
};

async function readBytes(path, max = MAX_INPUT) {
  if (path === '-') {
    const chunks = [];
    let n = 0;
    for await (const c of process.stdin) {
      n += c.length;
      if (n > max) throw new Error('Girdi çok büyük');
      chunks.push(c);
    }
    return new Uint8Array(Buffer.concat(chunks));
  }
  const s = await stat(path);
  if (!s.isFile()) throw new Error(`Dosya değil: ${path}`);
  if (s.size > max) throw new Error(`Dosya çok büyük: ${path}`);
  return new Uint8Array(await readFile(path));
}

/** Dizindeki Java/Android dosyaları (özyinelemeli, sembolik bağlar izlenmez), sıralı */
async function listInputs(root) {
  const out = [];
  const walkDir = async (dir) => {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await walkDir(p);
      else if (e.isFile() && JAVA_FILE.test(e.name)) out.push(p);
    }
  };
  await walkDir(root);
  return out;
}

async function writeOut(path, data) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, data);
}

const levelOf = (entry) => entry.report?.threat?.level ?? 'none';
const textOf = (entries, isDir, lang) => entries.map((e) => `${isDir ? `== ${e.file} ==\n` : ''}${e.error ? `${lang === 'en' ? 'Error' : 'Hata'}: ${e.error}\n` : ''}${e.report ? reportText(e.report, lang) : ''}`).join('\n');

export async function runCli(argv) {
  const { opts, positional } = parseArgs(argv, SPEC);
  const lang = opts.lang === undefined ? 'tr' : opts.lang;
  if (lang !== 'tr' && lang !== 'en') throw new UsageError(`--lang tr ya da en olmalı: ${lang}`);
  if (opts.help) { console.log(HELP[lang]); return EXIT.OK; }
  if (positional.length !== 1) throw new UsageError(`${HELP[lang]}\n\nTek bir girdi gerekli (dosya, dizin ya da -).`);
  if (opts['fail-on'] !== undefined && !LEVELS.slice(1).includes(opts['fail-on'])) throw new UsageError('--fail-on şunlardan biri olmalı: low, medium, high, critical');
  const view = opts.view ?? 'disasm';
  if (view !== 'disasm' && view !== 'java') throw new UsageError('--view disasm ya da java olmalı');
  const ids = passes().map((p) => p.id);
  const only = opts.only.flatMap((x) => x.split(',')).map((x) => x.trim()).filter(Boolean);
  const unknown = only.filter((x) => !ids.includes(x));
  if (unknown.length) throw new UsageError(`Bilinmeyen geçiş: ${unknown.join(', ')} (geçerli: ${ids.join(', ')})`);
  const stdoutReport = opts.json ? 'json' : ['json', 'text'].includes(opts.report) ? opts.report : null;
  const reportFile = opts.report !== undefined && !['json', 'text'].includes(opts.report) ? opts.report : null;

  const target = positional[0];
  const isDir = target !== '-' && (await stat(target).catch(() => null))?.isDirectory();
  if (isDir && (opts.out || opts.jar)) throw new UsageError('Dizin girdisinde -o/-j yerine -d kullanın');
  const log = (m) => { if (!opts.quiet) process.stderr.write(`${m}\n`); };
  const mapping = opts.mapping ? new TextDecoder().decode(await readBytes(opts.mapping, MAX_MAPPING)) : null;
  const ext = view === 'java' ? '.java.txt' : '.disasm.txt';

  const sandbox = createNodeSandbox();
  const entries = [];
  try {
    const files = isDir ? await listInputs(target) : [target];
    if (isDir && !files.length) log(lang === 'en' ? 'No .class/.jar/.apk/.aar/.dex files found.' : '.class/.jar/.apk/.aar/.dex dosyası bulunamadı.');
    for (const file of files) {
      const name = file === '-' ? '-' : isDir ? relative(target, file).split('\\').join('/') : file;
      const entry = { file: name, ok: false };
      entries.push(entry);
      let bytes;
      try {
        bytes = await readBytes(file);
      } catch (e) {
        entry.error = e.message;
        log(`${name}: ${e.message}`);
        continue;
      }
      const r = await sandbox.peel(bytes, { name: file === '-' ? 'stdin.jar' : basename(file), mapping, lang, timeline: false, ...(only.length ? { only } : {}) });
      const code = (view === 'java' ? r.java : r.code) ?? '';
      Object.assign(entry, { ok: Boolean(r.ok), error: r.ok ? undefined : r.error, kind: r.kind, rewritten: Boolean(r.rewritten), verified: Boolean(r.verified), changed: Boolean(r.changed), ms: r.ms ?? 0, report: r.report ?? null });
      if (r.ok) {
        if (opts['out-dir']) {
          const rel = isDir ? relative(target, file) : file === '-' ? 'stdin.jar' : basename(file);
          const dest = resolve(opts['out-dir'], rel.slice(0, rel.length - extname(rel).length) + ext);
          if (relative(resolve(opts['out-dir']), dest).startsWith('..')) throw new Error(`Çıktı dizini dışına yazma: ${rel}`);
          await writeOut(dest, code);
          if (r.bytes) await writeOut(dest.slice(0, dest.length - ext.length) + (r.ext === '.class' ? '.peeled.class' : `.peeled${r.ext}`), r.bytes);
        }
        if (opts.out) await writeOut(opts.out, code);
        else if (!isDir && !opts['out-dir'] && !stdoutReport) process.stdout.write(code.endsWith('\n') ? code : `${code}\n`);
        if (opts.jar) {
          if (r.bytes) await writeOut(opts.jar, r.bytes);
          else log(lang === 'en' ? `${name}: no clean archive (DEX/APK is not rewritten)` : `${name}: temiz arşiv yok (DEX/APK yeniden yazılmaz)`);
        }
      }
      if (r.report) {
        const th = r.report.threat;
        log(`${isDir ? `${name}: ` : ''}[${th.level} ${th.score}/100] ${r.report.summary}`);
      } else log(`${name}: ${r.error}`);
    }
  } finally {
    sandbox.close();
  }

  const payload = isDir ? entries : entries[0];
  const json = `${JSON.stringify(payload, (k, v) => (typeof v === 'bigint' ? String(v) : v), 2)}\n`;
  if (reportFile) await writeOut(reportFile, /\.txt$/i.test(reportFile) ? textOf(entries, isDir, lang) : json);
  if (stdoutReport === 'json') process.stdout.write(json);
  else if (stdoutReport === 'text') process.stdout.write(textOf(entries, isDir, lang));

  const failOn = opts['fail-on'];
  if (failOn && entries.some((e) => LEVELS.indexOf(levelOf(e)) >= LEVELS.indexOf(failOn))) return EXIT.THREAT;
  return entries.some((e) => !e.ok) ? EXIT.ERROR : EXIT.OK;
}
