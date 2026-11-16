// ProGuard / R8 mapping.txt ayrıştırıcı. Dosya "özgün → gizlenmiş" eşlemesidir; Peel tersini kullanır:
// gizlenmiş sınıf/alan/yöntem → özgün ad. Yöntem ve alan anahtarları gizlenmiş tanımlayıcıyla kurulur (aşırı yükleme).
//   com.example.Foo -> a.a:
//       java.lang.String name -> a
//       1:4:void run(int,java.lang.String):12:15 -> b
const PRIM = { boolean: 'Z', byte: 'B', char: 'C', short: 'S', int: 'I', long: 'J', float: 'F', double: 'D', void: 'V' };
const MAX_LINES = 2_000_000;

const toInternal = (dotted) => dotted.replaceAll('.', '/');
function descOf(javaType, forward) {
  let dims = 0;
  let t = javaType.trim();
  while (t.endsWith('[]')) { dims++; t = t.slice(0, -2); }
  const base = PRIM[t] ?? `L${forward.get(toInternal(t)) ?? toInternal(t)};`;
  return '['.repeat(dims) + base;
}

/**
 * @param {string} text mapping.txt içeriği
 * @returns {{ classes: Map<string,string>, fields: Map<string,string>, methods: Map<string,string>, count: number, errors: number }}
 *   classes: gizlenmiş iç ad → özgün iç ad; fields: "sahip.ad:tanım" → özgün ad; methods: "sahip.ad(tanım)" → özgün ad
 */
export function parseMapping(text) {
  const lines = String(text).split(/\r?\n/).slice(0, MAX_LINES);
  const forward = new Map();
  const classes = new Map();
  // 1. tur: sınıflar (tanımlayıcılar gizlenmiş adlarla kurulabilsin)
  for (const line of lines) {
    const m = /^(\S[^\s]*)\s+->\s+(\S+):\s*$/.exec(line);
    if (!m) continue;
    const orig = toInternal(m[1]);
    const obf = toInternal(m[2]);
    forward.set(orig, obf);
    classes.set(obf, orig);
  }
  const fields = new Map();
  const methods = new Map();
  let current = null;
  let errors = 0;
  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const cm = /^(\S[^\s]*)\s+->\s+(\S+):\s*$/.exec(line);
    if (cm) { current = toInternal(cm[2]); continue; }
    if (!current || !/^\s/.test(line)) { errors++; continue; }
    const mm = /^\s+(?:\d+:\d+:)?(\S+)\s+([^\s(]+)\(([^)]*)\)(?::\d+(?::\d+)?)?\s+->\s+(\S+)\s*$/.exec(line);
    if (mm) {
      const [, ret, name, args, obf] = mm;
      if (name.includes('.')) continue; // R8 satır içi gömülmüş başka sınıfın yöntemi
      const desc = `(${args ? args.split(',').map((a) => descOf(a, forward)).join('') : ''})${descOf(ret, forward)}`;
      methods.set(`${current}.${obf}${desc}`, name);
      continue;
    }
    const fm = /^\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s*$/.exec(line);
    if (fm) { fields.set(`${current}.${fm[3]}:${descOf(fm[1], forward)}`, fm[2]); continue; }
    errors++;
  }
  return { classes, fields, methods, count: classes.size + fields.size + methods.size, errors };
}
