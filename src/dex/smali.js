// DEX görünümleri: smali benzeri ayrıştırma ve yazmaç tabanlı sözde Java. Yeniden adlandırma planı ve çözülmüş dizge
// işaretleri (passes/strings.js decryptDex) yalnızca burada, görüntülemede uygulanır; DEX baytları değişmez.
import { decode, payloadAt } from './opcodes.js';
import { methodsOf, internalOf } from './dex.js';
import { javaString } from '../jvm/disasm.js';
import { javaType } from '../jvm/classfile.js';
import { LIMITS } from '../core/limits.js';

const IDENT = { cls: (n) => n, desc: (d) => d, method: (o, n) => n, field: (o, n) => n };
const hex = (n) => n.toString(16).padStart(4, '0');
const ACCF = [[0x1, 'public'], [0x2, 'private'], [0x4, 'protected'], [0x8, 'static'], [0x10, 'final'], [0x20, 'synchronized'], [0x100, 'native'], [0x200, 'interface'], [0x400, 'abstract'], [0x1000, 'synthetic'], [0x4000, 'enum'], [0x10000, 'constructor']];
const accStr = (a, cls = false) => ACCF.filter(([b, n]) => a & b && !(cls && n === 'synchronized')).map(([, n]) => n).join(' ');

function namer(dex, plan = IDENT) {
  const t = (d) => (d ? plan.desc(d) : d);
  return {
    type: t,
    field: (i) => { const f = dex.fields[i]; return f ? `${t(f.cls)}->${plan.field(internalOf(f.cls), f.name, f.type)}:${t(f.type)}` : `field@${i}`; },
    method: (i) => { const m = dex.methods[i]; return m ? `${t(m.cls)}->${plan.method(internalOf(m.cls), m.name, m.desc)}${t(m.desc)}` : `method@${i}`; },
    methodParts: (i) => { const m = dex.methods[i]; return m ? { cls: t(m.cls), name: plan.method(internalOf(m.cls), m.name, m.desc), params: m.proto.params, ret: m.proto.ret } : null; },
    fieldParts: (i) => { const f = dex.fields[i]; return f ? { cls: t(f.cls), name: plan.field(internalOf(f.cls), f.name, f.type), type: f.type } : null; },
  };
}

function operands(dex, nm, ins, code) {
  const v = (r) => `v${r}`;
  const ref = () => {
    switch (ins.kind) {
      case 'string': return javaString(dex.strings[ins.index] ?? `string@${ins.index}`);
      case 'type': return nm.type(dex.types[ins.index]) ?? `type@${ins.index}`;
      case 'field': return nm.field(ins.index);
      case 'method': return nm.method(ins.index);
      default: return `${ins.kind}@${ins.index}`;
    }
  };
  const tgt = () => `:L${hex(ins.target)}`;
  switch (ins.fmt) {
    case '10x': return '';
    case '12x': case '22x': case '32x': return `${v(ins.a)}, ${v(ins.b)}`;
    case '11n': case '21s': case '31i': case '21h': return ins.wide !== undefined ? `${v(ins.a)}, ${ins.wide}L` : `${v(ins.a)}, ${ins.lit}`;
    case '51l': return `${v(ins.a)}, ${ins.wide}L`;
    case '11x': return v(ins.a);
    case '10t': case '20t': case '30t': return tgt();
    case '21t': return `${v(ins.a)}, ${tgt()}`;
    case '31t': {
      if (ins.name === 'fill-array-data') { try { const p = payloadAt(code.insns, ins.target); return `${v(ins.a)}, { ${p.size} x ${p.width} bytes }`; } catch { return `${v(ins.a)}, ${tgt()}`; } }
      try { const p = payloadAt(code.insns, ins.target); return `${v(ins.a)}, { ${p.cases.map(([k, o]) => `${k} -> :L${hex(ins.pc + o)}`).join(', ')} }`; } catch { return `${v(ins.a)}, ${tgt()}`; }
    }
    case '21c': case '31c': return `${v(ins.a)}, ${ref()}`;
    case '23x': return `${v(ins.a)}, ${v(ins.b)}, ${v(ins.c)}`;
    case '22b': case '22s': return `${v(ins.a)}, ${v(ins.b)}, ${ins.lit}`;
    case '22t': return `${v(ins.a)}, ${v(ins.b)}, ${tgt()}`;
    case '22c': return `${v(ins.a)}, ${v(ins.b)}, ${ref()}`;
    case '35c': case '3rc': case '45cc': case '4rcc': return `{${ins.regs.map(v).join(', ')}}, ${ref()}`;
    default: return '';
  }
}

const targetsOf = (insns, code) => {
  const t = new Set();
  for (const ins of insns) {
    if (ins.target === undefined || ins.name === 'fill-array-data') continue;
    if (ins.name.endsWith('switch')) { try { for (const [, o] of payloadAt(code.insns, ins.target).cases) t.add(ins.pc + o); } catch { /* bozuk tablo */ } } else t.add(ins.target);
  }
  for (const tr of code.tries) { for (const h of tr.handlers) t.add(h.addr); if (tr.catchAll !== null) t.add(tr.catchAll); }
  return t;
};

function methodSmali(dex, nm, m, marks, lines) {
  const id = dex.methods[m.idx];
  lines.push(`.method ${accStr(m.access)} ${nm.method(m.idx).split('->')[1]}`.replace(/\s+/g, ' ').replace('.method  ', '.method '));
  if (!m.code) { lines.push('.end method'); return; }
  const c = m.code;
  lines.push(`    .registers ${c.registers}`);
  let insns;
  try { insns = decode(c.insns); } catch (e) { lines.push(`    # cannot decode: ${e.message}`, '.end method'); return; }
  const targets = targetsOf(insns, c);
  for (const t of c.tries) lines.push(`    .catch ${t.handlers.map((h) => `${nm.type(h.type)} -> :L${hex(h.addr)}`).join(', ')}${t.catchAll !== null ? `${t.handlers.length ? ', ' : ''}all -> :L${hex(t.catchAll)}` : ''} {:L${hex(t.start)} .. :L${hex(t.start + t.count)}}`);
  let skipUntil = -1;
  for (const ins of insns) {
    if (ins.pc < skipUntil) continue;
    if (targets.has(ins.pc)) lines.push(`  :L${hex(ins.pc)}`);
    if (ins.fmt === 'payload') continue;
    const mk = marks?.get(ins.pc);
    if (mk) {
      lines.push(`    ${hex(ins.pc)}: const-string v${mk.reg}, ${javaString(mk.value)}    # peel: decrypted by ${mk.from}`);
      skipUntil = mk.until;
      continue;
    }
    const ops = operands(dex, nm, ins, c);
    lines.push(`    ${hex(ins.pc)}: ${ops ? `${ins.name} ${ops}` : ins.name}`);
  }
  lines.push('.end method');
  return id;
}

/** Tüm DEX dosyasının smali benzeri ayrıştırması */
export function smaliDex(dex, { plan = IDENT, notes = new Map(), only = null } = {}) {
  const nm = namer(dex, plan);
  const out = [];
  for (const c of dex.classes) {
    if (only && !only.has(c.type)) continue;
    const lines = [`.class ${accStr(c.access, true)} ${nm.type(c.type)}`.replace(/\s+/g, ' ')];
    if (c.superType) lines.push(`.super ${nm.type(c.superType)}`);
    if (c.sourceFile) lines.push(`.source ${javaString(c.sourceFile)}`);
    for (const i of c.interfaces) lines.push(`.implements ${nm.type(i)}`);
    const sv = c.staticValues;
    c.staticFields.forEach((f, i) => {
      const val = sv[i] && sv[i].type !== 'Array' ? ` = ${sv[i].type === 'String' ? javaString(sv[i].value ?? '') : String(sv[i].value)}` : '';
      lines.push(`.field ${accStr(f.access)} ${nm.field(f.idx).split('->')[1]}${val}`.replace(/\s+/g, ' ').replace(/ = /, ' = '));
    });
    for (const f of c.instanceFields) lines.push(`.field ${accStr(f.access)} ${nm.field(f.idx).split('->')[1]}`.replace(/\s+/g, ' '));
    for (const m of methodsOf(c)) { lines.push(''); methodSmali(dex, nm, m, m.code ? notes.get(m.code) : null, lines); }
    out.push(lines.join('\n'));
  }
  return out.join('\n\n');
}

// ── sözde Java (yazmaç tabanlı) ──
const BINS = { add: '+', sub: '-', mul: '*', div: '/', rem: '%', and: '&', or: '|', xor: '^', shl: '<<', shr: '>>', ushr: '>>>' };
const IFS = { eq: '==', ne: '!=', lt: '<', ge: '>=', gt: '>', le: '<=' };
const simpleT = (d) => { const j = javaType(d); return j.slice(j.lastIndexOf('.') + 1); };

function methodPseudo(dex, nm, m, marks) {
  const c = m.code;
  const insns = decode(c.insns);
  if (insns.length > LIMITS.pseudoInsns) return { lines: [`    /* Peel: method too large (${insns.length} instructions); see the smali view */`], ok: false };
  const targets = targetsOf(insns, c);
  const id = dex.methods[m.idx];
  const isStatic = Boolean(m.access & 0x8);
  const names = new Map();
  let r = c.registers - c.ins;
  if (!isStatic) names.set(r++, 'this');
  id.proto.params.forEach((p, i) => { names.set(r, `p${i}`); r += p === 'J' || p === 'D' ? 2 : 1; });
  const v = (x) => names.get(x) ?? `v${x}`;
  const out = [];
  const emit = (s) => out.push(`    ${s}`);
  for (const t of c.tries) out.push(`    // try L${hex(t.start)}..L${hex(t.start + t.count)} catch (${t.handlers.map((h) => simpleT(h.type)).join(', ')}${t.catchAll !== null ? ' | Throwable' : ''})`);
  let pending = null; // move-result bekleyen çağrı
  let skipUntil = -1;
  for (const ins of insns) {
    if (ins.pc < skipUntil) continue;
    if (targets.has(ins.pc)) out.push(`  L${hex(ins.pc)}:`);
    if (ins.fmt === 'payload') continue;
    const n = ins.name;
    const mk = marks?.get(ins.pc);
    if (mk) { emit(`${v(mk.reg)} = ${javaString(mk.value)};`); skipUntil = mk.until; continue; }
    if (pending && !n.startsWith('move-result')) { emit(`${pending};`); pending = null; }
    if (n.startsWith('move-result')) { emit(`${v(ins.a)} = ${pending ?? 'result'};`); pending = null; continue; }
    if (n === 'move-exception') { emit(`${v(ins.a)} = caught;`); continue; }
    if (n.startsWith('move')) { emit(`${v(ins.a)} = ${v(ins.b)};`); continue; }
    if (n === 'return-void') { emit('return;'); continue; }
    if (n.startsWith('return')) { emit(`return ${v(ins.a)};`); continue; }
    if (n.startsWith('const-string')) { emit(`${v(ins.a)} = ${javaString(dex.strings[ins.index] ?? '')};`); continue; }
    if (n.startsWith('const-wide')) { emit(`${v(ins.a)} = ${ins.wide}L;`); continue; }
    if (n.startsWith('const-class')) { emit(`${v(ins.a)} = ${simpleT(nm.type(dex.types[ins.index]))}.class;`); continue; }
    if (n.startsWith('const')) { emit(`${v(ins.a)} = ${ins.lit};`); continue; }
    if (n === 'check-cast') { emit(`${v(ins.a)} = (${simpleT(nm.type(dex.types[ins.index]))}) ${v(ins.a)};`); continue; }
    if (n === 'instance-of') { emit(`${v(ins.a)} = ${v(ins.b)} instanceof ${simpleT(nm.type(dex.types[ins.index]))};`); continue; }
    if (n === 'array-length') { emit(`${v(ins.a)} = ${v(ins.b)}.length;`); continue; }
    if (n === 'new-instance') { emit(`${v(ins.a)} = new ${simpleT(nm.type(dex.types[ins.index]))}; // constructor follows`); continue; }
    if (n === 'new-array') { emit(`${v(ins.a)} = new ${javaType(nm.type(dex.types[ins.index])).replace(/\[\]$/, '')}[${v(ins.b)}];`); continue; }
    if (n.startsWith('filled-new-array')) { pending = `new ${javaType(nm.type(dex.types[ins.index])).replace(/\[\]$/, '')}[] { ${ins.regs.map(v).join(', ')} }`; continue; }
    if (n === 'fill-array-data') { emit(`fill(${v(ins.a)}, L${hex(ins.target)}); // array data`); continue; }
    if (n === 'throw') { emit(`throw ${v(ins.a)};`); continue; }
    if (n.startsWith('goto')) { emit(`goto L${hex(ins.target)};`); continue; }
    if (n.endsWith('switch')) {
      emit(`switch (${v(ins.a)}) {`);
      try { for (const [k, o] of payloadAt(c.insns, ins.target).cases) emit(`  case ${k}: goto L${hex(ins.pc + o)};`); } catch { emit('  /* corrupt table */'); }
      emit('}');
      continue;
    }
    if (n.startsWith('cmp')) { emit(`${v(ins.a)} = compare(${v(ins.b)}, ${v(ins.c)});`); continue; }
    if (n.startsWith('if-')) { const z = n.endsWith('z'); emit(`if (${v(ins.a)} ${IFS[n.slice(3, 5)]} ${z ? '0' : v(ins.b)}) goto L${hex(ins.target)};`); continue; }
    if (n.startsWith('aget')) { emit(`${v(ins.a)} = ${v(ins.b)}[${v(ins.c)}];`); continue; }
    if (n.startsWith('aput')) { emit(`${v(ins.b)}[${v(ins.c)}] = ${v(ins.a)};`); continue; }
    if (n.startsWith('iget') || n.startsWith('iput') || n.startsWith('sget') || n.startsWith('sput')) {
      const f = nm.fieldParts(ins.index);
      const target = n[0] === 'i' ? `${v(ins.b)}.${f?.name}` : `${simpleT(f?.cls ?? 'L?;')}.${f?.name}`;
      emit(n[1] === 'g' ? `${v(ins.a)} = ${target};` : `${target} = ${v(ins.a)};`);
      continue;
    }
    if (n.startsWith('invoke-')) {
      const mp = ins.kind === 'method' ? nm.methodParts(ins.index) : null;
      if (!mp) { pending = `${n}(${ins.regs.map(v).join(', ')})`; continue; }
      const regs = [...ins.regs];
      const isSt = n.startsWith('invoke-static');
      const recv = isSt ? null : v(regs.shift());
      const args = [];
      for (const p of mp.params) { args.push(v(regs.shift())); if (p === 'J' || p === 'D') regs.shift(); }
      if (mp.name === '<init>') { emit(`${recv} = new ${simpleT(mp.cls)}(${args.join(', ')});`.replace(/^this = new .*/, `super(${args.join(', ')});`)); continue; }
      const call = `${isSt ? simpleT(mp.cls) : n.startsWith('invoke-super') ? 'super' : recv}.${mp.name}(${args.join(', ')})`;
      if (mp.ret === 'V') emit(`${call};`); else pending = call;
      continue;
    }
    const un = /^(neg|not)-(\w+)$/.exec(n);
    if (un) { emit(`${v(ins.a)} = ${un[1] === 'neg' ? '-' : '~'}${v(ins.b)};`); continue; }
    const cv = /^(\w+)-to-(\w+)$/.exec(n);
    if (cv) { emit(`${v(ins.a)} = (${cv[2]}) ${v(ins.b)};`); continue; }
    if (n === 'rsub-int' || n === 'rsub-int/lit8') { emit(`${v(ins.a)} = ${ins.lit} - ${v(ins.b)};`); continue; }
    const bin = /^(\w+)-(int|long|float|double)(\/2addr|\/lit8|\/lit16)?$/.exec(n);
    if (bin && BINS[bin[1]]) {
      const o = BINS[bin[1]];
      if (bin[3] === '/2addr') emit(`${v(ins.a)} ${o}= ${v(ins.b)};`);
      else if (bin[3]) emit(`${v(ins.a)} = ${v(ins.b)} ${o} ${ins.lit};`);
      else emit(`${v(ins.a)} = ${v(ins.b)} ${o} ${v(ins.c)};`);
      continue;
    }
    if (n === 'nop' || n.startsWith('monitor')) continue;
    emit(`// ${n}`);
  }
  if (pending) emit(`${pending};`);
  return { lines: out, ok: true };
}

export function pseudoDex(dex, { plan = IDENT, notes = new Map() } = {}) {
  const nm = namer(dex, plan);
  const out = [];
  const stats = { methods: 0, structured: 0, fallback: 0 };
  for (const c of dex.classes) {
    const lines = [`class ${javaType(nm.type(c.type))}${c.superType && c.superType !== 'Ljava/lang/Object;' ? ` extends ${javaType(nm.type(c.superType))}` : ''}${c.interfaces.length ? ` implements ${c.interfaces.map((i) => javaType(nm.type(i))).join(', ')}` : ''} {`];
    for (const f of [...c.staticFields, ...c.instanceFields]) {
      const fp = nm.fieldParts(f.idx);
      lines.push(`  ${accStr(f.access)} ${javaType(nm.type(fp.type))} ${fp.name};`.replace(/\s+/g, ' ').replace(/^ /, '  '));
    }
    for (const m of methodsOf(c)) {
      const mp = nm.methodParts(m.idx);
      lines.push('');
      const sig = mp.name === '<clinit>' ? 'static' : `${accStr(m.access & ~0x10000)} ${mp.name === '<init>' ? simpleT(mp.cls) : `${javaType(nm.type(mp.ret))} ${mp.name}`}(${mp.params.map((p, i) => `${javaType(nm.type(p))} p${i}`).join(', ')})`.trim();
      if (!m.code) { lines.push(`  ${sig};`); continue; }
      stats.methods++;
      lines.push(`  ${sig} {`);
      try {
        const r = methodPseudo(dex, nm, m, notes.get(m.code));
        lines.push(...r.lines);
        if (r.ok) stats.structured++; else stats.fallback++;
      } catch (e) {
        stats.fallback++;
        lines.push(`    /* Peel: no pseudo-Java for this method (${e.message}); see the smali view */`);
      }
      lines.push('  }');
    }
    lines.push('}');
    out.push(lines.join('\n'));
  }
  return { text: out.join('\n\n'), stats };
}
