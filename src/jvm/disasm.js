// javap benzeri ayrıştırma: sınıf başlığı, alanlar, yöntemler, komutlar (çözülmüş havuz sabitleriyle), istisna tabloları.
import { decode, opName, NEWARRAY_TYPES } from './opcodes.js';
import { utf8, className, thisName, superName, memberName, memberDesc, constant, ref, nat, findAttr, javaType, parseMethodDesc, ACC } from './classfile.js';
import { Reader } from '../core/bytes.js';

export function javaString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20 || (c >= 0x7f && c < 0xa0) || (c >= 0xd800 && c <= 0xdfff) || c === 0x2028 || c === 0x2029 || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || c === 0xfeff) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

export function flags(acc, kind) {
  const out = [];
  if (acc & ACC.PUBLIC) out.push('public');
  if (acc & ACC.PRIVATE) out.push('private');
  if (acc & ACC.PROTECTED) out.push('protected');
  if (acc & ACC.STATIC) out.push('static');
  if (acc & ACC.FINAL) out.push('final');
  if (kind === 'method' && acc & ACC.SYNCHRONIZED) out.push('synchronized');
  if (kind === 'field' && acc & ACC.VOLATILE) out.push('volatile');
  if (kind === 'field' && acc & ACC.TRANSIENT) out.push('transient');
  if (kind === 'method' && acc & ACC.NATIVE) out.push('native');
  if (kind !== 'field' && acc & ACC.ABSTRACT && !(acc & ACC.INTERFACE)) out.push('abstract');
  if (kind === 'method' && acc & ACC.BRIDGE) out.push('/* bridge */');
  if (acc & ACC.SYNTHETIC) out.push('/* synthetic */');
  return out;
}

export function classHeader(cf) {
  const kind = cf.access & ACC.ANNOTATION ? '@interface' : cf.access & ACC.INTERFACE ? 'interface' : cf.access & ACC.ENUM ? 'enum' : 'class';
  const sup = superName(cf);
  const ifs = cf.interfaces.map((i) => className(cf, i).replaceAll('/', '.'));
  return `${[...flags(cf.access & ~ACC.SUPER & ~(cf.access & ACC.INTERFACE ? ACC.ABSTRACT : 0), 'class'), kind].join(' ')} ${thisName(cf).replaceAll('/', '.')}`
    + (sup && sup !== 'java/lang/Object' && kind !== 'interface' ? ` extends ${sup.replaceAll('/', '.')}` : '')
    + (ifs.length ? ` ${kind === 'interface' ? 'extends' : 'implements'} ${ifs.join(', ')}` : '');
}

export function methodSignature(cf, m) {
  const name = memberName(cf, m);
  const { params, ret } = parseMethodDesc(memberDesc(cf, m));
  const owner = thisName(cf);
  const head = flags(m.access, 'method').join(' ');
  const args = params.map((p) => javaType(p)).join(', ');
  if (name === '<clinit>') return 'static {}';
  if (name === '<init>') return `${head ? `${head} ` : ''}${owner.slice(owner.lastIndexOf('/') + 1)}(${args})`;
  return `${head ? `${head} ` : ''}${javaType(ret)} ${name}(${args})`;
}

export function operand(cf, ins) {
  if (ins.index !== undefined) {
    const e = cf.cp[ins.index];
    if (!e) return `#${ins.index}`;
    if (e.tag >= 9 && e.tag <= 11) { const r = ref(cf, ins.index); return `${r.owner}.${r.name}:${r.desc}`; }
    if (e.tag === 7) return className(cf, ins.index) + (ins.dims ? `, ${ins.dims}` : '');
    if (e.tag === 18) { const n = nat(cf, e.natIndex); return `#${e.bsmIndex}:${n.name}:${n.desc}`; }
    const c = constant(cf, ins.index);
    if (c?.type === 'String') return javaString(c.value);
    if (c?.type === 'J') return `${c.value}l`;
    if (c?.type === 'F') return `${c.value}f`;
    if (c?.type === 'D') return `${c.value}d`;
    if (c?.type === 'Class') return `class ${c.value}`;
    if (c) return typeof c.value === 'object' ? JSON.stringify(c.value) : String(c.value);
    return `#${ins.index}`;
  }
  if (ins.cases) return `{ ${ins.cases.map(([k, t]) => `${k}: ${t}`).join(', ')}, default: ${ins.default} }`;
  if (ins.target !== undefined) return String(ins.target);
  if (ins.name === 'iinc' || ins.wideOp === 0x84) return `${ins.local}, ${ins.value}`;
  if (ins.local !== undefined) return String(ins.local);
  if (ins.atype !== undefined) return javaType(NEWARRAY_TYPES[ins.atype] ?? '?');
  if (ins.value !== undefined) return String(ins.value);
  return '';
}

function methodBody(cf, m, lines) {
  const c = m.code;
  lines.push(`    Code: stack=${c.maxStack}, locals=${c.maxLocals}`);
  let insns;
  try { insns = decode(c.code); } catch (e) { lines.push(`      // cannot decode: ${e.message}`); return; }
  for (let i = 0; i < insns.length; i++) {
    const ins = insns[i];
    if (ins.op === 0) {
      let n = 1;
      while (insns[i + n]?.op === 0) n++;
      lines.push(`    ${String(ins.pc).padStart(5)}: nop${n > 1 ? ` (x${n})` : ''}`);
      i += n - 1;
      continue;
    }
    const opnd = operand(cf, ins);
    lines.push(`    ${String(ins.pc).padStart(5)}: ${opnd ? `${ins.name.padEnd(15)} ${opnd}` : ins.name}`);
  }
  if (c.exceptions.length) {
    lines.push('    Exception table:');
    for (const e of c.exceptions) lines.push(`      ${e.start} - ${e.end} -> ${e.handler} ${e.catchType ? className(cf, e.catchType) : 'any'}`);
  }
}

/** Tek sınıfın ayrıştırması */
export function disassembleClass(cf) {
  const lines = [];
  const sf = findAttr(cf, cf.attrs, 'SourceFile');
  lines.push(`// ${thisName(cf)}.class · version ${cf.major}.${cf.minor}${sf ? ` · source ${utf8(cf, new Reader(sf.data).u2())}` : ''}`);
  lines.push(`${classHeader(cf)} {`);
  for (const f of cf.fields) {
    const cv = findAttr(cf, f.attrs, 'ConstantValue');
    let init = '';
    if (cv && cv.data.length >= 2) {
      const k = constant(cf, new Reader(cv.data).u2());
      if (k) init = ` = ${k.type === 'String' ? javaString(k.value) : String(k.value)}`;
    }
    lines.push(`  ${[...flags(f.access, 'field'), javaType(memberDesc(cf, f))].join(' ')} ${memberName(cf, f)}${init};`);
  }
  for (const m of cf.methods) {
    lines.push('');
    lines.push(`  ${methodSignature(cf, m)};`);
    lines.push(`    descriptor: ${memberDesc(cf, m)}`);
    if (m.code) methodBody(cf, m, lines);
  }
  lines.push('}');
  return lines.join('\n');
}

export { opName };
