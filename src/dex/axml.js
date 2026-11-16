// Android ikili XML (AndroidManifest.xml) çözücü. Dizge havuzu (UTF-8 ve UTF-16), kaynak kimliği haritası, ad alanları,
// öğeler ve türlü öznitelik değerleri okunur; metin XML ve manifest özeti (paket, izinler, bileşenler) üretilir.
// Ad dizgesi silinmiş (karartılmış) özniteliklerin adı kaynak kimliğinden bulunur.
import { Reader, ParseError } from '../core/bytes.js';

const ATTR_IDS = {
  0x01010003: 'name', 0x01010001: 'label', 0x01010002: 'icon', 0x0101021b: 'versionCode', 0x0101021c: 'versionName',
  0x0101020c: 'minSdkVersion', 0x01010270: 'targetSdkVersion', 0x01010010: 'exported', 0x0101000f: 'debuggable',
  0x01010006: 'permission', 0x0101000e: 'enabled', 0x01010018: 'authorities', 0x0101001f: 'process', 0x01010280: 'allowBackup',
  0x01010272: 'usesCleartextTraffic', 0x01010026: 'scheme', 0x01010028: 'host', 0x0101002b: 'mimeType', 0x01010024: 'value',
  0x01010025: 'resource', 0x0101000c: 'priority', 0x01010004: 'manageSpaceActivity', 0x01010020: 'theme',
};
const utf16 = new TextDecoder('utf-16le');
const utf8 = new TextDecoder('utf-8');

function readPool(r, start) {
  const c = r.at(start);
  c.u2();
  const headerSize = c.u2();
  const size = c.u4();
  const count = c.u4();
  c.u4();
  const flags = c.u4();
  const stringsStart = c.u4();
  if (count > 200000 || start + size > r.length) throw new ParseError('AXML dizge havuzu bozuk');
  const offs = [];
  const o = r.at(start + headerSize);
  for (let i = 0; i < count; i++) offs.push(o.u4());
  const isUtf8 = Boolean(flags & 0x100);
  return offs.map((off) => {
    const s = r.at(start + stringsStart + off);
    try {
      if (isUtf8) {
        let n = s.u1(); if (n & 0x80) s.u1();
        n = s.u1(); if (n & 0x80) n = ((n & 0x7f) << 8) | s.u1();
        return utf8.decode(s.bytes(n));
      }
      let n = s.u2(); if (n & 0x8000) n = ((n & 0x7fff) << 16) | s.u2();
      return utf16.decode(s.bytes(n * 2));
    } catch {
      return '';
    }
  });
}

function typed(type, data, strings) {
  switch (type) {
    case 0x03: return strings[data] ?? '';
    case 0x10: return String(data | 0);
    case 0x11: return `0x${(data >>> 0).toString(16)}`;
    case 0x12: return data ? 'true' : 'false';
    case 0x01: return `@0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case 0x02: return `?0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case 0x04: return String(new Float32Array(new Uint32Array([data]).buffer)[0]);
    default: return `0x${(data >>> 0).toString(16)}`;
  }
}

/** @returns {{ root: { name, attrs, children }, xml: string }} */
export function parseAxml(bytes) {
  const r = new Reader(bytes, true);
  if (r.u2() !== 0x0003) throw new ParseError('ikili XML değil');
  r.u2();
  const total = Math.min(r.u4(), bytes.length);
  let strings = [];
  let ids = [];
  const nsMap = new Map();
  const root = { name: '#document', attrs: [], children: [] };
  const stack = [root];
  let pos = 8;
  let guard = 0;
  while (pos + 8 <= total) {
    if (++guard > 500000) throw new ParseError('AXML çok büyük');
    const c = r.at(pos);
    const type = c.u2();
    const headerSize = c.u2();
    const size = c.u4();
    if (size < 8 || pos + size > bytes.length) throw new ParseError('AXML parça boyutu bozuk');
    if (type === 0x0001) strings = readPool(r, pos);
    else if (type === 0x0180) { const n = (size - headerSize) / 4; const m = r.at(pos + headerSize); ids = Array.from({ length: n }, () => m.u4()); }
    else if (type === 0x0100) { const m = r.at(pos + 16); const prefix = m.u4(); const uri = m.u4(); nsMap.set(strings[uri], strings[prefix]); }
    else if (type === 0x0102) {
      const m = r.at(pos + 16);
      m.u4();
      const name = strings[m.u4()] ?? '?';
      const attrStart = m.u2();
      const attrSize = m.u2();
      const attrCount = m.u2();
      const el = { name, attrs: [], children: [] };
      for (let i = 0; i < attrCount && i < 1000; i++) {
        const a = r.at(pos + 16 + attrStart + i * attrSize);
        const ns = a.u4();
        const nameIdx = a.u4();
        const raw = a.u4();
        a.u2(); a.u1();
        const dtype = a.u1();
        const data = a.u4();
        let aname = strings[nameIdx] ?? '';
        if (!aname && ids[nameIdx]) aname = ATTR_IDS[ids[nameIdx]] ?? `attr_0x${ids[nameIdx].toString(16)}`;
        const prefix = ns !== 0xffffffff ? nsMap.get(strings[ns]) ?? 'ns' : null;
        el.attrs.push({ name: aname, prefix, value: raw !== 0xffffffff ? strings[raw] ?? typed(dtype, data, strings) : typed(dtype, data, strings) });
      }
      stack.at(-1).children.push(el);
      if (stack.length < 64) stack.push(el);
    } else if (type === 0x0103) { if (stack.length > 1) stack.pop(); }
    pos += size;
  }
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  const lines = ['<?xml version="1.0" encoding="utf-8"?>'];
  const walk = (el, depth) => {
    const pad = '  '.repeat(depth);
    const ns = depth === 0 ? [...nsMap].map(([uri, p]) => ` xmlns:${p}="${esc(uri)}"`).join('') : '';
    const attrs = el.attrs.map((a) => ` ${a.prefix ? `${a.prefix}:` : ''}${a.name}="${esc(a.value)}"`).join('');
    if (!el.children.length) { lines.push(`${pad}<${el.name}${ns}${attrs} />`); return; }
    lines.push(`${pad}<${el.name}${ns}${attrs}>`);
    for (const ch of el.children) walk(ch, depth + 1);
    lines.push(`${pad}</${el.name}>`);
  };
  for (const el of root.children) walk(el, 0);
  return { root: root.children[0] ?? null, xml: lines.join('\n') };
}

const attr = (el, name) => el.attrs.find((a) => a.name === name)?.value ?? null;

/** Manifest özeti: paket, sürüm, SDK, izinler, bileşenler (tam sınıf adlarıyla) */
export function manifestSummary(root) {
  if (!root || root.name !== 'manifest') return null;
  const pkg = attr(root, 'package') ?? '';
  const full = (n) => (!n ? n : n.startsWith('.') ? pkg + n : n.includes('.') ? n : `${pkg}.${n}`);
  const out = { package: pkg, versionName: attr(root, 'versionName'), versionCode: attr(root, 'versionCode'), minSdk: null, targetSdk: null, permissions: [], application: null, components: [], debuggable: false, allowBackup: null, cleartext: null };
  for (const el of root.children) {
    if (el.name === 'uses-permission' || el.name === 'uses-permission-sdk-23') { const n = attr(el, 'name'); if (n) out.permissions.push(n); }
    if (el.name === 'uses-sdk') { out.minSdk = attr(el, 'minSdkVersion'); out.targetSdk = attr(el, 'targetSdkVersion'); }
    if (el.name === 'application') {
      out.application = full(attr(el, 'name'));
      out.debuggable = attr(el, 'debuggable') === 'true';
      out.allowBackup = attr(el, 'allowBackup');
      out.cleartext = attr(el, 'usesCleartextTraffic');
      for (const c of el.children) {
        if (!['activity', 'activity-alias', 'service', 'receiver', 'provider'].includes(c.name)) continue;
        const actions = c.children.filter((x) => x.name === 'intent-filter').flatMap((f) => f.children.filter((x) => x.name === 'action').map((x) => attr(x, 'name')).filter(Boolean));
        const exp = attr(c, 'exported');
        out.components.push({ kind: c.name, name: full(attr(c, 'name')), exported: exp === null ? actions.length > 0 : exp === 'true', permission: attr(c, 'permission'), actions });
      }
    }
  }
  return out;
}
