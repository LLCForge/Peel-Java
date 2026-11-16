// İkili AndroidManifest.xml üretici (yalnızca fixture için). UTF-16 dizge havuzu, kaynak kimliği haritası, android ad alanı.
import { Writer } from '../../src/core/bytes.js';

const ANDROID = 'http://schemas.android.com/apk/res/android';
const IDS = { name: 0x01010003, label: 0x01010001, versionCode: 0x0101021b, versionName: 0x0101021c, minSdkVersion: 0x0101020c, targetSdkVersion: 0x01010270, exported: 0x01010010, debuggable: 0x0101000f };

/** el: { name, attrs: [[ad, değer, 'android'?]], children } — değer number ise tamsayı, boolean ise mantıksal */
export function buildAxml(rootEl) {
  const attrNames = [];
  const other = new Set(['android', ANDROID]);
  const walk = (el) => {
    other.add(el.name);
    for (const [n, v, ns] of el.attrs ?? []) {
      if (ns && IDS[n] && !attrNames.includes(n)) attrNames.push(n);
      else if (!ns || !IDS[n]) other.add(n);
      if (typeof v === 'string') other.add(v);
    }
    for (const c of el.children ?? []) walk(c);
  };
  walk(rootEl);
  for (const n of attrNames) other.delete(n);
  const strings = [...attrNames, ...other];
  const si = (s) => strings.indexOf(s);

  const body = new Writer(true);
  // dizge havuzu
  const pool = new Writer(true);
  const data = new Writer(true);
  const offs = strings.map((s) => { const o = data.pos; data.u2(s.length); for (let i = 0; i < s.length; i++) data.u2(s.charCodeAt(i)); data.u2(0); return o; });
  data.align(4);
  pool.u2(0x0001).u2(28).u4(28 + strings.length * 4 + data.pos).u4(strings.length).u4(0).u4(0).u4(28 + strings.length * 4).u4(0);
  for (const o of offs) pool.u4(o);
  pool.bytes(data.done());
  body.bytes(pool.done());
  // kaynak haritası
  body.u2(0x0180).u2(8).u4(8 + attrNames.length * 4);
  for (const n of attrNames) body.u4(IDS[n]);
  // ad alanı
  const ns = () => { body.u4(1).u4(0xffffffff).u4(si('android')).u4(si(ANDROID)); };
  body.u2(0x0100).u2(16).u4(24); ns();
  const el = (e) => {
    const attrs = e.attrs ?? [];
    body.u2(0x0102).u2(16).u4(36 + attrs.length * 20).u4(1).u4(0xffffffff);
    body.u4(0xffffffff).u4(si(e.name)).u2(20).u2(20).u2(attrs.length).u2(0).u2(0).u2(0);
    for (const [n, v, isNs] of attrs) {
      body.u4(isNs ? si(ANDROID) : 0xffffffff).u4(si(n));
      if (typeof v === 'string') body.u4(si(v)).u2(8).u1(0).u1(0x03).u4(si(v));
      else if (typeof v === 'boolean') body.u4(0xffffffff).u2(8).u1(0).u1(0x12).u4(v ? 0xffffffff : 0);
      else body.u4(0xffffffff).u2(8).u1(0).u1(0x10).u4(v);
    }
    for (const c of e.children ?? []) el(c);
    body.u2(0x0103).u2(16).u4(24).u4(1).u4(0xffffffff).u4(0xffffffff).u4(si(e.name));
  };
  el(rootEl);
  body.u2(0x0101).u2(16).u4(24); ns();
  const b = body.done();
  const out = new Writer(true);
  out.u2(0x0003).u2(8).u4(8 + b.length).bytes(b);
  return out.done();
}
