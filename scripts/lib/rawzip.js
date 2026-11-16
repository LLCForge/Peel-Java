// Ham ZIP yazıcı (yalnızca fixture için): sıkıştırmasız kayıtlar, aynı adlı kayıtlar ve dizin kayıtları yazılabilir.
// fflate'in nesne tabanlı zipSync'i aynı adı iki kez yazamaz; Paramorphism tarzı hileler için bu gerekir.
import { Writer, crc32 } from '../../src/core/bytes.js';

/** entries: [[ad, Uint8Array]] (ad "/" ile bitiyorsa dizin) */
export function rawZip(entries) {
  const w = new Writer(true, 4096);
  const enc = new TextEncoder();
  const central = [];
  for (const [name, data] of entries) {
    const nb = enc.encode(name);
    const off = w.pos;
    const crc = crc32(data);
    w.u4(0x04034b50).u2(10).u2(0x800).u2(0).u2(0).u2(0x21).u4(crc).u4(data.length).u4(data.length).u2(nb.length).u2(0).bytes(nb).bytes(data);
    central.push({ nb, off, crc, size: data.length, dir: name.endsWith('/') });
  }
  const cd = w.pos;
  for (const c of central) {
    w.u4(0x02014b50).u2(20).u2(10).u2(0x800).u2(0).u2(0).u2(0x21).u4(c.crc).u4(c.size).u4(c.size).u2(c.nb.length).u2(0).u2(0).u2(0).u2(0).u4(c.dir ? 0x10 : 0).u4(c.off).bytes(c.nb);
  }
  const cdSize = w.pos - cd;
  w.u4(0x06054b50).u2(0).u2(0).u2(central.length).u2(central.length).u4(cdSize).u4(cd).u2(0);
  return w.done();
}
