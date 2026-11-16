// ZIP okuyucu (JAR, APK, AAR). Merkezi dizin elle okunur: Paramorphism tarzı hileler (aynı adlı kayıtlar, "x.class/"
// dizin kayıtları, yalan boyutlar) görünür kalır ve rapora girer. Açma fflate ile, bildirilen boyutta önceden ayrılmış
// tamponla yapılır; bildirilen boyut, oran ve toplam sınırları aşan kayıt açılmaz (zip bombası).
import { inflateSync, zipSync } from 'fflate';
import { Reader, ParseError, decodeMutf8 } from './bytes.js';
import { LIMITS } from './limits.js';

const utf8 = new TextDecoder('utf-8');
export const isZip = (b) => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5) && (b[3] === 4 || b[3] === 6);

/**
 * @returns {{ entries: { name, size, csize, method, offset, dir, encrypted, dup }[], notes: string[] }}
 */
export function listZip(bytes) {
  const r = new Reader(bytes, true);
  // dizin sonu kaydı: sondan en fazla 64 KB yorum geriye aranır
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 0xffff); i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 5 && bytes[i + 3] === 6) { eocd = i; break; }
  }
  if (eocd < 0) throw new ParseError('ZIP dizin sonu bulunamadı');
  const e = r.at(eocd + 10);
  const count = e.u2();
  const cdSize = e.u4();
  const cdOff = e.u4();
  const notes = [];
  if (count === 0xffff || cdOff === 0xffffffff) throw new ParseError('ZIP64 arşivleri desteklenmiyor');
  if (count > LIMITS.zipEntries) throw new ParseError(`çok fazla kayıt (${count})`);
  if (cdOff + cdSize > bytes.length) throw new ParseError('merkezi dizin dosya dışında');
  const entries = [];
  const seen = new Map();
  const c = r.at(cdOff);
  for (let i = 0; i < count; i++) {
    if (c.u4() !== 0x02014b50) throw new ParseError(`bozuk merkezi dizin kaydı #${i}`);
    c.pos += 4;
    const flags = c.u2();
    const method = c.u2();
    c.pos += 8;
    const csize = c.u4();
    const size = c.u4();
    const nlen = c.u2();
    const xlen = c.u2();
    const klen = c.u2();
    c.pos += 8;
    const offset = c.u4();
    const raw = c.bytes(nlen);
    c.pos += xlen + klen;
    let name;
    try { name = flags & 0x800 ? utf8.decode(raw) : decodeMutf8(raw); } catch { name = decodeMutf8(raw); }
    const entry = { name, size, csize, method, offset, dir: name.endsWith('/'), encrypted: Boolean(flags & 1), dup: seen.has(name) };
    if (entry.dup) entries[seen.get(name)].dup = true;
    else seen.set(name, entries.length);
    entries.push(entry);
  }
  return { entries, notes };
}

/** Tek kaydı açar; sınır aşımında ya da desteklenmeyen biçimde neden döner */
export function readEntry(bytes, entry, budget = { left: LIMITS.zipTotalBytes }) {
  if (entry.dir) return { error: 'dizin' };
  if (entry.encrypted) return { error: 'şifreli kayıt' };
  if (entry.size > LIMITS.zipEntryBytes) return { error: `çok büyük (${entry.size} bayt)` };
  if (entry.size > budget.left) return { error: 'toplam açma sınırı aşıldı' };
  if (entry.size > 1024 * 1024 && entry.csize > 0 && entry.size / entry.csize > LIMITS.zipRatio) return { error: `şüpheli sıkıştırma oranı (${Math.round(entry.size / entry.csize)}:1)` };
  const r = new Reader(bytes, true, entry.offset);
  try {
    if (r.u4() !== 0x04034b50) return { error: 'yerel başlık bozuk' };
    r.pos += 22;
    const nlen = r.u2();
    const xlen = r.u2();
    r.pos += nlen + xlen;
    const data = r.bytes(Math.min(entry.csize, bytes.length - r.pos));
    budget.left -= entry.size;
    if (entry.method === 0) return { data: data.slice(0, entry.size) };
    if (entry.method !== 8) return { error: `desteklenmeyen sıkıştırma (${entry.method})` };
    const out = inflateSync(data, { out: new Uint8Array(entry.size) });
    // fflate bildirilen tampona sığmayan veriyi büyütür: boyut yalanı da sınırla denetlenir
    if (out.length > LIMITS.zipEntryBytes) return { error: 'açılan veri sınırı aştı' };
    return { data: out.length === entry.size ? out : out.slice(0, entry.size) };
  } catch (e) {
    return { error: e instanceof ParseError ? e.message : `açılamadı (${e.message})` };
  }
}

/** Sıralı kayıtlardan ZIP üretir: [[ad, bayt]] */
export function writeZip(files) {
  const obj = {};
  for (const [name, data] of files) obj[name] = [data, { level: /\.(png|jpe?g|so|zip|jar|gz)$/i.test(name) ? 0 : 6, mtime: new Date(1980, 0, 1) }];
  return zipSync(obj);
}
