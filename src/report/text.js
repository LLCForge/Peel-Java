// Rapor modüllerinin ortak yardımcıları. Tarayıcıda da çalışır (Node'a özgü API yok).

export const t = (tr, en = tr) => ({ tr, en });
export const pick = (o, lang) => (lang === 'en' ? o.en : o.tr);

/** Antivirüs imzalarına takılmasın diye şüpheli dizgeler kaynakta parçalı yazılır: rx(['Virtual', 'AllocEx']) */
export const rx = (parts, flags = '') => new RegExp(parts.join(''), flags);

/** Kanıt için tek satırlık, kısaltılmış kesit */
export function snippet(s, max = 120) {
  const one = String(s).replace(/\s+/g, ' ').trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

export const LEVELS = ['none', 'low', 'medium', 'high', 'critical'];
export const levelOf = (score) => (score <= 0 ? 'none' : score < 25 ? 'low' : score < 50 ? 'medium' : score < 75 ? 'high' : 'critical');

const LEVEL = {
  tr: { none: 'yok', low: 'düşük', medium: 'orta', high: 'yüksek', critical: 'kritik' },
  en: { none: 'none', low: 'low', medium: 'medium', high: 'high', critical: 'critical' },
};

/** Düz metin rapor (CLI --report text) */
export function reportText(r, lang = r?.lang ?? 'tr') {
  const en = lang === 'en';
  const L = (tr, e) => (en ? e : tr);
  const pct = (c) => (en ? `${Math.round(c * 100)}%` : `%${Math.round(c * 100)}`);
  const lines = [];
  lines.push(`${L('Özet', 'Summary')}: ${r.summary}`);
  lines.push(`${L('Tehdit', 'Threat')}: ${LEVEL[en ? 'en' : 'tr'][r.threat.level]} (${r.threat.score}/100)`);
  for (const c of r.threat.classes) {
    lines.push(`  - ${c.title}`);
    for (const e of c.evidence) lines.push(`      ${e}`);
  }
  if (r.protection) {
    lines.push(`${L('Paketleyici', 'Packer')}: ${r.protection.product} (${L('açılmaz, yalnızca rapor', 'not unpacked, report only')})`);
    for (const n of r.protection.notes) lines.push(`  - ${n}`);
  }
  if (r.detection.length) {
    lines.push(`${L('Tespitler', 'Detections')}:`);
    for (const d of r.detection) {
      lines.push(`  - ${d.name} [${d.kind}] ${pct(d.confidence)}${d.decodable ? '' : L(' (yalnızca rapor)', ' (report only)')}`);
      for (const e of d.evidence) lines.push(`      ${e}`);
    }
  }
  const s = r.strings;
  if (s.decryptors.length) {
    lines.push(`${L('Dizge çözücüler', 'String decryptors')}: ${s.decrypted}/${s.sites}`);
    for (const d of s.decryptors) lines.push(`  - ${d.owner}.${d.name}${d.array ? '[]' : d.desc}: ${d.decoded}/${d.sites}${d.reasons.length ? ` · ${d.reasons.join('; ')}` : ''}`);
  }
  const m = r.manifest;
  if (m) {
    lines.push(`Manifest: ${m.package}${m.versionName ? ` ${m.versionName}` : ''}${m.minSdk ? ` · minSdk ${m.minSdk}` : ''}${m.targetSdk ? ` · targetSdk ${m.targetSdk}` : ''}${m.debuggable ? ' · debuggable' : ''}`);
    for (const p of m.permissions) lines.push(`  ${L('izin', 'permission')}: ${p.name}${p.dangerous ? ` (${L('tehlikeli', 'dangerous')})` : ''}`);
    for (const c of m.components) lines.push(`  ${c.kind}: ${c.name}${c.exported ? ` (${L('dışa açık', 'exported')})` : ''}`);
  }
  if (r.reflection.length) {
    lines.push(`${L('Yansıma / dinamik yükleme / yerel', 'Reflection / dynamic loading / native')}:`);
    for (const x of r.reflection.slice(0, 30)) lines.push(`  - [${x.kind}] ${x.api}${x.where.length ? ` · ${x.where.slice(0, 2).join(', ')}` : ''}`);
  }
  if (r.native.length) {
    lines.push(`${L('Yerel kütüphaneler', 'Native libraries')}:`);
    for (const n of r.native) lines.push(`  - ${n.path} (${n.size} ${L('bayt', 'bytes')}${n.elf ? ', ELF' : ''})`);
  }
  if (r.crypto.length) {
    lines.push(`${L('Kripto', 'Crypto')}:`);
    for (const c of r.crypto) lines.push(`  - ${c.name}: ${c.evidence.join('; ')}`);
  }
  if (r.packages.length) lines.push(`${L('Paketler', 'Packages')}: ${r.packages.slice(0, 12).map((p) => `${p.name} (${p.classes})`).join(', ')}`);
  const io = r.iocs;
  const keys = ['urls', 'domains', 'ips', 'emails', 'discordWebhooks', 'telegram', 'downloads', 'benign'];
  if (keys.some((k) => io[k]?.length)) {
    lines.push('IOC:');
    for (const k of keys) if (io[k]?.length) lines.push(`  ${k}: ${io[k].join(', ')}`);
  }
  const x = r.metrics;
  lines.push(`${L('Okunurluk', 'Readability')}: ${r.readability.before} → ${r.readability.after}/100`);
  lines.push(`${L('Ölçüler', 'Metrics')}: ${x.inBytes} → ${x.outBytes} ${L('bayt', 'bytes')}, ${L('sınıf', 'classes')} ${x.classes}, ${L('dizge', 'strings')} ${x.strings}, ${L('ad', 'names')} ${x.renamed}, ${L('yapısal doğrulama', 'structural check')} ${x.verified ? L('geçti', 'passed') : x.rewritten ? L('başarısız', 'failed') : L('yok (DEX yeniden yazılmaz)', 'n/a (DEX is not rewritten)')}`);
  return `${lines.join('\n')}\n`;
}
