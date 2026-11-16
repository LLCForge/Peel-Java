// Raporun tek paragraflık özeti (tr | en); yalnızca bulunan bulgulara dayanır.

const LEVEL = {
  tr: { none: 'yok', low: 'düşük', medium: 'orta', high: 'yüksek', critical: 'kritik' },
  en: { none: 'none', low: 'low', medium: 'medium', high: 'high', critical: 'critical' },
};
const KIND = {
  tr: { class: 'sınıf dosyası', jar: 'JAR arşivi', apk: 'Android uygulaması (APK)', aar: 'Android kütüphanesi (AAR)', dex: 'DEX dosyası', zip: 'ZIP arşivi' },
  en: { class: 'class file', jar: 'JAR archive', apk: 'Android app (APK)', aar: 'Android library (AAR)', dex: 'DEX file', zip: 'ZIP archive' },
};

const list = (xs, en) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} ${en ? 'and' : 've'} ${xs.at(-1)}`);

export function summarize(r, lang = 'tr') {
  const en = lang === 'en';
  const parts = [];
  const pct = (c) => (en ? `${Math.round(c * 100)}%` : `%${Math.round(c * 100)}`);
  const name = (d) => `${d.name} (${pct(d.confidence)})`;
  const of = (kind) => r.detection.filter((d) => d.kind === kind);
  const i = r.info;
  if (i) {
    const what = KIND[en ? 'en' : 'tr'][i.kind] ?? i.kind;
    const pkg = r.manifest?.package ? ` ${r.manifest.package}` : '';
    parts.push(en
      ? `${i.name} is a${/^[aeiou]/i.test(what) ? 'n' : ''} ${what}${pkg} with ${i.classes} classes and ${i.methods} methods.`
      : `${i.name}: ${what}${pkg}, ${i.classes} sınıf, ${i.methods} yöntem.`);
  }
  if (r.protection) {
    parts.push(en
      ? `It is packed with ${r.protection.product}; the packed code is not unpacked, only reported.`
      : `Dosya ${r.protection.product} ile paketlenmiş; paketlenmiş kod açılmaz, yalnızca raporlanır.`);
  }
  if (of('obfuscator').length) parts.push(`Obfuscator: ${list(of('obfuscator').map(name), en)}.`);
  if (of('technique').length) parts.push(en ? `Techniques: ${list(of('technique').map((d) => d.name), en)}.` : `Teknikler: ${list(of('technique').map((d) => d.name), en)}.`);
  const s = r.strings;
  const m = r.metrics;
  const done = [[s.decrypted, 'dizge', 'string(s)'], [m.renamed, 'ad', 'name(s)']].filter(([n]) => n > 0).map(([n, tr, e]) => `${n} ${en ? e : tr}`);
  if (done.length) {
    parts.push(en
      ? `Recovered: ${list(done, en)}${s.failed ? `; ${s.failed} call site(s) were left untouched because their decryptor needs something the sandbox does not emulate` : ''}.`
      : `Geri kazanılan: ${list(done, en)}${s.failed ? `; ${s.failed} çağrı yeri, çözücüsü sandbox'ın taklit etmediği bir şeye ihtiyaç duyduğu için olduğu gibi bırakıldı` : ''}.`);
  } else if (s.failed) {
    parts.push(en ? `${s.failed} decryptor call site(s) could not be evaluated and were left untouched.` : `${s.failed} çözücü çağrı yeri değerlendirilemedi ve olduğu gibi bırakıldı.`);
  }
  if (r.readability) parts.push(en ? `Readability ${r.readability.before} → ${r.readability.after}/100.` : `Okunurluk ${r.readability.before} → ${r.readability.after}/100.`);
  const th = r.threat;
  const lv = LEVEL[en ? 'en' : 'tr'][th.level];
  if (th.classes.length) {
    const cls = th.classes.slice(0, 5).map((c) => c.title);
    parts.push(en ? `Capabilities (threat ${lv}, ${th.score}/100): ${list(cls, en)}.` : `Yetenekler (tehdit ${lv}, ${th.score}/100): ${list(cls, en)}.`);
  } else {
    parts.push(en ? 'No risky capability was found (threat level none).' : 'Riskli bir yetenek bulunmadı (tehdit düzeyi yok).');
  }
  const io = r.iocs;
  const counts = [[io.urls, 'URL', 'URL(s)'], [io.domains, 'alan adı', 'domain(s)'], [io.ips, 'IP', 'IP(s)'], [io.emails, 'e-posta', 'e-mail(s)'], [io.discordWebhooks, 'Discord webhook', 'Discord webhook(s)'], [io.telegram, 'Telegram', 'Telegram']]
    .filter(([xs]) => xs?.length).map(([xs, tr, e]) => `${xs.length} ${en ? e : tr}`);
  if (counts.length) parts.push(en ? `IOCs: ${list(counts, en)}.` : `IOC: ${list(counts, en)}.`);
  return parts.join(' ');
}
