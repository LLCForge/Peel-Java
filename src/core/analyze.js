// Analiz raporu. Arayüz, CLI ve kütüphane bu biçimi kullanır; alanlar eklenebilir, var olanlar değişmez.
//
// Report = {
//   info:        { name, kind: 'class'|'jar'|'apk'|'aar'|'dex'|'zip', classes, methods, fields, dexes, size, mainClass }
//   detection:   [{ id, name, kind: 'obfuscator'|'packer'|'technique', confidence (0-1), decodable, evidence: string[] }]
//   protection:  null | { product, decodable: false, notes: string[] }   bilinen Android paketleyicisi: yalnızca tanınır
//   threat:      { score (0-100), level: 'none'|'low'|'medium'|'high'|'critical', classes: [{ id, title, weight, evidence }] }
//   manifest:    null | { package, versionName, versionCode, minSdk, targetSdk, debuggable, allowBackup, cleartext,
//                         permissions: [{ name, dangerous }], components: [{ kind, name, exported, permission, actions }] }
//   strings:     { decrypted, sites, failed, decryptors: [{ owner, name, desc, array, sites, decoded, failed, reasons }],
//                  samples: [{ where, value }] }
//   reflection:  [{ kind: 'reflection'|'dynamic-loading'|'native'|'exec', api, where: string[] }]
//   crypto:      [{ id, name, evidence: string[] }]
//   native:      [{ path, abi, name, size, elf }]
//   packages:    [{ name, classes }]
//   iocs:        { urls, domains, ips, emails, discordWebhooks, telegram, downloads, benign: string[] }
//   readability: { before, after }   0-100
//   metrics:     { inBytes, outBytes, classes, methods, strings, renamed, verified, rewritten, removed }
//   summary:     string
//   lang:        'tr'|'en'
// }
import { detect } from '../report/detect.js';
import { threat as assessThreat } from '../report/threat.js';
import { iocs as findIocs } from '../report/iocs.js';
import { summarize } from '../report/summary.js';
import { mainClassOf } from './program.js';
import { translate } from '../report/en.js';

const DANGEROUS = new Set(['SEND_SMS', 'READ_SMS', 'RECEIVE_SMS', 'RECEIVE_MMS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
  'ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'CAMERA', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'CALL_PHONE', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS',
  'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE', 'GET_ACCOUNTS', 'BODY_SENSORS', 'READ_CALENDAR', 'WRITE_CALENDAR',
  'PROCESS_OUTGOING_CALLS', 'ANSWER_PHONE_CALLS', 'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES', 'BIND_ACCESSIBILITY_SERVICE', 'BIND_DEVICE_ADMIN']);

/**
 * @param {object} r deobfuscate() sonucu
 * @param {{ inBytes?: number, lang?: 'tr'|'en' }} o
 */
export function analyze(r, { inBytes = 0, lang = 'tr' } = {}) {
  lang = lang === 'en' ? 'en' : 'tr';
  const { prog, facts, results } = r;
  const s = results.strings ?? { strings: 0, sites: 0, decryptors: [], failures: [], values: [] };
  const decrypted = s.values.map((v) => v.value);
  const detection = detect(prog, facts, { decryptors: s.decryptors, mapping: r.mapping, lang });
  const packers = detection.filter((d) => d.kind === 'packer');
  const allStrings = [...facts.strings, ...decrypted];
  const iocs = findIocs([...allStrings, prog.manifest?.xml ?? '', prog.jarManifest ?? '']);
  const ms = prog.manifest?.summary ?? null;
  const manifest = ms ? { ...ms, permissions: ms.permissions.map((p) => ({ name: p, dangerous: DANGEROUS.has(p.replace(/^android\.permission\./, '')) })) } : null;
  const methods = prog.classes.reduce((n, c) => n + c.cf.methods.length, 0) + prog.dexes.reduce((n, d) => n + d.dex.classes.reduce((k, c) => k + c.directMethods.length + c.virtualMethods.length, 0), 0);
  const fields = [...facts.model.values()].reduce((n, c) => n + c.fields.length, 0);
  const report = {
    info: { name: prog.name, kind: prog.kind, classes: facts.model.size, methods, fields, dexes: prog.dexes.length, size: prog.size, mainClass: mainClassOf(prog)?.replaceAll('/', '.') ?? null },
    detection,
    protection: packers.length ? { product: packers.map((d) => d.name).join(', '), decodable: false, notes: packers.flatMap((d) => d.evidence).slice(0, 6) } : null,
    threat: assessThreat({ manifest: ms, refs: facts.refs, strings: allStrings, iocs }, lang),
    manifest,
    strings: {
      decrypted: s.strings,
      sites: s.sites,
      failed: s.sites - s.strings,
      decryptors: s.decryptors.map((d) => ({ ...d, owner: d.owner.replace(/^L|;$/g, '').replaceAll('/', '.'), reasons: d.reasons.map((x) => translate(x, lang)) })),
      samples: s.values.slice(0, 200),
    },
    reflection: facts.reflection,
    crypto: facts.crypto.map((c) => ({ ...c, evidence: c.evidence.map((e) => translate(e, lang)) })),
    native: prog.nativeLibs,
    packages: facts.packages.slice(0, 40),
    iocs,
    readability: r.readability,
    metrics: {
      inBytes,
      outBytes: r.bytes?.length ?? 0,
      classes: facts.model.size,
      methods,
      strings: s.strings,
      renamed: (r.stats.classes ?? 0) + (r.stats.methods ?? 0) + (r.stats.fields ?? 0),
      verified: Boolean(r.verified),
      rewritten: Boolean(r.rewritten),
      removed: r.removed?.length ?? 0,
    },
    lang,
    summary: '',
  };
  report.summary = summarize(report, lang);
  return report;
}
