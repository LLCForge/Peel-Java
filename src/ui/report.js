import { t } from '../i18n.js';
import { h } from './dom.js';

// Analiz raporu görünümü (biçim: src/core/analyze.js). Rapordaki tüm dizgeler incelenen dosyadan gelir ve güvenilmezdir:
// yalnızca textContent ile basılır. Boş bölümler gösterilmez.

const MAX_ROWS = 80;
const kb = (n) => `${((Number(n) || 0) / 1024).toFixed(1)} KB`;
const arr = (v) => (Array.isArray(v) ? v : []);
const str = (v) => (v == null ? '' : String(v));
const section = (title, ...body) => h('section', { class: 'rep-section' }, h('h3', {}, title), ...body);
const LEVELS = ['none', 'low', 'medium', 'high', 'critical'];

function table(headers, rows, classes = []) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'rep-table' },
    h('thead', {}, h('tr', {}, ...headers.map((x) => h('th', { scope: 'col' }, x)))),
    h('tbody', {}, ...rows.slice(0, MAX_ROWS).map((r) => h('tr', {}, ...r.map((c, i) => h('td', { class: classes[i] ?? '' }, str(c))))))),
  rows.length > MAX_ROWS ? h('p', { class: 'rep-muted small' }, t('report.more', { n: rows.length - MAX_ROWS })) : null);
}

function protection(p) {
  if (!p || typeof p !== 'object') return null;
  return h('section', { class: 'rep-section rep-protect', role: 'note' },
    h('h3', {}, t('report.protection')),
    h('p', { class: 'protect-title' }, [str(p.product), str(p.version)].filter(Boolean).join(' ')),
    h('p', {}, t('report.protection.body')),
    arr(p.notes).length ? h('ul', { class: 'rep-list' }, ...arr(p.notes).map((n) => h('li', {}, str(n)))) : null);
}

function threat(th) {
  if (!th || typeof th !== 'object') return null;
  const classes = arr(th.classes);
  const level = LEVELS.includes(th.level) ? th.level : 'none';
  if (!classes.length && !(Number(th.score) > 0)) return null;
  return section(t('report.threat'),
    h('div', { class: `risk risk-${level}` }, h('b', {}, str(Number(th.score) || 0)), h('span', {}, t(`report.risk.${level}`))),
    classes.length ? table([t('report.threat.class'), t('report.threat.evidence')], classes.map((c) => [str(c.title || c.id), arr(c.evidence).map(str).join(' · ')]), ['', 'rep-muted mono']) : null);
}

const KINDS = ['obfuscator', 'packer', 'technique'];
function detection(list) {
  const items = arr(list).filter((x) => x && typeof x === 'object');
  if (!items.length) return null;
  return section(t('report.detect'), h('div', { class: 'detect' }, ...items.map((f) => h('div', { class: 'detect-row' },
    h('span', { class: 'detect-name' }, [str(f.name), str(f.version)].filter(Boolean).join(' '),
      KINDS.includes(f.kind) ? h('small', {}, t(`report.detect.kind.${f.kind}`)) : null,
      h('small', {}, `${Math.round((Number(f.confidence) || 0) * 100)}%`),
      f.decodable === false ? h('small', { class: 'detect-only' }, t('report.detect.reportOnly')) : null),
    h('span', { class: 'detect-ev' }, arr(f.evidence).map(str).join(' · '))))));
}

function info(i, m) {
  if (!i || typeof i !== 'object') return null;
  const dl = h('dl', { class: 'kv' });
  const row = (label, value) => { if (value) dl.append(h('dt', {}, label), h('dd', {}, value)); };
  row(t('report.info.name'), str(i.name));
  row(t('report.metric.kind'), str(i.kind));
  row(t('report.info.types'), `${str(i.classes)} / ${str(i.methods)} / ${str(i.fields)}`);
  if (i.mainClass) row('Main-Class', str(i.mainClass));
  if (m && typeof m === 'object') {
    row(t('report.manifest.package'), [str(m.package), str(m.versionName)].filter(Boolean).join(' '));
    row('SDK', [m.minSdk ? `min ${str(m.minSdk)}` : '', m.targetSdk ? `target ${str(m.targetSdk)}` : ''].filter(Boolean).join(' · '));
    if (m.debuggable) row('debuggable', 'true');
  }
  return section(t('report.info'), dl);
}

function manifest(m) {
  if (!m || typeof m !== 'object') return null;
  const perms = arr(m.permissions);
  const comps = arr(m.components);
  if (!perms.length && !comps.length) return null;
  return section(t('report.manifest'),
    perms.length ? h('div', { class: 'ioc-group' }, h('h4', {}, `${t('report.manifest.permissions')} (${perms.length})`),
      h('ul', { class: 'ioc-list' }, ...perms.slice(0, MAX_ROWS).map((p) => h('li', { class: p.dangerous ? 'perm-danger' : '' }, str(p.name).replace(/^android\.permission\./, ''), p.dangerous ? h('small', {}, ` ${t('report.manifest.dangerous')}`) : null)))) : null,
    comps.length ? h('div', { class: 'ioc-group' }, h('h4', {}, `${t('report.manifest.components')} (${comps.length})`),
      table([t('report.manifest.kind'), t('report.info.name'), t('report.manifest.exported')], comps.map((c) => [str(c.kind), str(c.name), c.exported ? t('ui.yes') : '–']), ['', 'mono', ''])) : null);
}

function strings(s) {
  if (!s || typeof s !== 'object' || !arr(s.decryptors).length) return null;
  const rows = arr(s.decryptors).map((d) => [`${str(d.owner)}.${str(d.name)}${d.array ? '[]' : ''}`, `${str(d.decoded)}/${str(d.sites)}`, arr(d.reasons).map(str).join(' · ')]);
  return section(t('report.strings'),
    h('p', { class: 'rep-note' }, t('report.strings.note', { n: s.decrypted ?? 0, m: s.sites ?? 0 })),
    table([t('report.strings.decryptor'), t('report.strings.sites'), t('report.strings.reason')], rows, ['mono', '', 'rep-muted']),
    arr(s.samples).length ? h('div', { class: 'ioc-group' }, h('h4', {}, t('report.strings.samples')),
      h('ul', { class: 'ioc-list' }, ...arr(s.samples).slice(0, 40).map((v) => h('li', {}, JSON.stringify(str(v.value)))))) : null);
}

function reflection(list, native) {
  const items = arr(list);
  const libs = arr(native);
  if (!items.length && !libs.length) return null;
  return section(t('report.reflection'),
    items.length ? table([t('report.reflection.kind'), 'API', t('report.reflection.where')], items.map((x) => [t(`report.reflection.${x.kind}`), str(x.api), arr(x.where).slice(0, 2).map(str).join(', ')]), ['', 'mono', 'rep-muted mono']) : null,
    libs.length ? h('div', { class: 'ioc-group' }, h('h4', {}, `${t('report.native')} (${libs.length})`),
      table([t('report.native.path'), t('report.native.size')], libs.map((l) => [str(l.path), `${kb(l.size)}${l.elf ? ' · ELF' : ''}`]), ['mono', ''])) : null);
}

function crypto(list) {
  const items = arr(list);
  if (!items.length) return null;
  return section(t('report.crypto'), table([t('report.crypto.algo'), t('report.threat.evidence')], items.map((c) => [str(c.name), arr(c.evidence).map(str).join(' · ')]), ['', 'rep-muted mono']));
}

function packages(list) {
  const items = arr(list);
  if (!items.length) return null;
  return section(t('report.packages'), h('ul', { class: 'ioc-list' }, ...items.slice(0, 40).map((p) => h('li', {}, `${str(p.name)} (${str(p.classes)})`))));
}

function iocs(data) {
  if (!data || typeof data !== 'object') return null;
  const groups = ['urls', 'domains', 'ips', 'emails', 'discordWebhooks', 'telegram'].filter((k) => arr(data[k]).length);
  if (!groups.length) return null;
  return section(t('report.iocs'), ...groups.map((k) => h('div', { class: 'ioc-group' },
    h('h4', {}, `${t(`report.ioc.${k}`)} (${data[k].length})`),
    h('ul', { class: 'ioc-list' }, ...data[k].slice(0, MAX_ROWS).map((v) => h('li', {}, str(v)))))));
}

function metrics(m, r, extra) {
  const dl = h('dl', { class: 'kv' });
  const row = (label, value) => dl.append(h('dt', {}, label), h('dd', {}, value));
  if (r && typeof r === 'object') row(t('report.metric.readability'), `${str(r.before)} → ${str(r.after)} / 100`);
  if (m) {
    row(t('report.metric.size'), `${kb(m.inBytes)} → ${m.rewritten ? kb(m.outBytes) : t('report.metric.notRewritten')}`);
    for (const [k, label] of [['strings', 'strings'], ['renamed', 'renamed'], ['removed', 'removed']])
      if (Number(m[k]) > 0) row(t(`report.metric.${label}`), str(m[k]));
    if (m.rewritten) row(t('report.metric.verified'), t(m.verified ? 'report.verified.yes' : 'report.verified.no'));
  }
  if (extra.ms != null) row(t('report.metric.time'), `${(extra.ms / 1000).toFixed(2)} s`);
  return section(t('report.metrics'), dl);
}

function passTimes(events) {
  const by = new Map();
  for (const e of arr(events)) {
    const p = by.get(e.id) ?? { id: e.id, ms: 0, ok: 0, fail: 0 };
    p.ms += Number(e.ms) || 0;
    if (e.state === 'ok') p.ok++;
    if (e.state === 'fail') p.fail++;
    by.set(e.id, p);
  }
  const list = [...by.values()].sort((a, b) => b.ms - a.ms);
  if (!list.length) return null;
  const max = Math.max(1, ...list.map((p) => p.ms));
  return section(t('report.passes'), h('div', { class: 'bars' }, ...list.map((p) => {
    const bar = h('i');
    bar.style.width = `${Math.max(2, (p.ms / max) * 100)}%`;
    return h('div', { class: 'bar' },
      h('span', {}, p.id),
      h('span', {}, bar),
      h('span', {}, `${p.ms} ms`),
      h('span', { class: p.fail ? 'bar-fail' : 'bar-ok' }, p.fail ? t('report.pass.rolled', { n: p.fail }) : p.ok ? t('report.pass.changed', { n: p.ok }) : '–'));
  })));
}

/**
 * @param {HTMLElement} el
 * @param {object|null} report
 * @param {{ ms?: number, events?: object[], onExport?: () => void }} [extra]
 */
export function renderReport(el, report, extra = {}) {
  el.textContent = '';
  if (!report) {
    el.append(h('p', { class: 'placeholder' }, t('report.empty')));
    return;
  }
  const rep = h('div', { class: 'rep' });
  if (report.summary) rep.append(h('p', { class: 'rep-summary' }, str(report.summary)));
  for (const node of [
    protection(report.protection),
    threat(report.threat),
    detection(report.detection),
    info(report.info, report.manifest),
    strings(report.strings),
    manifest(report.manifest),
    reflection(report.reflection, report.native),
    iocs(report.iocs),
    crypto(report.crypto),
    packages(report.packages),
    metrics(report.metrics, report.readability, extra),
    passTimes(extra.events),
  ]) if (node) rep.append(node);
  if (extra.onExport) rep.append(h('button', { type: 'button', class: 'ghost small rep-export', onclick: extra.onExport }, t('action.export')));
  el.append(rep);
}
