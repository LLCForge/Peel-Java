// Tehdit analizi (Java/Android). Kanıt kaynakları: manifest izinleri ve bileşenleri, başvurulan API'ler, dizge
// sabitleri (çözülmüş dizgeler dahil) ve IOC'ler. Bu bir yetenek göstergesidir, hüküm değildir: meşru uygulamalar da
// SMS ya da erişilebilirlik kullanabilir. Şüpheli dizgeler kaynakta parçalı yazılır (antivirüs imzalarına takılmasın).
import { levelOf, pick, rx, t } from './text.js';

export const CLASSES = {
  'sms-send': t('SMS gönderme', 'Sending SMS'),
  'sms-read': t('SMS okuma / yakalama', 'Reading / intercepting SMS'),
  accessibility: t('Erişilebilirlik hizmeti (ekran okuma / tıklama)', 'Accessibility service (screen reading / clicking)'),
  'device-admin': t('Cihaz yöneticisi', 'Device administrator'),
  overlay: t('Diğer uygulamaların üstünde pencere', 'Drawing over other apps'),
  'dynamic-loading': t('Çalışma anında kod yükleme', 'Runtime code loading'),
  'process-exec': t('Kabuk komutu çalıştırma', 'Shell command execution'),
  root: t('Root erişimi denemesi', 'Root access attempt'),
  persistence: t('Açılışta başlama', 'Start on boot'),
  exfiltration: t('Veri sızdırma kanalı (Discord/Telegram)', 'Exfiltration channel (Discord/Telegram)'),
  'sensitive-data': t('Hassas veri erişimi (kişiler, konum, arama kaydı, mikrofon)', 'Sensitive data access (contacts, location, call log, microphone)'),
  'install-packages': t('Başka uygulama kurma', 'Installing other apps'),
  'anti-analysis': t('Analiz/emülatör tespiti', 'Anti-analysis / emulator detection'),
};

const P = (s) => `android.permission.${s}`;
const any = (list, re) => list.filter((s) => re.test(s));
const ROOT = rx(['/system/(x?bin|sbin)/', 'su\\b|\\bsu -c|Superuser\\.', 'apk|com\\.topjohnwu\\.', 'magisk'], 'i');
const EMU = rx(['generic_x86|goldfish|ranchu|sdk_gphone|Genymotion|', 'de\\.robv\\.android\\.xposed|frida-', 'server|/proc/self/maps'], 'i');
const HOOK = rx(['discord(?:app)?\\.com/api/(?:v\\d+/)?', 'webhooks/'], 'i');

/**
 * @param {{ manifest: object|null, refs: Map, strings: string[], iocs: object }} o
 */
export function threat({ manifest, refs, strings, iocs }, lang = 'tr') {
  const en = lang === 'en';
  const L = (tr, e) => (en ? e : tr);
  const perms = new Set(manifest?.permissions ?? []);
  const comps = manifest?.components ?? [];
  const keys = [...refs.keys()];
  const has = (re) => keys.filter((k) => re.test(k)).map((k) => k.replaceAll('/', '.'));
  const found = [];
  const add = (id, weight, evidence) => { if (evidence.length) found.push({ id, title: pick(CLASSES[id], lang), weight, evidence: [...new Set(evidence)].slice(0, 5) }); };
  const perm = (...names) => names.filter((n) => perms.has(P(n))).map((n) => `${L('izin', 'permission')}: ${n}`);

  add('sms-send', 30, [...perm('SEND_SMS'), ...has(/^android\/telephony\/SmsManager\.(sendTextMessage|sendMultipartTextMessage|sendDataMessage)$/)]);
  add('sms-read', 25, [...perm('READ_SMS', 'RECEIVE_SMS'), ...comps.filter((c) => c.actions.some((a) => /SMS_RECEIVED/.test(a))).map((c) => `${L('alıcı', 'receiver')}: ${c.name}`)]);
  add('accessibility', 30, comps.filter((c) => c.permission === P('BIND_ACCESSIBILITY_SERVICE') || c.actions.includes('android.accessibilityservice.AccessibilityService')).map((c) => `${L('hizmet', 'service')}: ${c.name}`));
  add('device-admin', 25, [...comps.filter((c) => c.permission === P('BIND_DEVICE_ADMIN')).map((c) => `${L('alıcı', 'receiver')}: ${c.name}`), ...has(/^android\/app\/admin\/DevicePolicyManager\.(lockNow|wipeData|resetPassword)$/)]);
  add('overlay', 15, perm('SYSTEM_ALERT_WINDOW'));
  add('dynamic-loading', 25, [...has(/^dalvik\/system\/(DexClassLoader|InMemoryDexClassLoader|PathClassLoader|DexFile)\.|^java\/net\/URLClassLoader\.|^java\/lang\/ClassLoader\.defineClass$/),
    ...any(strings, /^dalvik[./]system[./](DexClassLoader|InMemoryDexClassLoader|PathClassLoader|DexFile)$|^java[./]net[./]URLClassLoader$/).map((s) => `${L('dizge (yansımayla)', 'string (via reflection)')}: "${s}"`)]);
  add('process-exec', 20, has(/^java\/lang\/Runtime\.exec$|^java\/lang\/ProcessBuilder\.start$/));
  add('root', 15, any(strings, ROOT).map((s) => `"${s.slice(0, 60)}"`));
  add('persistence', 10, [...perm('RECEIVE_BOOT_COMPLETED'), ...comps.filter((c) => c.actions.some((a) => /BOOT_COMPLETED/.test(a))).map((c) => `${L('alıcı', 'receiver')}: ${c.name}`)]);
  add('exfiltration', 30, [...(iocs.discordWebhooks ?? []), ...(iocs.telegram ?? []), ...any(strings, HOOK).map((s) => s.slice(0, 80))]);
  add('sensitive-data', 10, perm('READ_CONTACTS', 'ACCESS_FINE_LOCATION', 'READ_CALL_LOG', 'RECORD_AUDIO', 'CAMERA', 'READ_PHONE_STATE', 'GET_ACCOUNTS'));
  add('install-packages', 20, [...perm('REQUEST_INSTALL_PACKAGES', 'INSTALL_PACKAGES'), ...any(strings, /^application\/vnd\.android\.package-archive$/).map((s) => `"${s}"`)]);
  add('anti-analysis', 10, [...has(/^android\/os\/Debug\.isDebuggerConnected$/), ...any(strings, EMU).map((s) => `"${s.slice(0, 60)}"`)]);
  const score = Math.min(100, found.reduce((s, c) => s + c.weight, 0));
  return { score, level: levelOf(score), classes: found.sort((a, b) => b.weight - a.weight) };
}
