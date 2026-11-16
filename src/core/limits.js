// Tüm sınırlar tek yerde. Amaç: zip bombası, dev sabit havuzu, sonsuz döngülü çözücü ya da derin özyineleme tarayıcıyı
// ya da CLI'yi kilitlemesin. Sınır aşılırsa o parça atlanır ve raporlanır; dosyanın geri kalanı işlenir.
export const LIMITS = Object.freeze({
  inputBytes: 128 * 1024 * 1024, // girdi dosyası
  zipEntries: 50_000, // arşivdeki kayıt sayısı
  zipEntryBytes: 64 * 1024 * 1024, // açılan tek kayıt
  zipTotalBytes: 512 * 1024 * 1024, // açılan kayıtların toplamı
  zipRatio: 400, // sıkıştırma oranı (bomba sezgisi), 1 MB'tan küçük kayıtlara uygulanmaz
  nestedArchives: 8, // AAR içindeki classes.jar/libs/*.jar
  classes: 40_000, // ayrıştırılan sınıf
  constantPool: 65_535,
  codeBytes: 65_535, // JVM yöntem gövdesi üst sınırı (JVMS)
  dexItems: 4_000_000, // DEX tablolarındaki toplam öğe
  interpSteps: 2_000_000, // tek bir çözücü çağrısının komut bütçesi
  interpDepth: 48, // çağrı derinliği
  interpHeap: 8 * 1024 * 1024, // dizi ve dizge öğelerinin toplamı
  interpMs: 1500, // tek çağrı için duvar saati sınırı
  decryptMs: 20_000, // dizge geçişinin toplam süresi
  decryptSites: 200_000,
  outputChars: 6 * 1024 * 1024, // ayrıştırma metni (fazlası kesilir)
  pseudoInsns: 4000, // sözde Java için yöntem başına komut
});
