# gokdogan — Mimari Özeti

> **gökdoğan**, avcı şahin (peregrine falcon) demektir — gökyüzünün en hızlı
> avcısı. İsim yerinde: triyaj hızla, hangi örneğin tam analiz hak ettiğine
> saniyeler içinde karar vermektir. (Paket ve komut ASCII `gokdogan`.)

**Statik PE malware triyaj motoru.** Bir Windows çalıştırılabilirini alır,
örneği **hiç çalıştırmadan** statik özelliklerini çıkarır ve şeffaf, ağırlıklı
bir verdikt üretir: `LIKELY_CLEAN`, `SUSPICIOUS` veya `HIGH_RISK`.

- 31 odaklı modülde **~5.200 satır** Python
- **~4.300 satır** test · **345 test** · gerçek binary entegrasyon paketi
- Yanlış-pozitif benchmark'ı ([`scripts/benign_sweep.py`](scripts/benign_sweep.py)): ayarlamada kullanılmamış zararsız dosyaların %2,2'si işaretleniyor (v0.5.2'de %12,7)
- Zorunlu bağımlılık: `pefile`, `ppdeep`, `dnfile` · opsiyonel: `yara-python`, `py-tlsh`

Bu belge motorun *nasıl ve neden* böyle kurulduğunu anlatır. Kullanım için
[README.md](README.md).

---

## 1. Tasarım ilkeleri

Motorun tamamı, onu bir analist için doğru, hızlı ve güvenilir kılan beş karar
etrafında düzenlendi.

| İlke | Kodda karşılığı |
|---|---|
| **Saf fonksiyonlar → dataclass'lar** | Her analizci, `bytes`/`pefile.PE` üzerinde çalışıp dataclass döndüren saf bir fonksiyondur ([`models.py`](gokdogan/models.py)). Analizciler birbirini ya da çıktı formatını tanımaz. Yeni aşama eklemek = bir modül + [`engine.py`](gokdogan/engine.py)'de bir satır. |
| **Varsayılan çevrimdışı** | `triage()` çekirdeği asla ağa dokunmaz, örneği asla çalıştırmaz. Tek çevrimiçi özellik (reputation) opt-in, yalnızca-hash ve CLI katmanındadır — böylece analiz çekirdeği air-gapped bir malware iş istasyonunda güvenlidir. |
| **Denetlenebilir verdikt** | Skorun kendisi rapordur: her puan okunur bir gerekçe taşır ([`verdict.py`](gokdogan/verdict.py)). Analistin itiraz edemeyeceği gizli bir model yoktur. |
| **Yanlış-pozitife karşı kalibre, tek makinede** | Ağırlıklar, bir iş istasyonundaki 2.888 yüklü PE dosyasından rastgele bir örneklem triyaj edilip zararsız yazılımın aldığı verdiktlerin nedenleri giderilerek belirlendi ([`scripts/benign_sweep.py`](scripts/benign_sweep.py)); sonuç aynı makineden ayrı, ayarlamada kullanılmamış ikinci bir örneklemde denetlendi. Capability kuralları yalnızca genel API sayısı değil, belirli API'ler ister; entropi adaları yalnızca yazılabilir bölümlerde tetiklenir; sıkıştırılmış medya kaynakları başlıklarından tanınır. |
| **Zarif düşüş** | Eksik YARA, eksik kural, bozuk kaynak ağacı, çözümlenemeyen import tablosu — her biri çökme değil, raporda bir nota dönüşür. |

---

## 2. Boru hattı

<p align="center">
  <img src="assets/pipeline-tr.png" width="880"
       alt="gokdogan statik boru hattı: bir örnek triyaj aşamalarından geçerek şeffaf ağırlıklı bir verdikte ve çeşitli çıktı formatlarına ulaşır">
</p>

```
                          ┌──────────────────────────────────────────────┐
   sample.exe  ─────────▶ │                 engine.triage()              │
   (çalıştırılmaz)        │                                              │
                          │  loader ─ hashler, imphash, section,         │
                          │           anomali, import, delay-import      │
                          │  rich   ─ araç zinciri hash + checksum        │
                          │  fuzzy  ─ ssdeep / TLSH                       │
                          │  packers ─ bilinen isim + sezgisel           │
                          │  resources ─ gömülü PE, yüksek entropi        │
                          │  blobs  ─ şifreli-config entropi adaları     │
                          │  strings_ext ─ sınıflandırılmış IOC string   │
                          │  decoded ─ XOR/ADD/ROL/base64/hex kurtarma    │
                          │  exports ─ fırlatma mekanizması export'ları  │
                          │  capabilities ─ API+kanıt → davranış etiketi │
                          │  attack ─ capability/YARA → MITRE ATT&CK      │
                          │  yara   ─ ağırlıklı kural eşleşmeleri        │
                          │  verdict ─ şeffaf ağırlıklı skor             │
                          └───────────────────────┬──────────────────────┘
                                                  ▼
      konsol · JSON · HTML · CSV/JSONL · ATT&CK Navigator layer   (+ opt-in reputation)
```

Her aşama bir `TriageReport`'un tek bir dilimini yazar; raporlayıcılar ve
verdikt motoru yalnızca bu yapıyı okur. Sunum ve analiz tamamen ayrıktır.

---

## 3. Modül haritası (31 modül, katmana göre)

**Çekirdek**
- [`engine.py`](gokdogan/engine.py) — orkestratör; tüm `triage()` boru hattı
- [`models.py`](gokdogan/models.py) — her aşamanın paylaştığı dataclass'lar
- [`loader.py`](gokdogan/loader.py) — PE parse, hashler, imphash, yapısal anomaliler, (delay-)import

**Kimlik & kümeleme**
- [`fuzzy.py`](gokdogan/fuzzy.py) — ssdeep + opsiyonel TLSH; `--compare` benzerlik
- [`rich.py`](gokdogan/rich.py) — Rich header hash, `@comp.id` çözümleme, checksum-kurcalama tespiti
- [`hashes.py`](gokdogan/hashes.py) — authentihash (imza-bağımsız) + impfuzzy import hash
- [`cluster.py`](gokdogan/cluster.py) — `--cluster` union-find ile dropzone gruplama
- [`baseline.py`](gokdogan/baseline.py) — `--baseline` bilinen-iyi referansla diff

**Yapı**
- [`entropy.py`](gokdogan/entropy.py) — Shannon entropi + eşikler
- [`packers.py`](gokdogan/packers.py) — bilinen packer bölümleri + yapısal sezgiseller
- [`blobs.py`](gokdogan/blobs.py) — şifreli-config entropi adaları
- [`resources.py`](gokdogan/resources.py) — `.rsrc` gezici: gömülü PE, yüksek-entropi blob
- [`overlay.py`](gokdogan/overlay.py) — overlay içeriği: magic-byte tip, entropi, gömülü PE
- [`signature.py`](gokdogan/signature.py) — Authenticode doğrulama (WinVerifyTrust) + sertifika adları
- [`dotnet.py`](gokdogan/dotnet.py) — .NET: CLR başlığı, obfuscator'lar, metadata referansları, P/Invoke ve IL çağrı noktaları (dnfile)

**İçerik**
- [`strings_ext.py`](gokdogan/strings_ext.py) — ASCII/UTF-16LE çıkarma + IOC sınıflandırma
- [`decoded.py`](gokdogan/decoded.py) — FLOSS-lite: XOR/ADD/ROL/base64/hex string kurtarma
- [`stackstrings.py`](gokdogan/stackstrings.py) — desen-tabanlı x86 stack-string kurtarma (emülatörsüz)
- [`extractors.py`](gokdogan/extractors.py) — aile config çıkarımı (Discord/Telegram/stager URL)

**Davranış & istihbarat**
- [`exports.py`](gokdogan/exports.py) — export tablosu + fırlatma mekanizması tespiti
- [`capabilities.py`](gokdogan/capabilities.py) — API/kanıt → davranış etiketi (capa tarzı)
- [`attack.py`](gokdogan/attack.py) — capability/YARA → MITRE ATT&CK + Navigator layer
- [`yara_scan.py`](gokdogan/yara_scan.py) — opsiyonel yara-python entegrasyonu
- [`reputation.py`](gokdogan/reputation.py) — opt-in VirusTotal / MalwareBazaar hash lookup

**Verdikt & raporlama**
- [`verdict.py`](gokdogan/verdict.py) — şeffaf ağırlıklı skorlama
- [`report.py`](gokdogan/report.py) — ANSI konsol + JSON
- [`html_report.py`](gokdogan/html_report.py) — tek dosya, escape'li, tema-duyarlı HTML
- [`summary.py`](gokdogan/summary.py) — batch CSV/JSONL için sample başına düz satır
- [`misp.py`](gokdogan/misp.py) — threat-intel paylaşımı için MISP event export
- [`web.py`](gokdogan/web.py) — opsiyonel FastAPI upload-and-triage servisi
- [`cli.py`](gokdogan/cli.py) — argparse CLI, çıkış kodları, çıktı yönlendirme

---

## 4. Analiz yüzeyi

<p align="center">
  <img src="assets/analysis-layers-tr.png" width="900"
       alt="gokdogan analiz yüzeyi: beş katman — kimlik, yapı, içerik, davranış, istihbarat — ve her birini besleyen modüller">
</p>

| Eksen | Sinyaller |
|---|---|
| **Kimlik / kümeleme** | MD5·SHA1·SHA256, imphash, Rich-header hash, ssdeep, TLSH |
| **Yapı** | bölüm + genel entropi, entropi adaları, packer tespiti, W+X bölümler, TLS callback, aşırı overlay, silinmiş/gelecek timestamp, checksum uyuşmazlığı |
| **İçerik** | sınıflandırılmış IOC string (URL/IP/domain/registry/PDB/komut/UA), XOR/ADD/ROL/base64/hex-kurtarılmış string, gömülü PE, şifreli-config blob |
| **Davranış** | import + delay-import + export + .NET metadata/P/Invoke capability'leri (injection, keylogging, persistence, anti-debug, anti-recovery, reflective-loading, dropper, …) minimum isabet sayısıyla |
| **İstihbarat** | MITRE ATT&CK teknik eşlemesi (taktik bazlı), YARA, opt-in reputation |

---

## 5. Mühendislik öne çıkanları

Bunlar bir kütüphaneyi birbirine bağlamanın ötesine geçen kararlar — bir
mülakatta anlatmaya değer kısımlar.

**Kodlu string'ler için anahtar-bağımsız komşuluk araması.** 800 KB'lık bir
DLL'de 255 tek-bayt anahtarı × anchor'ları tüm binary üzerinde brute-force
etmek ~2,4 sn sürüyordu. İçgörü: herhangi bir tek-bayt XOR/ADD altında
`encoded[i] ⊕ encoded[i-1]` **anahtardan bağımsızdır**. Tamponu bir kez
dönüştürmek (XOR için bigint kaydırma, C hızında) anahtar tespitini anchor
başına tek bir substring aramasına indirger — **2.440 ms → 133 ms**, tam
kapsam korunarak. ([`decoded.py`](gokdogan/decoded.py))

**Entropi varsayılmadı, ölçüldü.** 256 baytlık pencere rastgeleliği ölçmek
için çok küçüktür: gerçek rastgele veri orada ortalama yalnızca ~7,17 bit
verir (küçük-örneklem yanlılığı), eşik sessizce ulaşılamaz hale gelir.
Dağılımı ölçmek 512 baytlık pencereye (rastgele ≈ 7,5+) ve 7,4 eşiğine
götürdü. ([`blobs.py`](gokdogan/blobs.py))

**Yanlış-pozitifler el sallamayla değil kalibrasyonla giderildi.** Config-blob
tespiti 150 stok imzalı sistem binary'sinde tarandı; salt-okunur `.rdata`
meşru olarak yüksek-entropili sertifika verisi taşır, bu yüzden tarama
yazılabilir bölümlerle sınırlandı → **o 150 dosyada 0 yanlış-pozitif** (aşağıdaki
geniş zararsız taramada entropi adası dosyaların %1'inde yine çıkıyor). Aynı
disiplin kaynak gezicide sıkıştırılmış medyayı başlığından tanır ve bir
capability tetiklenmeden önce belirli API'ler ister.

**Yanlış-pozitifler önce ölçüldü, sonra kaynağında giderildi.** v0.5.2, bir iş
istasyonundaki 2.888 yüklü PE dosyasının %11,8'ini `SUSPICIOUS` veya üstü
buluyordu. [`scripts/benign_sweep.py`](scripts/benign_sweep.py), zararsız
dosyalarda hangi skor gerekçelerinin tetiklendiğini ve işaretlenen dosyalarda
kaç puan taşıdığını çıkarır; her düzeltme tek bir nedene gitti: sahte tarih
sanılan reproducible-build zaman damgaları (dosyaların %58'i), her MSVC
çalışma zamanının bağladığı debugger kontrolleri, keylogging sanılan GUI
klavye çağrıları, bir capability ile bir YARA kuralının aynı kanıtı iki kez
sayması ve büyük programlarda yaygın davranış etiketlerinin toplanması. Her
aday kural devreye girmeden önce bu dosyalarda fiyatlandı; sentetik,
malware biçimli raporlar da tespitin kaybolmasına karşı koruma sağlar.
Ayarlamada kullanılmamış 2.694 başka dosyada oran %12,7'den %2,2'ye indi.
([`verdict.py`](gokdogan/verdict.py), [`capabilities.py`](gokdogan/capabilities.py))

**Aracın kendisinin güvenliği.** Malware string'leri markup içerebilir; HTML
raporu her sample-türevli değeri `html.escape`'ten geçirir, böylece bir rapor
açıldığında gömülü bir `<script>` asla çalışmaz — testle doğrulandı.
([`html_report.py`](gokdogan/html_report.py))

**Çevrimdışı çekirdek, opt-in egress.** Reputation tek ağ özelliğidir.
Varsayılan kapalıdır, yalnızca SHA-256 gönderir (asla dosya), anahtarsız
çalışmayı reddeder (böylece kazara hash sızdırmaz) ve CLI katmanında eklenir —
`triage()` motoru kanıtlanabilir şekilde çevrimdışı kalır.
([`reputation.py`](gokdogan/reputation.py))

---

## 6. Verdikt modeli

<p align="center">
  <img src="assets/verdict-model-tr.png" width="860"
       alt="gokdogan verdikt modeli: LIKELY_CLEAN / SUSPICIOUS / HIGH_RISK spektrumu, eşikler ve temsili toplamsal ağırlıklar">
</p>

Skorlama bilinçli olarak şeffaf ve toplamsaldır; tablonun son satırları
korkulukları gösterir. Temsili ağırlıklar:

| Sinyal | Puan |
|---|---|
| Packer tespit edildi | +15 |
| Yüksek genel entropi (≥ 7,0) | +10 |
| Her yapısal anomali | +6 (TLS callback +2) |
| Bayat PE sağlama toplamı / yüksek entropili overlay, imza kredisi olmayan herhangi bir dosyada | +12 / +10 (aksi halde +6) |
| Capability (şiddet 1 / 2 / 3) | +2 / +8 / +18 (keylogging +8) |
| YARA eşleşmesi | kural `meta.weight`, varsayılan +15 |
| Ağ IOC string'leri | her biri +1, en fazla +5 |
| Kurtarılmış kodlu IOC/payload | +24'e kadar |
| Geçerli Authenticode imzası, gömülü ya da Windows kataloğu üzerinden | −15; sertifika tablosunda doğrulanmamış veri varsa 0 |
| İmza var ama geçerli değil (self-signed, süresi dolmuş, doğrulanmamış) | 0 |
| Paketleme sinyalleri birlikte (packer, entropi, packer YARA, stub anomalileri) | en fazla 30 |
| Kimsenin kefil olmadığı, beş ya da daha az import'lu program | paketleme grubuna tavanı olan 30 ile girer |
| Kimsenin kefil olmadığı, imajının (overlay hariç dosya) entropisi ≥ 7,0 olan program | 30'a yükseltilir |
| Import/export'tan okunan şiddet 1–2 capability'ler, ≥ 200 fonksiyon import eden dosyada | birlikte en fazla 16 |
| `meta.overlaps` ile adı verilen capability ile aynı eşleşen metni okuyan YARA kuralı | yalnızca o capability'nin puanını aşan kısım |

"Kimsenin kefil olmadığı" geçerli imzası olmayan bir GUI ya da konsol programı
demektir (DLL, sürücü ya da önyükleme imajı değil). İki program kuralı ilk
recall ölçümünden geldi: bilinmeyen bir crypter ya da API'sini çalışma anında
çözen bir stager, adı bilinen bir packer kadar opaktır ve motorun onlar için
koyduğu kural (paketleme tek başına `SUSPICIOUS`'a yönlendirir) artık bunları
da kapsar.

Eşikler: **`SUSPICIOUS` ≥ 30**, **`HIGH_RISK` ≥ 60**. Tam döküm her raporda
basılır — analist bir örneğin neden o skoru aldığını tam olarak görür ve YARA
kuralları sezgiselleri geçersiz kılmak için kendi ağırlığını ekleyebilir.

Boru hattı dostu çıkış kodları: `0` temiz · `2` şüpheli · `3` yüksek risk.

---

## 7. Test

**345 test / ~4.300 satır.** Birim testleri her analizciyi sentetik girdilerle
izole eder (elle üretilmiş XOR/base64 payload'ları, sahte PE tamponları,
ekilmiş entropi adaları, sentetik sertifika tabloları, sınıflandırmayı bir
zamanlar karesel yapan düşmanca string'ler). Entegrasyon paketi tüm boru
hattını gerçek sistem binary'lerine (`notepad.exe`, `kernel32.dll`, `mmc.exe`
ve varsa imzalı `chrome.exe`) karşı çalıştırır ve hiçbirinin `HIGH_RISK`
almadığını doğrular; v0.5.2'de `mmc.exe` ve `chrome.exe` alıyordu (83 ve 79).
Tespit koruması ([`tests/archetypes.py`](tests/archetypes.py)) on iki
sentetik, malware biçimli raporu skorlar ve kalibrasyon herhangi birini
v0.5.2'nin verdiği verdiktin altına düşürürse başarısız olur (belgelenmiş
tek bir istisna ile). Ağ kodu enjekte HTTP mock'larıyla test edilir — gerçek
dış çağrı yoktur.

Yanlış-pozitif benchmark'ı `pytest`'in parçası değil, ayrı bir betiktir:
[`scripts/benign_sweep.py`](scripts/benign_sweep.py) yüklü PE dosyalarını
triyaj eder, her birini zararsız sayar ve işaretleme oranını, arkasındaki
gerekçeleri ve en kötü dosyaları raporlar. Benchmark'ın yalnızca zararsız
yarısını ölçer. Recall, izole bir laboratuvarda
[`scripts/recall_sweep.py`](scripts/recall_sweep.py) ile ölçülür
([BENCHMARK.md](BENCHMARK.md)): dört MalwareBazaar günlük arşivi (75 aileden
445 EXE/DLL) üzerindeki ilk koşu, ayrılmış kısmının %55,3'ünü (83/150)
işaretledi. Ayarlama kısmından yapılan skor değişiklikleri, aynı örnekler
üzerindeki ikinci koşuda bu oranı %71,3'e (107/150) çıkardı; ilk koşunun
işaretlediği hiçbir örnek kaçmadı.

---

## 8. Teknoloji yığını

Python 3.10+ · `pefile` (PE parse) · `ppdeep` (saf-Python ssdeep) · `dnfile` (.NET metadata) · opsiyonel
`yara-python`, `py-tlsh` · reputation için standart kütüphane `urllib`. Web
framework yok, ağır bağımlılık yok — malware-lab akışına giren, kendi kendine
yeten bir CLI.

---

*gokdogan yalnızca statik triyaj yapar. Örneği asla çalıştırmaz ve verdikti
kesin bir sınıflandırma değil, bir önceliklendirme sinyalidir. Gerçek
malware'i izole bir analiz VM'inde ele alın.*
