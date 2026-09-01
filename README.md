# AED-DC Engine
### Autonomous Ephemeral Deception & Deterministic Containment

AED-DC, kurumsal ağ ve sistem altyapılarında iç ağ keşiflerini, port taramalarını ve yetkisiz yatay yayılım (lateral movement) girişimlerini tespit edip engelleyen otonom bir güvenlik, aldatma ve mikro-tecrit platformudur.

---

## Temel Yetenekler

- **Sanal Kör Nokta (Decoy IP):** Ağdaki boş IP havuzunu pasif olarak izler; üzerinde meşru iş yükü bulunmadığı için sıfır yanlış pozitif (zero false-positive) prensibiyle çalışır.
- **Çoklu Protokol Aldatması (Multi-Protocol Trapping):**
  - **Sahte HTTP (Port 80):** Gelen isteklere dinamik sunucu başlıkları (Apache, Nginx, LiteSpeed) ile yanıt verir; `User-Agent`, istek yolu ve metod verilerini toplar.
  - **Sahte SSH (Port 22):** Gerçek OpenSSH servisini yerel IP'ye kilitler; tuzak IP üzerinde standart Port 22'de sahte SSH banner'ı sunarak saldırganın istemci sürümünü yakalar.
- **Dinamik Bal Jetonları (Honeytoken Injection) & Akıllı Rota:**
  - `/.env`, `/config`, `/vault` gibi hassas yolları arayan saldırganlara dinamik sahte AWS anahtarları, PostgreSQL bağlantı dizgileri ve JWT şifreleri sunar.
  - `/robots.txt` arayan saldırganlara sahte tuzak dizin rotaları iletir.
- **Deterministik Çekirdek Tecriti:** Tehdit algılandığı an insan müdahalesine gerek duymadan Linux çekirdeğindeki `nftables` tablosuna `priority -100` ile `DROP` kuralı yazarak saldırganı ağ seviyesinde tecrit eder.
- **İlişkisel Adli Veritabanı (SQLite):** Tüm saldırı olaylarını, zaman damgalarını, çalınan bal jetonlarını ve istemci detaylarını yapılandırılmış `incidents.db` veritabanında indeksli olarak saklar.
- **RESTful Yönetim API'si (FastAPI):** Sistemin uzaktan yönetilmesini, olayların sorgulanmasını, istatistiklerin alınmasını ve çekirdekteki tecrit kurallarının yönetilmesini sağlayan Swagger UI (`/docs`) destekli modern API katmanı.
- **Beyaz Liste (Whitelist) Koruması:** Ağ geçidi ve kritik sunucuların yanlışlıkla engellenmesini önler.

---

## Proje Mimarisi

```text
aed-dc-engine/
├── api/
│   └── app.py              # FastAPI REST API ve Swagger UI yönetim sunucusu
├── database/
│   ├── __init__.py
│   └── db.py               # SQLite ilişkisel adli olay veritabanı sürücüsü
├── core/
│   └── engine.py           # BPF tabanlı çekirdek paket dinleme ve olay motoru
├── containment/
│   └── blocker.py          # Linux nftables deterministik tecrit sürücüsü
├── traps/
│   ├── service_mock.py     # Asenkron sahte HTTP 80 sunucusu ve akıllı rota yöneticisi
│   ├── ssh_mock.py         # Asenkron sahte SSH 22 sunucusu ve banner yakalayıcı
│   ├── honeytokens.py      # Dinamik AWS/DB/JWT bal jetonu üretim fabrikası
│   └── mutator.py          # Dinamik HTTP/SSH sunucu başlığı mutasyon motoru
├── config/
│   └── config.yaml         # IP havuzu, hedef portlar ve beyaz liste ayarları
├── logs/
│   └── detections.json     # JSON tabanlı adli olay kütüğü
├── main.py                 # Çok iş parçacıklı entegre ana başlatıcı
└── requirements.txt        # Python bağımlılıkları
