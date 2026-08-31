# AED-DC Engine
### Autonomous Ephemeral Deception & Deterministic Containment

AED-DC, kurumsal ağ ve sistem altyapılarında iç ağ keşiflerini, port taramalarını ve yetkisiz yatay yayılım (lateral movement) girişimlerini tespit edip engelleyen otonom bir güvenlik ve aldatma otomasyonudur.

---

## Temel Yetenekler
- **Sanal Kör Nokta (Decoy IP):** Ağdaki boş IP havuzunu pasif olarak izler; sıfır yanlış pozitif (zero false-positive) ile çalışır.
- **Çoklu Protokol Aldatması (Multi-Protocol Trapping):**
  - **Sahte HTTP (Port 80):** Saldırgana rastgele Apache, Nginx veya LiteSpeed başlıkları dönerek User-Agent ve hedef URL verilerini toplar.
  - **Sahte SSH (Port 22):** Gerçek SSH servisini yerel IP'ye kilitler; tuzak IP'de saldırganın SSH istemci sürümünü yakalar.
- **Deterministik Çekirdek Tecriti:** Tehdit algılandığında insan müdahalesine gerek duymadan Linux çekirdeğindeki `nftables` tablosuna milisaniyeler içinde kural yazarak saldırganı ağ seviyesinde izole eder.
- **Adli Telemetri (Forensic Logging):** Saldırganın kullandığı araçları, zaman damgalarını ve denediği portları yapılandırılmış JSON formatında saklar.
- **Beyaz Liste Koruması:** Ağ geçidi ve kritik sunucuların yanlışlıkla engellenmesini önler.

---

## Proje Mimarisi
- `core/`: Çekirdek BPF ağ dinleyicisi ve olay yürütme motoru (`engine.py`).
- `containment/`: Linux `nftables` tabanlı deterministik izolasyon sürücüsü (`blocker.py`).
- `traps/`: 
  - `service_mock.py`: Asenkron sahte HTTP 80 sunucusu ve delil toplayıcı.
  - `ssh_mock.py`: Asenkron sahte SSH 22 sunucusu ve istemci başlık yakalayıcı.
  - `mutator.py`: Dinamik HTTP ve SSH servis başlığı (banner) mutasyon motoru.
- `config/`: IP havuzu, hedef portlar ve beyaz liste tanımları (`config.yaml`).
- `logs/`: Yapılandırılmış JSON adli olay kayıtları (`detections.json`).
- `main.py`: Çekirdek dinleyici ile sahte servisleri eş zamanlı yöneten ana başlatıcı.

---

## Çalıştırma

```bash
# 1. Sanal ortamı aktif edin
source venv/bin/activate

# 2. Çoklu protokol güvenlik motorunu başlatın (Root yetkisi gerektirir)
sudo ./venv/bin/python main.py
