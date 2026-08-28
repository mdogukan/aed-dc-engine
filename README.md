# AED-DC Engine
### Autonomous Ephemeral Deception & Deterministic Containment

AED-DC, kurumsal ağ ve sistem altyapılarında iç ağ keşiflerini, port taramalarını ve yatay yayılım (lateral movement) girişimlerini tespit edip engelleyen otonom bir güvenlik otomasyonudur.

---

## Nasıl Çalışır?
1. **Sanal Kör Nokta (Decoy IP):** Ağdaki boş IP adreslerini pasif olarak dinler. Bu adreslerde meşru bir iş yükü bulunmadığından yapılan tüm istekler kesin bir anomali kabul edilir.
2. **Deterministik Tespit:** BPF (Berkeley Packet Filter) mekanizması ile CPU tüketmeden gelen ilk bağlantı paketlerini (TCP SYN) yakalar.
3. **Çekirdek Düzeyinde Tecrit:** Tespit anında analist onayına gerek kalmadan Linux çekirdeğindeki `nftables` tablosuna kural yazarak saldırganı ağ seviyesinde tecrit eder.
4. **Hizmet Sürekliliği:** Beyaz liste (whitelist) mekanizması sayesinde ağ geçidi ve kritik sunucuların yanlışlıkla engellenmesini önler.

---

## Modüler Yapı
- `core/`: Çekirdek paket dinleme ve kural yürütme motoru.
- `containment/`: Linux `nftables` tabanlı deterministik izolasyon sürücüsü.
- `traps/`: Dinamik servis yanıltma ve banner mutasyon katmanı.
- `config/`: IP havuzu, hedef portlar ve beyaz liste tanımları.
- `logs/`: Yapılandırılmış JSON formatında adli olay kayıtları.

---

## Çalıştırma

```bash
# Sanal ortamı aktif etme
source venv/bin/activate

# Güvenlik motorunu başlatma (Root yetkisi gereklidir)
sudo ./venv/bin/python core/engine.py

