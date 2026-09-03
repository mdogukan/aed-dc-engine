# AED-DC Engine (Autonomous Cyber Deception & Kernel Containment Engine)

AED-DC Engine, kurumsal ağlar için tasarlanmış; saldırganı pasif keşif aşamasından itibaren saptayan, dinamik bal tuzaklarıyla (honeypot/decoy) oltalayan ve Linux çekirdek seviyesinde (nftables timeout sets) otonom olarak tecrit eden yeni nesil bir **Siber Aldatma ve Adli Bilişim (Deception & Containment)** platformudur.

Sistem, sahte IP havuzlarını dinleyerek **sıfır yanlış alarm (zero false-positive)** prensibiyle çalışır.

---

## Sistem Mimarisi

- **Paket Yakalama (Kernel Promiscuous):** Scapy tabanlı ham soket dinleyicisi (ens33).
- **Yem Servisleri (Decoys):** Port 80 (Sahte .env API sızıntısı) ve Port 22 (Ubuntu OpenSSH Banner).
- **Çekirdek Tecrit Motoru:** nftables inet aed_filter @isolated_ips timeout kuralı ile O(1) hızında paket düşürme.
- **Adli Delil Deposu (Forensics):** TCP bayrakları, TTL, pencere boyutu ve HTTP başlıklarını JSON olarak saklayan SQLite altyapısı.
- **Canlı Operasyon Konsolu:** Thread-safe WebSocket telemetrisi ile F5 gerektirmeyen gerçek zamanlı izleme paneli.

---

## Temel Yetenekler

1. **Çekirdek Düzeyinde Tecrit (Kernel-Level Containment):** Bellek kümelerinde (sets) otomatik TTL geri sayımı ile sıfır CPU yükü.
2. **Kademeli Yargılama ve Eşik Denetimi (Rate Limiting):** Tekil pingler ve kapalı port yoklamaları sessizce gözlemlenir (RECON_DETECTED / PROBE_DETECTED). 5 saniyede 5 ICMP veya 3 SYN paketinde IP çekirdekte mühürlenir.
3. **Yüksek Etkileşimli Yem Servisleri:** Saldırgana sahte AWS/JWT anahtarları servis edilerek profil çıkartılır ve temas anında tecrit edilir.
4. **Dinamik Ceza Ölçeklendirmesi (Multi-Strike TTL):** 1. ihlalde 1 saat, mükerrer ihlallerde 6 ve 48 saatlik ceza süreleri.
5. **Adli Raporlama:** Tek tıkla SIEM ve SOC uyumlu JSON ve CSV formatında dışa aktarım.

---

## REST API Uç Noktaları

- `GET /api/incidents` : Güncel adli olayları listeler.
- `GET /api/blocked-ips` : Çekirdekte tecrit edilen IP listesini döner.
- `POST /api/unblock/{ip}` : IP engelini hem çekirdekten hem panelden kaldırır.
- `GET /api/export/json` : Adli kayıtları JSON raporu olarak indirir.
- `GET /api/export/csv` : Adli kayıtları CSV formatında indirir.
- `WS /ws/stream` : Canlı telemetri akışı için WebSocket soketi.
