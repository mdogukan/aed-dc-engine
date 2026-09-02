# AED-DC Engine (Otonom Tehdit İzleme, Aldatma ve Tecrit Motoru)

AED-DC Engine; kurumsal ağlarda yetkisiz tarama, sızma ve keşif girişimlerini dinamik tuzaklar (honeypot) ile saptayan, çekirdek (kernel) seviyesinde `nftables` kuralları ile saldırganı anında izole eden ve tüm adli delilleri gerçek zamanlı olarak görselleştiren otonom bir aktif savunma sistemidir.

---

## Temel Özellikler

* **Çekirdek Düzeyinde Ağ Dinleme (BPF):** Scapy tabanlı paket analiz motoru ile ağ üzerindeki şüpheli SYN ve port tarama hareketlerinin düşük gecikmeyle yakalanması.
* **Dinamik Aldatma Servisleri (Decoy Traps):** 
  * Asenkron HTTP bal jetonu (Honeytoken) tuzağı (`.env`, `robots.txt` ve mutasyonlu banner yanıtları).
  * Asenkron SSH tuzağı ile yetkisiz kaba kuvvet (brute-force) girişimlerinin adli kaydı.
* **Çekirdek Seviyesinde Otonom Tecrit:** `nftables` kanca zincirleri (`inet aed_filter aed_isolation`) aracılığıyla tespit edilen saldırgan IP adreslerinin sistem seviyesinde `DROP` kuralı ile anında engellenmesi.
* **Kalıcı Adli Veri Kaydı:** Yakalanan tüm adli delillerin (kaynak IP, port, hedef, HTTP başlıkları, kullanıcı ajanları) zaman damgalı olarak SQLite veritabanında saklanması.
* **Gerçek Zamanlı Telemetri ve Web Paneli:**
  * FastAPI ve WebSocket (`/ws/threats`) ile sayfayı yenilemeden tarayıcıya itilen canlı saldırı akışı.
  * Sayfa ilk açıldığında geçmiş olayları ve mevcut `nftables` engellerini REST uç noktalarından çeken hibrit kontrol paneli (`/`).
* **Asenkron Dış Bildirim Motoru:** Kritik tecrit kararlarını dış webhook ve sistemlere `httpx` üzerinden asenkron ileten bildirim mimarisi.

---

## Mimari Bileşenler

```text
aed-dc-engine/
├── alerts/
│   └── notifier.py         # Asenkron HTTP bildirim motoru (httpx)
├── api/
│   ├── app.py              # FastAPI REST uç noktaları (/api/incidents, /api/containment/*)
│   ├── panel.html          # WebSocket ve REST tabanlı canlı adli izleme arayüzü
│   └── ws_manager.py       # Çift yönlü WebSocket bağlantı yöneticisi
├── containment/
│   └── blocker.py          # nftables çekirdek filtreleme ve tecrit kuralları
├── core/
│   └── engine.py           # Paket analiz ve çekirdek dinleme motoru
├── database/
│   ├── db.py               # SQLite adli olay yönetim katmanı
│   └── incidents.db        # Olay veritabanı
├── traps/
│   ├── honeytokens.py      # Sahte kimlik ve konfigürasyon veri üreteçleri
│   ├── mutator.py          # Dinamik servis başlığı ve yanıt mutasyon modülü
│   ├── service_mock.py     # Asenkron sahte HTTP servisi
│   └── ssh_mock.py         # Asenkron sahte SSH servisi
├── main.py                 # Tüm servisleri koordine eden ana başlatıcı
└── requirements.txt        # Proje bağımlılıkları
