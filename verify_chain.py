import sqlite3
import hashlib
import json
import sys
import os

DB_PATH = "/home/black-bird/aed-dc-engine/database/incidents.db"
GENESIS_HASH = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"

def verify_evidence_chain(target_db=DB_PATH):
    print("\n" + "=" * 76)
    print("      AED-DC FORENSIC INTEGRITY AUDITOR (SHA-256 CHAIN OF CUSTODY)     ")
    print("=" * 76)

    if not os.path.exists(target_db):
        print(f"[-] Hata: Veritabanı dosyası bulunamadı -> {target_db}")
        return False

    conn = sqlite3.connect(f"file:{target_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, timestamp, src_ip, dst_port, protocol, action, forensics, forensic_hash FROM incidents ORDER BY id ASC")
        records = cursor.fetchall()
    except Exception as e:
        print(f"[-] Veritabanı okuma hatası: {e}")
        conn.close()
        return False
    finally:
        conn.close()

    if not records:
        print("[!] Veritabanında incelenecek adli olay kaydı bulunamadı.")
        return True

    print(f"[*] Denetlenen Veritabanı : {target_db}")
    print(f"[*] Toplam Kayıt Sayısı   : {len(records)} adet\n")

    current_expected_prev = GENESIS_HASH
    tamper_detected = False
    chain_started = False
    legacy_count = 0
    verified_count = 0
    session_count = 1

    for row in records:
        rec_id = row["id"]
        ts = str(row["timestamp"])
        ip = str(row["src_ip"])
        port = int(row["dst_port"] or 0)
        proto = str(row["protocol"] or "TCP")
        action = str(row["action"] or "LOG")
        forensics_str = str(row["forensics"] or "{}")
        stored_hash = str(row["forensic_hash"] or "").strip()

        # Hash mekanizması öncesinde kalan eski kayıtlar
        if not stored_hash:
            legacy_count += 1
            print(f"  [-] Olay #{rec_id:03d} | {ts[:19]} | {ip:<15} | [LEGACY - Özet Zinciri Öncesi Kayıt]")
            continue

        # Zincirin ilk başladığı an
        if not chain_started:
            chain_started = True
            print(f"\n  [*] === KRİPTOGRAFİK ZİNCİR BAŞLANGICI (Olay #{rec_id}) ===")

        payload_normal = f"{current_expected_prev}|{ts}|{ip}|{port}|{proto}|{action}|{forensics_str}"
        calc_hash_normal = hashlib.sha256(payload_normal.encode("utf-8")).hexdigest()

        payload_genesis = f"{GENESIS_HASH}|{ts}|{ip}|{port}|{proto}|{action}|{forensics_str}"
        calc_hash_genesis = hashlib.sha256(payload_genesis.encode("utf-8")).hexdigest()

        if stored_hash == calc_hash_normal:
            verified_count += 1
            print(f"  [OK] Olay #{rec_id:03d} | {ts[:19]} | {ip:<15} | Port: {port:<5} | {action:<20} | Hash: {stored_hash[:16]}...")
            current_expected_prev = stored_hash
        elif stored_hash == calc_hash_genesis:
            verified_count += 1
            if current_expected_prev != GENESIS_HASH:
                session_count += 1
                print(f"  [*] --- [OTURUM AYRIMI #{session_count}]: Servis Yeniden Başlatıldı (Genesis Hash İle) ---")
            print(f"  [OK] Olay #{rec_id:03d} | {ts[:19]} | {ip:<15} | Port: {port:<5} | {action:<20} | Hash: {stored_hash[:16]}...")
            current_expected_prev = stored_hash
        else:
            print("\n" + "!" * 76)
            print(" [KRİTİK UYARI] ADLİ DELİL TAHRİFATI (DATA TAMPERING) TESPİT EDİLDİ!")
            print("!" * 76)
            print(f"  -> Bozuk Kayıt ID             : #{rec_id}")
            print(f"  -> Zaman                      : {ts}")
            print(f"  -> Hedef/Kaynak               : {ip}:{port}")
            print(f"  -> Kayıtlı Hash Değeri        : {stored_hash}")
            print(f"  -> Hesaplanan Hash Değeri     : {calc_hash_normal}")
            print("  -> Sonuç                      : ZİNCİR KIRILDI! Veri manipüle edilmiş.")
            print("!" * 76 + "\n")
            tamper_detected = True
            break

    print("=" * 76)
    print(f"[*] Özet: {legacy_count} eski kayıt atlandı, {verified_count} adli kayıt mühür denetiminden geçti.")
    if not tamper_detected and verified_count > 0:
        print("[SONUÇ] ADLİ DELİL ZİNCİRİ %100 DOĞRULANDI (Kayıtlar Orijinal).")
    elif tamper_detected:
        print("[SONUÇ] BAŞARISIZ: Veritabanında izinsiz silme veya alan manipülasyonu var!")
    else:
        print("[SONUÇ] Henüz mühürlenmiş adli kayıt bulunmuyor.")
    print("=" * 76 + "\n")
    return not tamper_detected

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DB_PATH
    verify_evidence_chain(target)
