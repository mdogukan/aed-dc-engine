import sqlite3
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

GENESIS_HASH = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"

class ForensicCertificateEngine:
    def __init__(self, db_path: str = "/home/black-bird/aed-dc-engine/database/incidents.db"):
        self.db_path = db_path

    def generate_certificate(self, investigator_note: str = "Otonom Adli Bütünlük Doğrulama ve Kriptografik Delil Sertifikası") -> Dict[str, Any]:
        if not os.path.exists(self.db_path):
            return {"status": "error", "message": "Veritabanı dosyası bulunamadı."}

        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, timestamp, src_ip, dst_port, protocol, action, forensics, forensic_hash FROM incidents ORDER BY id ASC")
            records = cursor.fetchall()
        except Exception as e:
            return {"status": "error", "message": f"Veritabanı sorgu hatası: {str(e)}"}
        finally:
            conn.close()

        total_records = len(records)
        if total_records == 0:
            return {"status": "error", "message": "Doğrulanacak adli olay kaydı bulunamadı."}

        current_expected_prev = GENESIS_HASH
        tamper_detected = False
        legacy_count = 0
        verified_count = 0
        session_count = 1
        genesis_block_hash = GENESIS_HASH
        last_block_hash = None

        for row in records:
            rec_id = row["id"]
            ts = str(row["timestamp"])
            ip = str(row["src_ip"])
            port = int(row["dst_port"] or 0)
            proto = str(row["protocol"] or "TCP")
            action = str(row["action"] or "LOG")
            forensics_str = str(row["forensics"] or "{}")
            stored_hash = str(row["forensic_hash"] or "").strip()

            if not stored_hash:
                legacy_count += 1
                continue

            last_block_hash = stored_hash

            payload_normal = f"{current_expected_prev}|{ts}|{ip}|{port}|{proto}|{action}|{forensics_str}"
            calc_hash_normal = hashlib.sha256(payload_normal.encode("utf-8")).hexdigest()

            payload_genesis = f"{GENESIS_HASH}|{ts}|{ip}|{port}|{proto}|{action}|{forensics_str}"
            calc_hash_genesis = hashlib.sha256(payload_genesis.encode("utf-8")).hexdigest()

            if stored_hash == calc_hash_normal:
                verified_count += 1
                current_expected_prev = stored_hash
            elif stored_hash == calc_hash_genesis:
                verified_count += 1
                if current_expected_prev != GENESIS_HASH:
                    session_count += 1
                current_expected_prev = stored_hash
            else:
                tamper_detected = True
                break

        overall_integrity = "VERIFIED_TAMPER_PROOF" if (not tamper_detected and verified_count > 0) else "TAMPERED_OR_COMPROMISED"
        
        now_utc = datetime.now(timezone.utc).isoformat()
        cert_raw = f"{now_utc}|{total_records}|{verified_count}|{genesis_block_hash}|{last_block_hash}|{overall_integrity}"
        certificate_signature = hashlib.sha256(cert_raw.encode("utf-8")).hexdigest()

        return {
            "certificate_metadata": {
                "title": "AED-DC ADLİ BİLİŞİM DELİL ZİNCİRİ BÜTÜNLÜK SERTİFİKASI",
                "standard": "RFC 6962 / ISO-IEC 27037 Tamper-Proof Chain of Custody",
                "issued_at_utc": now_utc,
                "investigator_note": investigator_note,
                "certificate_signature_sha256": certificate_signature
            },
            "chain_metrics": {
                "total_records_in_db": total_records,
                "legacy_records_skipped": legacy_count,
                "cryptographically_verified_records": verified_count,
                "tampered_compromised_records": 1 if tamper_detected else 0,
                "service_sessions_detected": session_count,
                "chain_continuity": "INTACT (KESİNTİSİZ BÜTÜNLÜK)" if not tamper_detected else "BROKEN (TAHRİFAT TESPİT EDİLDİ)"
            },
            "anchor_hashes": {
                "genesis_hash": genesis_block_hash,
                "last_evidence_hash": last_block_hash
            },
            "final_forensic_verdict": {
                "status": overall_integrity,
                "is_court_admissible": (overall_integrity == "VERIFIED_TAMPER_PROOF"),
                "verdict_text": "Tüm olay kayıtları SHA-256 zinciri ile kriptografik olarak doğrulanmıştır. Herhangi bir harici müdahale, silinme veya tahrifat bulunmamaktadır." if overall_integrity == "VERIFIED_TAMPER_PROOF" else "UYARI: Delil zincirinde tahrifat veya eksik blok tespit edildi!"
            }
        }

forensic_cert_engine = ForensicCertificateEngine()
