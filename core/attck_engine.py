import hashlib
import logging
from typing import Tuple

logger = logging.getLogger("AED-DC.ATTCK")

class AttckForensicEngine:
    """
    AED-DC Otonom MITRE ATT&CK TTP Eşleme ve Adli Delil Mühürleme Motoru.
    Gelen tuzak tetiklemelerini TTP'lerle eşleştirir ve adli delil zincirini
    SHA-256 blok hash'leriyle mühürler.
    """
    _last_evidence_hash = "GENESIS_BLOCK_AED_DC_CHAIN_OF_CUSTODY_v1.0"

    @classmethod
    def generate_chain_of_custody_hash(cls, timestamp: str, src_ip: str, dst_port: int, protocol: str, action: str, forensics_str: str) -> Tuple[str, str]:
        """
        Her olayı kendinden önceki olayın hash değeriyle bağlayarak
        değiştirilemez adli delil zinciri (Chain of Custody) üretir.
        """
        prev_hash = cls._last_evidence_hash
        raw_payload = f"{prev_hash}|{timestamp}|{src_ip}|{dst_port}|{protocol}|{action}|{forensics_str}"
        new_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        cls._last_evidence_hash = new_hash
        return new_hash, prev_hash

    def resolve_mitre_ttp(self, dst_port: int, protocol: str, action: str, forensics: dict) -> tuple:
        """
        Olay parametrelerine göre MITRE ATT&CK Taktiği, Teknik ID'si ve Açıklamasını döndürür.
        """
        trigger = forensics.get("trigger", "")
        req_path = forensics.get("requested_path", "")

        # 1. Deanonymization (VPN/Proxy Maskesi Düşürme & Çalınan Jeton İstismarı)
        if action == "ATTACKER_DEANONYMIZED":
            return (
                "Initial Access / Persistence",
                "T1078",
                "Valid Accounts: Out-of-Band Attacker Deanonymization"
            )

        # 2. Canary Honeytoken Kötüye Kullanımı
        if action == "CANARY_TOKEN_TRIGGERED" or trigger == "CANARY_HONEYTOKEN_MISUSE":
            return (
                "Credential Access",
                "T1552",
                "Unsecured Credentials: Stolen Honeytoken Misuse"
            )

        # 3. Bulut Meta-Veri (AWS IMDS) Keşfi
        if action == "CLOUD_METADATA_HARVESTING" or trigger == "CLOUD_METADATA_API_PROBE" or "meta-data" in req_path.lower():
            return (
                "Credential Access",
                "T1552.005",
                "Unsecured Credentials: Cloud Instance Metadata API"
            )

        # 4. Yem HTTP Servisi (.env vb. Gizli Dosya Arama)
        if dst_port == 80 or protocol == "HTTP":
            return (
                "Credential Access",
                "T1552.001",
                "Unsecured Credentials: Credentials In Files (.env Leak)"
            )

        # 5. SSH Kaba Kuvvet / Port Yoklaması
        if dst_port == 22 or protocol == "SSH":
            return (
                "Credential Access",
                "T1110",
                "Brute Force: Password Guessing / Unauthorized SSH Probe"
            )

        # 6. Port Bataklığı / Ağ Keşfi (Nmap SYN Taramaları)
        if action in ("ISOLATED_TARPIT_TRIGGER", "DROPPED"):
            return (
                "Discovery",
                "T1046",
                "Network Service Discovery: Port Tarama ve Servis Haritalama"
            )

        # Varsayılan Genel Keşif Sınıflandırması
        return (
            "Reconnaissance",
            "T1595",
            "Active Scanning: Bilgi Toplama ve Servis Yoklaması"
        )

# Geriye dönük uyumluluk için alias ve tekil nesne tanımları
ATTCKEngine = AttckForensicEngine
attck_engine = AttckForensicEngine()
