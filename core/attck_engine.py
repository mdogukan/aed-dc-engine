import hashlib
import json
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("AED-DC.ATTCK_Forensics")

class AttckForensicEngine:
    _instance = None
    _last_evidence_hash = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AttckForensicEngine, cls).__new__(cls)
        return cls._instance

    @staticmethod
    def resolve_mitre_ttp(dst_port: int, protocol: str, action: str, forensics: Dict[str, Any] = None) -> Tuple[str, str, str]:
        proto = (protocol or "").upper()
        act = (action or "").upper()
        port = int(dst_port or 0)
        forensics = forensics or {}
        trigger = str(forensics.get("trigger", "")).upper()
        user = forensics.get("attempted_user", "")

        # 1. Zehirli Yem / Geçerli Hesap İstismarı
        if "CANARY" in act or "CANARY" in trigger:
            return ("TA0001: Initial Access", "T1078", "Valid Accounts: Canary Token Misuse")

        # 2. Tarpit DoS / Kaynak Tüketimi
        if "TARPIT" in act or port == 8888 or "TARPIT" in trigger:
            return ("TA0040: Impact", "T1499", "Endpoint DoS: Resource Exhaustion")

        # 3. SSH Kimlik Denemesi / Kaba Kuvvet
        if "BRUTE" in trigger or (user and user not in ("Bilinmiyor", "", "None")):
            return ("TA0006: Credential Access", "T1110", "Brute Force: Credential Guessing")

        # 4. SSH Servis / Banner Keşfi
        if port in (22, 2222) or "SSH" in proto:
            return ("TA0007: Discovery", "T1046", "Network Service Discovery")

        # 5. HTTP Dizin / Dosya Keşfi (.env vb.)
        if port in (80, 8080) or "HTTP" in proto:
            return ("TA0007: Discovery", "T1083", "File and Directory Discovery")

        # 6. ICMP Ping Taraması
        if port == 0 or "ICMP" in proto or "PING" in act or "PING" in trigger:
            return ("TA0043: Reconnaissance", "T1595.001", "Active Scanning: Scanning IP Blocks")

        # 7. Aktif Port ve Zafiyet Taraması
        return ("TA0043: Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning")

    @classmethod
    def generate_chain_of_custody_hash(cls, timestamp: str, src_ip: str, dst_port: int, protocol: str, action: str, forensics_str: str) -> Tuple[str, str]:
        prev_hash = cls._last_evidence_hash
        raw_payload = f"{prev_hash}|{timestamp}|{src_ip}|{dst_port}|{protocol}|{action}|{forensics_str}"
        new_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        cls._last_evidence_hash = new_hash
        return new_hash, prev_hash

attck_engine = AttckForensicEngine()
