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

        # 1. Tarpit Bataklık Eylemi
        if "TARPIT" in act or port == 8888:
            return (
                "TA0040: Impact",
                "T1499",
                "Endpoint DoS: Resource Exhaustion"
            )

        # 2. ICMP Taraması
        if port == 0 or "ICMP" in proto or "RECON" in act or "PING" in act:
            return (
                "TA0043: Reconnaissance",
                "T1595.001",
                "Active Scanning: Scanning IP Blocks"
            )

        # 3. HTTP Web Tuzağı
        if port in (80, 8080) or "HTTP" in proto:
            return (
                "TA0007: Discovery",
                "T1083",
                "File and Directory Discovery"
            )

        # 4. SSH Tuzağı
        if port in (22, 2222) or "SSH" in proto:
            return (
                "TA0007: Discovery",
                "T1046",
                "Network Service Discovery"
            )

        return (
            "TA0043: Reconnaissance",
            "T1595.002",
            "Active Scanning: Vulnerability Scanning"
        )

    @classmethod
    def generate_chain_of_custody_hash(cls, timestamp: str, src_ip: str, dst_port: int, protocol: str, action: str, forensics_str: str) -> Tuple[str, str]:
        prev_hash = cls._last_evidence_hash
        raw_payload = f"{prev_hash}|{timestamp}|{src_ip}|{dst_port}|{protocol}|{action}|{forensics_str}"
        new_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        cls._last_evidence_hash = new_hash
        return new_hash, prev_hash

attck_engine = AttckForensicEngine()
