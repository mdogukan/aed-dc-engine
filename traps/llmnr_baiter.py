import socket
import struct
import threading
import time
import random
import logging
from datetime import datetime
from containment.blocker import containment_blocker
from database.db import db
from api.ws_manager import ws_manager

logger = logging.getLogger("AED-DC.LLMNRBaiter")

class LLMNRPoisonerHunter:
    """
    Ağda pusuya yatarak LLMNR/NBT-NS zehirlemesi yapan saldırganları ortaya çıkarmak
    ve otonom tecrit etmek için sahte broadcast yemleri atan avcı motoru.
    MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning)
    """
    LLMNR_MULTICAST_IP = "224.0.0.252"
    LLMNR_PORT = 5355

    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self._running = False
        self._thread = None
        self.whitelist = {"127.0.0.1", "192.168.159.133", "192.168.159.240", "192.168.159.2"}

    def _craft_llmnr_query(self, fake_hostname: str) -> bytes:
        tx_id = random.randint(1000, 65000)
        flags = 0x0000
        questions = 1
        answers = 0
        authority = 0
        additional = 0

        header = struct.pack("!HHHHHH", tx_id, flags, questions, answers, authority, additional)

        name_bytes = b""
        for part in fake_hostname.split("."):
            name_bytes += struct.pack("!B", len(part)) + part.encode("utf-8")
        name_bytes += b"\x00"

        query_type = struct.pack("!HH", 0x0001, 0x0001)
        return header + name_bytes + query_type

    def _hunter_loop(self):
        logger.info("[*] Proaktif LLMNR Yemleme ve Zehirleyici Avcısı devrede.")

        while self._running:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                sock.settimeout(4.0)

                canary_name = f"corp-vault-srv-{random.randint(100, 999)}.local"
                query_packet = self._craft_llmnr_query(canary_name)

                # Yerel ağa sahte LLMNR sorgusu bas
                sock.sendto(query_packet, (self.LLMNR_MULTICAST_IP, self.LLMNR_PORT))

                try:
                    while True:
                        data, (responder_ip, responder_port) = sock.recvfrom(1024)
                        if responder_ip not in self.whitelist:
                            logger.critical(
                                f"[ZEHİRLEYİCİ TESPİT EDİLDİ] {responder_ip} sahte LLMNR yanıtı fırlattı! "
                                f"Otonom L2 ve Çekirdek tecrit başlatılıyor."
                            )

                            # 1. Çekirdek ve L2 Tecrit
                            containment_blocker.isolate_ip(responder_ip, timeout_seconds=3600)

                            # 2. Adli Delil Sözlüğü
                            now_str = datetime.now().strftime("%H:%M:%S")
                            forensics = {
                                "attack_type": "LLMNR_POISONING_ATTEMPT",
                                "fake_hostname": canary_name,
                                "responder_port": responder_port,
                                "payload_len": len(data),
                                "description": f"Saldırgan {canary_name} sahte alan adına zehirli yanıt döndü."
                            }

                            # 3. SQLite Veritabanı Kaydı
                            try:
                                db.log_incident(
                                    src_ip=responder_ip,
                                    dst_port=5355,
                                    protocol="LLMNR",
                                    action="INTERACTED_AND_ISOLATED",
                                    forensics=forensics
                                )
                            except Exception as dbe:
                                logger.error(f"LLMNR veritabanı kayıt hatası: {dbe}")

                            # 4. Sol Panel Canlı WebSocket Telemetrisi
                            try:
                                payload = {
                                    "timestamp": now_str,
                                    "mitre_id": "T1557.001",
                                    "mitre_technique": "T1557.001 (LLMNR/NBT-NS Poisoning)",
                                    "src_ip": responder_ip,
                                    "ip": responder_ip,
                                    "dst_port": 5355,
                                    "port": 5355,
                                    "protocol": "LLMNR",
                                    "action": "INTERACTED_AND_ISOLATED",
                                    "event": "INTERACTED_AND_ISOLATED",
                                    "forensics": forensics
                                }
                                ws_manager.broadcast(payload)
                            except Exception as wse:
                                logger.error(f"LLMNR canlı yayın hatası: {wse}")

                except socket.timeout:
                    pass

            except Exception as e:
                logger.debug(f"LLMNR döngü kontrolü: {e}")
            finally:
                if sock:
                    sock.close()

            time.sleep(self.check_interval)

    def start(self):
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._hunter_loop, daemon=True)
            self._thread.start()

    def stop(self):
        self._running = False

llmnr_hunter = LLMNRPoisonerHunter(check_interval=20)
