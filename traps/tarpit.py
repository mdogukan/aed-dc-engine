import socket
import struct
import time
import logging
import threading
from core.attck_engine import attck_engine
from database.db import db
from api.ws_manager import live_broadcaster

logger = logging.getLogger("AED-DC.Tarpit")

class TCPTarpit:
    def __init__(self, tarpit_port: int = 8888):
        self.tarpit_port = tarpit_port
        self.running = False
        self._thread = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_tarpit, daemon=True, name="TCP-Tarpit-Worker")
        self._thread.start()
        logger.info(f"TCP Tarpit (Port Tarama Bataklığı) Port {self.tarpit_port} üzerinde devrede.")

    def _get_original_port(self, sock) -> int:
        SO_ORIGINAL_DST = 80
        try:
            odst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            _, orig_port = struct.unpack("!2xH4x8x", odst[:16])
            return int(orig_port)
        except Exception:
            return self.tarpit_port

    def _run_tarpit(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind(("0.0.0.0", self.tarpit_port))
            server_sock.listen(128)
        except Exception as e:
            logger.error(f"Tarpit soket başlatılamadı: {e}")
            return

        while self.running:
            try:
                client_sock, (client_ip, client_port) = server_sock.accept()
                threading.Thread(target=self._trap_client, args=(client_sock, client_ip, client_port), daemon=True).start()
            except Exception:
                break

    def _trap_client(self, sock, client_ip, client_port):
        targeted_port = self._get_original_port(sock)
        logger.warning(f"SALDIRGAN PORT TARAMA BATAKLIĞINA DÜŞTÜ: {client_ip}:{client_port} -> Hedef Port: {targeted_port}")

        forensics = {
            "technique": "Port Scan Tarpit Redirection",
            "targeted_port": targeted_port,
            "mechanism": "Slow-drip window manipulation (Resource Exhaustion)",
            "client_ip": client_ip,
            "client_port": client_port,
            "status": "SOCKET_FROZEN"
        }

        db.log_incident(
            src_ip=client_ip,
            dst_port=targeted_port,
            protocol="TCP",
            action="TARPIT_ENGAGED",
            forensics=forensics
        )

        ws_payload = {
            "event": "TARPIT_ENGAGED",
            "action": "TARPIT_ENGAGED",
            "src_ip": client_ip,
            "dst_port": targeted_port,
            "protocol": "TCP",
            "mitre_technique": "T1499 (Endpoint Denial of Service: Resource Exhaustion)",
            "mitre_tactic": "TA0040: Impact",
            "forensics": forensics
        }

        if hasattr(live_broadcaster, "broadcast_sync"):
            live_broadcaster.broadcast_sync(ws_payload)

        try:
            fake_banner = f"220 AED-DC Service Node ready (port {targeted_port} emulation)...\r\n"
            for char in fake_banner:
                sock.send(char.encode("utf-8"))
                time.sleep(3.0)

            while self.running:
                sock.send(b" ")
                time.sleep(10.0)
        except (socket.error, BrokenPipeError, ConnectionResetError):
            logger.info(f"Saldırgan bağlantıyı kesti: {client_ip}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

tarpit_engine = TCPTarpit()
