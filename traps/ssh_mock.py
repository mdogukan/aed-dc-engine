import sys
import os
import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.ws_manager import live_broadcaster
from alerts.notifier import notifier_engine
from containment.blocker import NftablesContainment
from database.db import IncidentDatabase

logger = logging.getLogger("AED-DC.SSHDecoy")

class AsyncSSHDecoyServer:
    def __init__(self, bind_ip="192.168.159.240", port=22, log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.port = port
        self.log_file = log_file
        self.blocker = NftablesContainment()
        self.db = IncidentDatabase()
        self.ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def _calculate_dynamic_ttl(self, client_ip: str) -> tuple[int, str]:
        now = datetime.now(timezone.utc)
        window_limit = now - timedelta(days=2)
        try:
            incidents = self.db.get_all_incidents()
            recent_strikes = sum(
                1 for inc in incidents 
                if inc.get("src_ip") == client_ip and (
                    datetime.fromisoformat(str(inc.get("timestamp")).replace("Z", "+00:00")).replace(tzinfo=timezone.utc) >= window_limit
                    if inc.get("timestamp") else True
                )
            )
            strike_count = max(1, recent_strikes)
        except Exception:
            strike_count = 1

        if strike_count <= 1:
            return 3600, "1 Saat (1. İhlal)"
        elif strike_count == 2:
            return 21600, "6 Saat (2. İhlal)"
        else:
            return 172800, "48 Saat (3+ İhlal)"

    def _log_forensic_data(self, client_ip: str, client_port: int, banner_received: str):
        forensic_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": self.bind_ip,
            "dst_port": self.port,
            "service_type": "SSH",
            "forensics": {"client_banner": banner_received},
            "action": "INTERACTED_AND_ISOLATED"
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(forensic_entry) + "\n")
            self.db.add_incident(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=self.bind_ip,
                dst_port=self.port,
                service_type="SSH",
                action="INTERACTED_AND_ISOLATED",
                forensics={"client_banner": banner_received}
            )
        except Exception as e:
            logger.error(f"SSH adli log hatası: {e}")

    async def handle_ssh_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        client_port = peername[1] if peername else 0

        try:
            writer.write(self.ssh_banner)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=4.0)
            client_banner = data.decode('utf-8', errors='ignore').strip() if data else "Protokol Verisi Alınamadı"
            self._log_forensic_data(client_ip, client_port, client_banner)

            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            # Doğrudan çekirdeğe timeout ile ekle
            ttl_seconds, ttl_label = self._calculate_dynamic_ttl(client_ip)
            self.blocker.isolate_ip(client_ip, timeout_seconds=ttl_seconds)

            payload_data = {
                "event": "ATTACK_ISOLATED",
                "src_ip": client_ip,
                "dst_port": self.port,
                "protocol": "SSH",
                "action": f"ISOLATED ({ttl_label})",
                "forensics": {"client_banner": client_banner}
            }

            await asyncio.gather(
                live_broadcaster.broadcast_event(payload_data),
                notifier_engine.broadcast_containment(client_ip, self.port, "SSH", f"SSH Tuzağı: {client_banner}"),
                return_exceptions=True
            )

        except Exception as e:
            logger.error(f"SSH işleyici hatası: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def start(self):
        try:
            server = await asyncio.start_server(self.handle_ssh_client, self.bind_ip, self.port)
            logger.info(f"[*] Dinamik Sahte SSH Servisi Başlatıldı | Dinleme: {self.bind_ip}:{self.port} (SSH)")
            async with server:
                await server.serve_forever()
        except Exception as e:
            logger.error(f"SSH dinleme hatası: {e}")
