import sys
import os
import asyncio
import logging
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.ws_manager import ws_manager, live_broadcaster
from containment.blocker import NftablesContainment
from database.db import db, IncidentDatabase

logger = logging.getLogger("AED-DC.SSHDecoy")

class AsyncSSHDecoyServer:
    def __init__(self, bind_ip="192.168.159.240", port=22, log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.port = int(port)
        self.log_file = log_file
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        self.blocker = NftablesContainment()
        self.db = db
        self.ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def _calculate_dynamic_ttl(self, client_ip: str) -> tuple[int, str]:
        now = datetime.now(timezone.utc)
        window_limit = now - timedelta(days=2)
        try:
            incidents = self.db.get_incidents(limit=500)
            recent_strikes = sum(
                1 for inc in incidents 
                if inc.get("src_ip") == client_ip
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

    def _log_forensic_data(self, client_ip: str, client_port: int, banner_received: str, ttl_label: str):
        forensics = {
            "client_banner": banner_received,
            "strike_penalty": ttl_label,
            "trigger": "SSH_LOW_INTERACTION_BANNER_TRAP"
        }
        forensic_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": self.bind_ip,
            "dst_port": self.port,
            "protocol": "SSH",
            "forensics": forensics,
            "action": "INTERACTED_AND_ISOLATED"
        }
        
        # 1. JSON dosyasına yaz
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(forensic_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"SSH JSON log hatası: {e}")

        # 2. SQLite veritabanına kaydet
        try:
            self.db.log_incident(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=self.bind_ip,
                dst_port=self.port,
                protocol="SSH",
                action="INTERACTED_AND_ISOLATED",
                forensics=forensics
            )
        except Exception as e:
            logger.error(f"SSH SQLite log hatası: {e}")

    async def handle_ssh_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        client_port = peername[1] if peername else 0

        try:
            writer.write(self.ssh_banner)
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(512), timeout=3.0)
                client_banner = data.decode('utf-8', errors='ignore').strip() if data else "SSH Banner Alınamadı"
            except Exception:
                client_banner = "Protokol Verisi Alınamadı (Zaman Aşımı)"

            # Dinamik TTL hesapla ve çekirdekte tecrit et
            ttl_seconds, ttl_label = self._calculate_dynamic_ttl(client_ip)
            self._log_forensic_data(client_ip, client_port, client_banner, ttl_label)

            self.blocker.isolate_ip(client_ip, timeout_seconds=ttl_seconds)

            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            payload_data = {
                "timestamp": now_str,
                "src_ip": client_ip,
                "ip": client_ip,
                "dst_port": self.port,
                "port": self.port,
                "protocol": "SSH",
                "action": "INTERACTED_AND_ISOLATED",
                "event": "INTERACTED_AND_ISOLATED",
                "forensics": {
                    "client_banner": client_banner,
                    "strike_penalty": ttl_label,
                    "trigger": "SSH_LOW_INTERACTION_BANNER_TRAP"
                }
            }

            # Sol tabloya WebSocket yayını
            try:
                ws_manager.broadcast_threadsafe(payload_data)
                await ws_manager.broadcast(payload_data)
            except Exception as e:
                logger.error(f"SSH WebSocket yayın hatası: {e}")

            # İsteğe bağlı harici bildirim motoru
            try:
                from alerts.notifier import notifier_engine
                await notifier_engine.broadcast_containment(client_ip, self.port, "SSH", f"SSH Tuzağı: {client_banner}")
            except Exception:
                pass

        except Exception as e:
            logger.error(f"SSH işleyici hatası: {e}")
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
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
