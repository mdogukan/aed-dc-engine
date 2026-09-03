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

logger = logging.getLogger("AED-DC.Decoy")

class AsyncDecoyServer:
    def __init__(self, bind_ip="0.0.0.0", port=80, target_decoy="192.168.159.240", log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.port = port
        self.target_decoy = target_decoy
        self.log_file = log_file
        self.blocker = NftablesContainment()
        self.db = IncidentDatabase()

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

    def _log_forensic_data(self, client_ip: str, client_port: int, details: dict):
        forensic_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": self.target_decoy,
            "dst_port": self.port,
            "service_type": "HTTP",
            "forensics": details,
            "action": "INTERACTED_AND_ISOLATED"
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(forensic_entry) + "\n")
            self.db.add_incident(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=self.target_decoy,
                dst_port=self.port,
                service_type="HTTP",
                action="INTERACTED_AND_ISOLATED",
                forensics=details
            )
        except Exception as e:
            logger.error(f"Adli log hatası: {e}")

    async def handle_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        sockname = writer.get_extra_info('sockname')

        client_ip = peername[0] if peername else "Unknown"
        client_port = peername[1] if peername else 0
        dest_ip = sockname[0] if sockname else "Unknown"

        if dest_ip != self.target_decoy:
            writer.close()
            return

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            request_text = data.decode('utf-8', errors='ignore')
            first_line = request_text.splitlines()[0] if request_text else ""
            user_agent = "Bilinmiyor"
            for line in request_text.splitlines():
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()

            body = (
                "# Cloud Storage Credentials\n"
                "AWS_ACCESS_KEY_ID=AKIA2KCNSZ0QS3V4YQR8\n"
                "AWS_SECRET_ACCESS_KEY=dSY5YRiznPs5raUVsVmNLuYY3kfwzk0BWCtPseVz\n"
                "AWS_DEFAULT_REGION=eu-central-1\n\n"
                "# JWT Authentication\n"
                "JWT_SECRET=-KkGAZ7ncixkQx73hMag0rqYm0jO5UwZG198do1c_cA\n"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n" + body
            )

            writer.write(response.encode('utf-8'))
            await writer.drain()

            details = {
                "first_line": first_line,
                "requested_path": first_line.split()[1] if len(first_line.split()) > 1 else "/",
                "user_agent": user_agent,
                "token_delivered": "ENV_CREDENTIALS_LEAKED"
            }
            self._log_forensic_data(client_ip, client_port, details)

            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass

            # Dinamik TTL hesapla ve doğrudan Linux çekirdeğindeki kümeye (Set) timeout ile ekle
            ttl_seconds, ttl_label = self._calculate_dynamic_ttl(client_ip)
            self.blocker.isolate_ip(client_ip, timeout_seconds=ttl_seconds)

            payload_data = {
                "event": "ATTACK_ISOLATED",
                "src_ip": client_ip,
                "dst_port": self.port,
                "protocol": "HTTP",
                "action": f"ISOLATED ({ttl_label})",
                "forensics": details
            }

            await asyncio.gather(
                live_broadcaster.broadcast_event(payload_data),
                notifier_engine.broadcast_containment(client_ip, self.port, "HTTP", f"Bal Jetonu Teslim Edildi: {first_line}"),
                return_exceptions=True
            )

        except Exception as e:
            logger.error(f"HTTP işleyici hatası: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def start(self):
        try:
            server = await asyncio.start_server(self.handle_client, self.bind_ip, self.port)
            logger.info(f"[*] Dinamik Sahte Servisler Başlatıldı | Dinleme: {self.bind_ip}:{self.port} (HTTP)")
            async with server:
                await server.serve_forever()
        except Exception as e:
            logger.error(f"Soket dinleme başlatılamadı: {e}")
