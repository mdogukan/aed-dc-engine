import asyncio
from api.ws_manager import live_broadcaster
from alerts.notifier import notifier_engine
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import logging
import json
from datetime import datetime, timezone
from traps.mutator import ServiceMutator
from traps.honeytokens import HoneytokenGenerator
from containment.blocker import NftablesContainment
from database.db import IncidentDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class AsyncDecoyServer:
    def __init__(self, bind_ip="0.0.0.0", target_decoy="192.168.159.240", log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.target_decoy = target_decoy
        self.log_file = log_file
        self.blocker = NftablesContainment()
        self.db = IncidentDatabase()

    def _log_forensic_data(self, client_ip, client_port, target_port, payload_type, details):
        forensic_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": self.target_decoy,
            "dst_port": target_port,
            "service_type": payload_type,
            "forensics": details,
            "action": "INTERACTED_AND_ISOLATED"
        }
        logging.warning(f"[ADLİ DELİL] {client_ip} -> HTTP:80 İstek: '{details.get('first_line', '')}' | Verilen Tuzak: {details.get('token_delivered', 'None')}")
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(forensic_entry) + "\n")
            self.db.add_incident(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=self.target_decoy,
                dst_port=target_port,
                service_type=payload_type,
                action="INTERACTED_AND_ISOLATED",
                forensics=details
            )
        except Exception as e:
            logging.error(f"Adli log hatası: {e}")

    async def handle_http_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        client_port = peername[1] if peername else 0

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            decoded_data = data.decode('utf-8', errors='ignore')
            lines = decoded_data.split("\r\n")
            
            first_line = lines[0] if lines else "Empty Request"
            parts = first_line.split()
            requested_path = parts[1] if len(parts) > 1 else "/"

            user_agent = "Unknown"
            for line in lines:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                    break

            token_delivered = "MUTATED_GATEWAY_ERROR"
            if any(key in requested_path.lower() for key in [".env", "config", "vault", "aws", "credentials"]):
                body = HoneytokenGenerator.get_env_honeytoken()
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.52 (Ubuntu)\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                    f"{body}"
                ).encode("utf-8")
                token_delivered = "ENV_CREDENTIALS_LEAKED"

            elif "robots.txt" in requested_path.lower():
                body = HoneytokenGenerator.get_robots_txt()
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: nginx/1.18.0 (Ubuntu)\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                    f"{body}"
                ).encode("utf-8")
                token_delivered = "ROBOTS_DIRECTORY_TRAP"

            else:
                response = ServiceMutator.get_http_banner()

            details = {
                "first_line": first_line,
                "requested_path": requested_path,
                "user_agent": user_agent,
                "token_delivered": token_delivered
            }

            self._log_forensic_data(client_ip, client_port, 80, "HTTP", details)
            writer.write(response)
            await writer.drain()
            self.blocker.isolate_ip(client_ip)
            payload_data = {
            "src_ip": client_ip,
            "dst_port": 80,
            "protocol": "HTTP",
            "action": "INTERACTED_AND_ISOLATED"
            }
            asyncio.create_task(live_broadcaster.broadcast_event(payload_data))
            asyncio.create_task(notifier_engine.broadcast_containment(client_ip, 80, "HTTP", "Sahte servis bal jetonu tetiklendi"))

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logging.error(f"HTTP Hatası: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        try:
            http_server = await asyncio.start_server(self.handle_http_client, self.bind_ip, 80)
            logging.info(f"[*] Dinamik Sahte Servisler Başlatıldı | Dinleme: {self.bind_ip}:80 (HTTP)")
            async with http_server:
                await http_server.serve_forever()
        except Exception as e:
            logging.error(f"Soket dinleme başlatılamadı: {e}")

if __name__ == "__main__":
    server = AsyncDecoyServer()
    asyncio.run(server.start())
