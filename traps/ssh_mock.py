import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import logging
import json
from datetime import datetime, timezone
from traps.mutator import ServiceMutator
from containment.blocker import NftablesContainment
from database.db import IncidentDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class AsyncSSHDecoyServer:
    def __init__(self, bind_ip="192.168.159.240", port=22, log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.port = port
        self.log_file = log_file
        self.blocker = NftablesContainment()
        self.db = IncidentDatabase()

    def _log_forensic_data(self, client_ip, client_port, details):
        forensic_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": self.bind_ip,
            "dst_port": self.port,
            "service_type": "SSH",
            "forensics": details,
            "action": "INTERACTED_AND_ISOLATED"
        }
        logging.warning(f"[SSH ADLİ DELİL] {client_ip} -> SSH Port:{self.port} İstemci: {details.get('client_banner', 'Unknown')}")
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(forensic_entry) + "\n")
            # SQLite veritabanına kaydet
            self.db.add_incident(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=self.bind_ip,
                dst_port=self.port,
                service_type="SSH",
                action="INTERACTED_AND_ISOLATED",
                forensics=details
            )
        except Exception as e:
            logging.error(f"Adli log hatası: {e}")

    async def handle_ssh_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        client_port = peername[1] if peername else 0

        try:
            ssh_banner = ServiceMutator.get_ssh_banner()
            writer.write(ssh_banner)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=3.0)
            client_banner = data.decode('utf-8', errors='ignore').strip()

            details = {
                "client_banner": client_banner if client_banner else "Direct Disconnect",
                "server_banner_sent": ssh_banner.decode('utf-8').strip()
            }

            self._log_forensic_data(client_ip, client_port, details)
            self.blocker.isolate_ip(client_ip)

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logging.error(f"SSH Hatası: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        try:
            server = await asyncio.start_server(self.handle_ssh_client, self.bind_ip, self.port)
            logging.info(f"[*] Dinamik Sahte SSH Servisi Başlatıldı | Hedef: {self.bind_ip}:{self.port} (SSH)")
            async with server:
                await server.serve_forever()
        except Exception as e:
            logging.error(f"SSH Soket başlatılamadı: {e}")

if __name__ == "__main__":
    ssh_decoy = AsyncSSHDecoyServer()
    asyncio.run(ssh_decoy.start())
