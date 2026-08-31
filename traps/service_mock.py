import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
import logging
import json
from datetime import datetime, timezone
from traps.mutator import ServiceMutator
from containment.blocker import NftablesContainment

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class AsyncDecoyServer:
    def __init__(self, bind_ip="0.0.0.0", target_decoy="192.168.159.240", log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.target_decoy = target_decoy
        self.log_file = log_file
        self.blocker = NftablesContainment()

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
        logging.warning(f"[ADLİ DELİL TOPLANDI] {client_ip} -> {payload_type} Port:{target_port} İstek: {details.get('first_line', '')}")
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(forensic_entry) + "\n")
        except Exception as e:
            logging.error(f"Adli log hatası: {e}")

    async def handle_http_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        client_port = peername[1] if peername else 0

        try:
            # Saldırgandan gelen HTTP verisini oku
            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            decoded_data = data.decode('utf-8', errors='ignore')
            lines = decoded_data.split("\r\n")
            
            first_line = lines[0] if lines else "Empty Request"
            user_agent = "Unknown"
            for line in lines:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                    break

            details = {
                "first_line": first_line,
                "user_agent": user_agent,
                "raw_request": decoded_data[:200]
            }

            # 1. Delili kaydet
            self._log_forensic_data(client_ip, client_port, 80, "HTTP", details)

            # 2. Sahte sunucu başlığı ve HTTP yanıtı döndür
            response = ServiceMutator.get_http_banner()
            writer.write(response)
            await writer.drain()

            # 3. İletişim biter bitmez çekirdek seviyesinde izole et
            self.blocker.isolate_ip(client_ip)

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
