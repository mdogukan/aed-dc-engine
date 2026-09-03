import sys
import os
import threading
import asyncio
import uvicorn
import logging

from core.engine import SecurityEngine
from traps.service_mock import AsyncDecoyServer
from traps.ssh_mock import AsyncSSHDecoyServer
from api.app import app
from api.ws_manager import live_broadcaster

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)

def run_sniffer_engine():
    """Scapy çekirdek dinleyicisini ayrı iş parçacığında çalıştırır."""
    engine = SecurityEngine()
    engine.run()

async def main():
    # Ana asenkron döngüyü WebSocket yöneticisine ata
    loop = asyncio.get_running_loop()
    live_broadcaster.set_loop(loop)

    logging.info("=================================================================")
    logging.info("   AED-DC ENGINE (OTONOM ALDATMA, TECRİT VE REST API SİSTEMİ)   ")
    logging.info("=================================================================")

    # 1. Scapy Sniffer iş parçacığını başlat
    sniffer_thread = threading.Thread(target=run_sniffer_engine, daemon=True)
    sniffer_thread.start()

    # 2. HTTP ve SSH sahte servislerini başlat
    http_decoy = AsyncDecoyServer(bind_ip="0.0.0.0", target_decoy="192.168.159.240")
    ssh_decoy = AsyncSSHDecoyServer(bind_ip="192.168.159.240", port=22)

    # 3. Uvicorn web sunucusu konfigürasyonu
    config = uvicorn.Config(app=app, host="0.0.0.0", port=8000, log_level="warning")
    server = uvicorn.Server(config)

    logging.info("[*] FastAPI Yönetim API'si Devrede | Erişim: http://0.0.0.0:8000/docs")

    # Tüm servisleri asenkron olarak eşzamanlı çalıştır
    await asyncio.gather(
        server.serve(),
        http_decoy.start(),
        ssh_decoy.start()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("\n[!] Sistem durduruluyor...")
        sys.exit(0)
