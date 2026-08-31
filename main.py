import threading
import asyncio
import logging
from core.engine import SecurityEngine
from traps.service_mock import AsyncDecoyServer
from traps.ssh_mock import AsyncSSHDecoyServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

def run_sniffer_engine():
    engine = SecurityEngine()
    engine.start()

async def run_all_traps():
    http_decoy = AsyncDecoyServer()
    ssh_decoy = AsyncSSHDecoyServer(bind_ip="192.168.159.240", port=22)

    await asyncio.gather(
        http_decoy.start(),
        ssh_decoy.start()
    )

def main():
    logging.info("=" * 65)
    logging.info("   AED-DC ENGINE (ÇOKLU PROTOKOL ALDATMA VE TECRİT SİSTEMİ)   ")
    logging.info("=" * 65)

    # 1. İş Parçacığı: Çekirdek Paket Dinleyici (BPF)
    sniffer_thread = threading.Thread(target=run_sniffer_engine, daemon=True)
    sniffer_thread.start()

    # 2. İş Parçacığı / Olay Döngüsü: Sahte HTTP ve Sahte SSH Servisleri
    try:
        asyncio.run(run_all_traps())
    except KeyboardInterrupt:
        logging.info("\n[*] Güvenlik motoru kapatılıyor...")

if __name__ == "__main__":
    main()
