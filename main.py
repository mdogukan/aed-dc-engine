import threading
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from api.ws_manager import live_broadcaster
import asyncio
import logging
import uvicorn
from core.engine import SecurityEngine
from traps.service_mock import AsyncDecoyServer
from traps.ssh_mock import AsyncSSHDecoyServer
from api.app import app

@app.get("/", response_class=HTMLResponse)
async def get_live_dashboard():
    with open("api/panel.html", "r", encoding="utf-8") as f:
        return f.read()

@app.websocket("/ws/threats")
async def websocket_threat_endpoint(websocket: WebSocket):
    await live_broadcaster.register(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        live_broadcaster.unregister(websocket)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

def run_sniffer_engine():
    engine = SecurityEngine()
    engine.start()

def run_api_server():
    """FastAPI REST API sunucusunu Port 8000 üzerinde çalıştırır."""
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

async def run_all_traps():
    http_decoy = AsyncDecoyServer()
    ssh_decoy = AsyncSSHDecoyServer(bind_ip="192.168.159.240", port=22)

    await asyncio.gather(
        http_decoy.start(),
        ssh_decoy.start()
    )

def main():
    logging.info("=" * 65)
    logging.info("   AED-DC ENGINE (OTONOM ALDATMA, TECRİT VE REST API SİSTEMİ)   ")
    logging.info("=" * 65)

    # 1. İş Parçacığı: Çekirdek BPF Dinleyicisi
    sniffer_thread = threading.Thread(target=run_sniffer_engine, daemon=True)
    sniffer_thread.start()

    # 2. İş Parçacığı: FastAPI REST API Sunucusu (Port 8000)
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()
    logging.info("[*] FastAPI Yönetim API'si Devrede | Erişim: http://0.0.0.0:8000/docs")

    # 3. Ana Olay Döngüsü: Sahte HTTP & SSH Tuzakları
    try:
        asyncio.run(run_all_traps())
    except KeyboardInterrupt:
        logging.info("\n[*] Güvenlik motoru kapatılıyor...")

if __name__ == "__main__":
    main()
