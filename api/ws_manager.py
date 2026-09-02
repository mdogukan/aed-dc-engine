import logging
from typing import List
from fastapi import WebSocket

logger = logging.getLogger("AED-DC.WebSocket")

class LiveBroadcastManager:
    """Tarayıcılara canlı adli telemetri akışı sağlar."""
    def __init__(self):
        self.active_sockets: List[WebSocket] = []

    async def register(self, websocket: WebSocket):
        await websocket.accept()
        self.active_sockets.append(websocket)
        logger.info(f"[*] Canlı izleme paneli bağlandı. Aktif ekran sayısı: {len(self.active_sockets)}")

    def unregister(self, websocket: WebSocket):
        if websocket in self.active_sockets:
            self.active_sockets.remove(websocket)
            logger.info(f"[*] İzleme paneli ayrıldı. Kalan: {len(self.active_sockets)}")

    async def broadcast_event(self, event_data: dict):
        if not self.active_sockets:
            return
        for ws in self.active_sockets:
            try:
                await ws.send_json(event_data)
            except Exception:
                pass

live_broadcaster = LiveBroadcastManager()

