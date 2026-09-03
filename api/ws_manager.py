import asyncio
import json
import logging
from fastapi import WebSocket

logger = logging.getLogger("AED-DC.WebSocket")

class ConnectionManager:
    # Tüm modüller ve thread'ler için ortak tekil havuz (Singleton)
    _connections: set[WebSocket] = set()
    _loop: asyncio.AbstractEventLoop = None

    @classmethod
    def set_loop(cls, loop: asyncio.AbstractEventLoop):
        cls._loop = loop
        logger.info("[*] WebSocket olay döngüsü başarıyla kaydedildi.")

    @classmethod
    async def connect(cls, websocket: WebSocket):
        await websocket.accept()
        cls._connections.add(websocket)
        if cls._loop is None or not cls._loop.is_running():
            try:
                cls._loop = asyncio.get_running_loop()
            except RuntimeError:
                pass
        logger.info(f"Canlı telemetri istemcisi bağlandı. Aktif istemci: {len(cls._connections)}")

    @classmethod
    def disconnect(cls, websocket: WebSocket):
        cls._connections.discard(websocket)
        logger.info(f"Canlı telemetri istemcisi ayrıldı. Kalan: {len(cls._connections)}")

    @classmethod
    async def broadcast_event(cls, data: dict):
        if not cls._connections:
            return
        message = json.dumps(data)
        dead = set()
        for conn in list(cls._connections):
            try:
                await conn.send_text(message)
            except Exception:
                dead.add(conn)
        for d in dead:
            cls.disconnect(d)

    @classmethod
    def broadcast_from_thread(cls, data: dict):
        """Scapy gibi harici thread'lerden FastAPI döngüsüne güvenli aktarım."""
        try:
            if cls._loop is not None and cls._loop.is_running():
                future = asyncio.run_coroutine_threadsafe(cls.broadcast_event(data), cls._loop)
                # Olası gizli coroutine hatalarını yakala
                def _callback(f):
                    try:
                        f.result()
                    except Exception as err:
                        logger.error(f"[WS YAYIN HATA] Coroutine hatası: {err}")
                future.add_done_callback(_callback)
                logger.info(f"[*] Canlı telemetri aktarıldı ({len(cls._connections)} aktif istemci): {data.get('event')}")
            else:
                logger.warning("[WS UYARI] Ana döngü henüz aktif değil, veri iletilemedi.")
        except Exception as e:
            logger.error(f"[WS HATA] Thread yayın hatası: {e}")

# Tekil örnek
live_broadcaster = ConnectionManager()
