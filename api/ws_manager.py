import asyncio
import logging
from typing import List
from fastapi import WebSocket

logger = logging.getLogger("AED-DC.WebSocket")

class ConnectionManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ConnectionManager, cls).__new__(cls)
            cls._instance.active_connections: List[WebSocket] = []
            cls._instance.loop = None
        return cls._instance

    def set_loop(self, loop):
        self.loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def _async_broadcast(self, message: dict):
        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for dead in disconnected:
            self.disconnect(dead)

    def broadcast(self, *args, **kwargs):
        message = args[0] if args else kwargs.get("message", kwargs.get("data", kwargs.get("event_data", {})))
        
        try:
            curr_loop = asyncio.get_running_loop()
        except RuntimeError:
            curr_loop = None

        target_loop = self.loop or curr_loop

        if target_loop and target_loop.is_running():
            if curr_loop == target_loop:
                return target_loop.create_task(self._async_broadcast(message))
            else:
                return asyncio.run_coroutine_threadsafe(self._async_broadcast(message), target_loop)
        return None

    # ssh_mock ve engine çağrıları için tam eşleşmeler
    broadcast_event = broadcast
    broadcast_from_thread = broadcast
    broadcast_threadsafe = broadcast
    broadcast_sync = broadcast
    send = broadcast
    emit = broadcast
    publish = broadcast

    def __call__(self, *args, **kwargs):
        return self.broadcast(*args, **kwargs)

ws_manager = ConnectionManager()
manager = ws_manager
live_broadcaster = ws_manager
