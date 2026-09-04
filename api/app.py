from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
import io
import csv
import json
import logging
from pathlib import Path
from containment.blocker import NftablesContainment
from database.db import db
from api.ws_manager import ws_manager

logger = logging.getLogger("AED-DC.API")

app = FastAPI(title="AED-DC Engine API")
blocker = NftablesContainment()

@app.on_event("startup")
async def startup_event():
    import asyncio
    ws_manager.set_loop(asyncio.get_running_loop())
    logger.info("AED-DC API ve WebSocket yöneticisi aktif edildi.")

@app.get("/", response_class=HTMLResponse)
async def get_panel():
    panel_path = Path(__file__).parent / "panel.html"
    if panel_path.exists():
        return panel_path.read_text(encoding="utf-8")
    return "<h3>panel.html bulunamadı</h3>"

@app.get("/api/incidents")
async def get_incidents(limit: int = 50):
    try:
        return db.get_incidents(limit=limit)
    except Exception as e:
        logger.error(f"Olaylar alınamadı: {e}")
        return []

@app.get("/api/blocked-ips")
async def get_blocked_ips():
    try:
        details = blocker.get_blocked_details()
        ips = [d["ip"] for d in details]
        return {"blocked_ips": ips, "details": details}
    except Exception as e:
        logger.error(f"Tecritli IP'ler sorgulanamadı: {e}")
        return {"blocked_ips": [], "details": []}

@app.post("/api/unblock/{ip}")
async def unblock_ip(ip: str):
    success = blocker.unblock_ip(ip)
    if success:
        await ws_manager.broadcast({"event": "IP_UNBLOCKED", "src_ip": ip, "action": "UNBLOCKED"})
        return {"status": "success", "ip": ip}
    raise HTTPException(status_code=400, detail="IP engeli kaldırılamadı")

@app.post("/api/unblock-all")
async def unblock_all():
    success = blocker.flush_all()
    if success:
        await ws_manager.broadcast({"event": "ALL_UNBLOCKED", "action": "ALL_UNBLOCKED"})
        return {"status": "success", "message": "Tüm engeller kaldırıldı"}
    raise HTTPException(status_code=500, detail="Küme sıfırlanamadı")

@app.get("/api/export/json")
async def export_json():
    incidents = db.get_incidents(limit=1000)
    data = json.dumps(incidents, indent=2, ensure_ascii=False)
    return StreamingResponse(
        io.StringIO(data),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=AED_Incidents_Report.json"}
    )

@app.get("/api/export/csv")
async def export_csv():
    incidents = db.get_incidents(limit=1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Src_IP", "Dst_Port", "Protocol", "Action", "Forensics"])
    for inc in incidents:
        writer.writerow([
            inc.get("id", ""),
            inc.get("timestamp", ""),
            inc.get("src_ip", ""),
            inc.get("dst_port", ""),
            inc.get("protocol", ""),
            inc.get("action", ""),
            json.dumps(inc.get("forensics", {}), ensure_ascii=False)
        ])
    output.seek(0)
    return StreamingResponse(
        io.StringIO(output.getvalue()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=AED_Incidents_Report.csv"}
    )

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
