import os
import io
import csv
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import FileResponse, Response
from containment.blocker import NftablesContainment
from database.db import IncidentDatabase
from api.ws_manager import live_broadcaster

app = FastAPI(title="AED-DC Engine API")

blocker = NftablesContainment()
db = IncidentDatabase()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def get_dashboard():
    """Canlı izleme panelini döndürür."""
    panel_path = os.path.join(BASE_DIR, "panel.html")
    return FileResponse(panel_path)

@app.websocket("/ws/threats")
async def threat_websocket_endpoint(websocket: WebSocket):
    """Canlı telemetri akışını sağlayan WebSocket uç noktası."""
    await live_broadcaster.register(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        live_broadcaster.unregister(websocket)

@app.get("/api/incidents")
async def get_incidents():
    """Geçmiş adli olayları listeler."""
    return db.get_all_incidents()

@app.get("/api/containment/blocked")
async def get_blocked_ips():
    """Mevcut nftables engelli IP listesini döndürür."""
    return {"blocked_ips": blocker.get_blocked_ips()}

@app.delete("/api/containment/unblock/{ip}")
async def unblock_ip_endpoint(ip: str):
    """Panel üzerinden tetiklenen manuel engel kaldırma rotası."""
    success = blocker.unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=400, detail=f"{ip} adresi nftables listesinden kaldırılamadı.")
    
    await live_broadcaster.broadcast_event({
        "event": "IP_UNBLOCKED",
        "src_ip": ip,
        "reason": "Yönetici tarafından manuel kaldırıldı"
    })
    return {"status": "success", "message": f"{ip} engeli başarıyla kaldırıldı."}

@app.get("/api/incidents/export")
async def export_incidents(export_format: str = Query("json")):
    """Adli olayları CSV veya JSON formatında indirir."""
    try:
        incidents = db.get_all_incidents()

        if export_format.lower() == "csv":
            output = io.StringIO()
            output.write('\ufeff')  # Excel için UTF-8 BOM etiketi

            if incidents:
                # Veritabanında mevcut olan tüm alanları otomatik al
                first_row = dict(incidents[0])
                fieldnames = list(first_row.keys())
            else:
                fieldnames = ["id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "service_type", "action", "forensics"]

            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for item in incidents:
                row = dict(item)
                for k, v in row.items():
                    if isinstance(v, (dict, list)):
                        row[k] = json.dumps(v, ensure_ascii=False)
                writer.writerow(row)

            return Response(
                content=output.getvalue(),
                media_type="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": "attachment; filename=aed_adli_delil_raporu.csv",
                    "Content-Type": "text/csv; charset=utf-8"
                }
            )

        # Varsayılan JSON Dışa Aktarma
        json_data = json.dumps(incidents, indent=2, ensure_ascii=False)
        return Response(
            content=json_data,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=aed_adli_delil_raporu.json"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dışa aktarma hatası: {str(e)}")
