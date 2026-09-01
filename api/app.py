import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database.db import IncidentDatabase
from containment.blocker import NftablesContainment

app = FastAPI(
    title="AED-DC Güvenlik ve İzolasyon API",
    description="Otonom Aldatma, Deterministik Tecrit ve Adli Olay Yönetim API'si",
    version="1.0.0"
)

# Tarayıcıların API'ye sorunsuz erişebilmesi için CORS izni veriyoruz
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = IncidentDatabase()
blocker = NftablesContainment()

class UnblockRequest(BaseModel):
    ip_address: str

@app.get("/api/health")
def health_check():
    """Sistem sağlık kontrolü."""
    return {"status": "ACTIVE", "engine": "AED-DC Autonomous Engine", "version": "1.0.0"}

@app.get("/api/incidents")
def list_incidents(limit: int = 50):
    """Veritabanında kayıtlı adli olayları listeler."""
    return db.get_all_incidents(limit=limit)

@app.get("/api/stats")
def get_dashboard_stats():
    """Güvenlik paneli için özet istatistikler üretir."""
    stats = db.get_statistics()
    stats["currently_blocked_count"] = len(blocker.get_blocked_ips())
    return stats

@app.get("/api/containment/blocked")
def list_blocked_ips():
    """Linux çekirdeğinde aktif olarak engelli olan IP'leri listeler."""
    return {"blocked_ips": blocker.get_blocked_ips()}

@app.post("/api/containment/release")
def release_ip_containment(req: UnblockRequest):
    """Belirtilen IP adresinin tecrit kilidini kaldırır."""
    success = blocker.release_ip(req.ip_address)
    if success:
        return {"status": "SUCCESS", "message": f"{req.ip_address} engeli kaldırıldı."}
    raise HTTPException(status_code=404, detail=f"{req.ip_address} için aktif bir engel bulunamadı.")
