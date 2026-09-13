from datetime import datetime, timezone
from pathlib import Path
import csv
import io

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .database import init_db, save_analysis, recent_analyses, all_analyses, clear_history
from .ip2location import lookup_ip, validate_ip, IP2LocationError
from .risk_engine import calculate_risk

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="ThreatMap API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

class IPRequest(BaseModel):
    ip: str

def normalize(data: dict, risk: dict) -> dict:
    as_info = data.get("as_info") or {}
    proxy = data.get("proxy") or {}
    return {
        "ip": data.get("ip"),
        "country_code": data.get("country_code"),
        "country_name": data.get("country_name"),
        "region_name": data.get("region_name"),
        "city_name": data.get("city_name"),
        "zip_code": data.get("zip_code"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "time_zone": data.get("time_zone"),
        "isp": data.get("isp"),
        "asn": data.get("asn") or as_info.get("as_number"),
        "as_name": data.get("as") or as_info.get("as_name"),
        "domain": data.get("domain") or as_info.get("as_domain"),
        "usage_type": data.get("usage_type") or as_info.get("as_usage_type"),
        "address_type": data.get("address_type"),
        "as_cidr": as_info.get("as_cidr"),
        "is_proxy": bool(data.get("is_proxy")),
        "proxy": proxy,
        "threat": proxy.get("threat"),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_reasons": risk["reasons"],
    }

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.post("/api/analyze")
async def analyze(request: IPRequest):
    try:
        ip = validate_ip(request.ip)
        data = await lookup_ip(ip)
        risk = calculate_risk(data)
        result = normalize(data, risk)
        save_analysis({
            "ip": result["ip"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "country": result.get("country_name"),
            "city": result.get("city_name"),
            "isp": result.get("isp"),
            "asn": result.get("asn"),
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
        })
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except IP2LocationError as exc:
        code = exc.status_code if exc.status_code in {429} else 502
        raise HTTPException(status_code=code, detail=str(exc))

@app.post("/api/bulk")
async def bulk(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    raw = await file.read()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="CSV file is too large (maximum 2 MB).")

    try:
        text = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid CSV file.")

    if not reader.fieldnames or "ip" not in [x.strip().lower() for x in reader.fieldnames]:
        raise HTTPException(status_code=400, detail='CSV must contain an "ip" column.')

    ip_key = next(x for x in reader.fieldnames if x.strip().lower() == "ip")
    values = []
    seen = set()
    for row in reader:
        value = (row.get(ip_key) or "").strip()
        if value and value not in seen:
            seen.add(value)
            values.append(value)

    if not values:
        raise HTTPException(status_code=400, detail="CSV contains no IP addresses.")
    if len(values) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 unique IPs per upload.")

    results = []
    for value in values:
        try:
            ip = validate_ip(value)
            data = await lookup_ip(ip)
            risk = calculate_risk(data)
            result = normalize(data, risk)
            save_analysis({
                "ip": result["ip"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "country": result.get("country_name"),
                "city": result.get("city_name"),
                "isp": result.get("isp"),
                "asn": result.get("asn"),
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
            })
            results.append({
                "ip": result["ip"],
                "country": result.get("country_name"),
                "city": result.get("city_name"),
                "isp": result.get("isp"),
                "asn": result.get("asn"),
                "proxy": "Yes" if result.get("is_proxy") else "No",
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
            })
        except (ValueError, IP2LocationError) as exc:
            results.append({
                "ip": value,
                "country": "Not available",
                "city": "Not available",
                "isp": "Not available",
                "asn": "Not available",
                "proxy": "Not available",
                "risk_score": None,
                "risk_level": "Error",
                "error": str(exc),
            })
    return {"count": len(results), "results": results}

@app.get("/api/history")
async def history():
    return all_analyses()

@app.delete("/api/history")
async def delete_history():
    clear_history()
    return {"message": "History cleared."}

@app.get("/api/dashboard")
async def dashboard():
    rows = all_analyses(500)
    return {
        "total": len(rows),
        "high": sum(r["risk_level"] == "High Risk" for r in rows),
        "medium": sum(r["risk_level"] == "Medium Risk" for r in rows),
        "low": sum(r["risk_level"] == "Low Risk" for r in rows),
        "recent": recent_analyses(8),
    }

@app.get("/api/history.csv")
async def history_csv():
    rows = all_analyses(500)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ip", "timestamp", "country", "city", "isp", "asn", "risk_score", "risk_level"
    ])
    writer.writeheader()
    writer.writerows(rows)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatmap-history.csv"}
    )

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/{path:path}")
async def frontend(path: str):
    if path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    target = FRONTEND_DIR / path
    if target.is_file():
        return FileResponse(target)
    return FileResponse(FRONTEND_DIR / "index.html")
