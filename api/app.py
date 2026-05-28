import os
import time
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from scanner.engine import validate_target, create_scan, run_scan, scans
from report.generator import generate_report
from report.pdf_report import generate_pdf

app = FastAPI(
    title="DevSpire Security Scanner API",
    version="1.0.0",
    description="Automated security assessment and penetration testing API",
)

# CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting — only counts valid scan starts, not rejected inputs
RATE_LIMIT = int(os.getenv("RATE_LIMIT_MAX", "5"))
RATE_WINDOW = int(os.getenv("RATE_WINDOW_SECS", "3600"))
_scan_timestamps: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(client_ip: str):
    now = time.time()
    timestamps = _scan_timestamps[client_ip]
    _scan_timestamps[client_ip] = [t for t in timestamps if now - t < RATE_WINDOW]
    if len(_scan_timestamps[client_ip]) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {RATE_LIMIT} scans per hour.",
        )


def _record_scan(client_ip: str):
    _scan_timestamps[client_ip].append(time.time())


class ScanRequest(BaseModel):
    target: str
    mode: str = "full"


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "active_scans": sum(1 for s in scans.values() if s["status"] == "running"),
    }


@app.post("/api/scan")
async def start_scan(request: Request, body: ScanRequest):
    # 1. Validate
    try:
        target = validate_target(body.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 2. Rate limit only valid requests
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    _record_scan(client_ip)

    # 3. Run scan synchronously (Vercel serverless is stateless)
    scan = create_scan(target)
    await run_scan(scan["scan_id"])

    # 4. Return completed scan with full results
    return scans[scan["scan_id"]]


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    report = generate_report(scan)
    pdf_bytes = generate_pdf(report)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="devspire-report-{scan["target"]}-{scan_id}.pdf"',
        },
    )


@app.get("/api/report/{scan_id}/json")
async def get_report_json(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    return generate_report(scan)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
