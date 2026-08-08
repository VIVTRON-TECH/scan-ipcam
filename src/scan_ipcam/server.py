from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from scan_ipcam import __version__
from scan_ipcam.scanner import scan_network

app = FastAPI(title="scan-ipcam", version=__version__)


class ScanRequest(BaseModel):
    subnet: str | None = Field(
        default=None,
        description="Optional CIDR subnet to scan, e.g. 192.168.1.0/24",
    )
    include_onvif: bool = True
    timeout: float = Field(default=0.35, ge=0.1, le=2.0)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/api/scan")
async def run_scan(request: ScanRequest) -> dict:
    devices = await scan_network(
        timeout=request.timeout,
        include_onvif=request.include_onvif,
        subnet=request.subnet,
    )
    return {
        "count": len(devices),
        "devices": [device.to_dict() for device in devices],
    }


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (Path(__file__).parent / "static" / "index.html").read_text()
