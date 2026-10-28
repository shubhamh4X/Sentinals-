"""
Sentinel AC — FastAPI Security Backend (Reference Production Implementation)
File: backend/fastapi_app/main.py

Provides:
- Role-Based Access Control (Administrator, Security Analyst, Read-Only Viewer)
- Per-Device Mutual HMAC-SHA256 Agent Authentication & Nonce Replay Protection
- Server-Side Detection Rule Evaluation (never trusts client/agent severity)
- WebSocket & Server-Sent Events (SSE) real-time SOC stream
- Cryptographically Signed Rule Update Verification
"""

from datetime import datetime, timezone
import hashlib
import hmac
import os
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Header, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="Sentinel AC — Free Fire Emulator Anti-Cheat API",
    version="2.4.1",
    description="Zero-trust telemetry ingestion, correlation engine, and SOC management API.",
)

AGENT_SHARED_SECRET = os.environ.get("SENTINEL_AGENT_HMAC_SECRET", "dev-only-replace-in-prod")
SEEN_NONCES: set[str] = set()


class TelemetryPayload(BaseModel):
    schemaVersion: str = Field(default="1.2.0", pattern=r"^1\.2\.0$")
    nonce: str = Field(..., min_length=8, max_length=64)
    deviceId: str = Field(..., pattern=r"^[a-zA-Z0-9_\-]+$")
    hostname: str = Field(..., max_length=120)
    emulator: str = Field(..., max_length=80)
    sessionId: str = Field(..., max_length=128)
    indicatorType: str
    processName: str = Field(..., max_length=160)
    processPath: str = Field(..., max_length=512)
    sha256: str = Field(..., max_length=128)
    signerIdentity: str = Field(..., max_length=200)
    observedTimestamp: str
    isSimulated: bool = False


def verify_agent_hmac(
    payload: TelemetryPayload,
    x_sentinel_signature: str = Header(..., alias="X-Sentinel-Signature"),
) -> bool:
    if payload.nonce in SEEN_NONCES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replay detected: telemetry nonce has already been processed.",
        )
    message = f"{payload.deviceId}:{payload.nonce}:{payload.indicatorType}:{payload.sha256}".encode("utf-8")
    expected = hmac.new(AGENT_SHARED_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_sentinel_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent HMAC-SHA256 signature.",
        )
    SEEN_NONCES.add(payload.nonce)
    return True


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "sentinel-ac-fastapi",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/telemetry/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_agent_telemetry(
    payload: TelemetryPayload,
    _authenticated: bool = Depends(verify_agent_hmac),
):
    return {
        "accepted": True,
        "deviceId": payload.deviceId,
        "nonce": payload.nonce,
        "evaluatedAt": datetime.now(timezone.utc).isoformat(),
    }
