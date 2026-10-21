import hashlib
import hmac
from typing import Any, Dict

from fastapi import APIRouter, Header, HTTPException, Request

from app.core.config import get_settings
from app.core.detections import detection_engine

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
settings = get_settings()


def verify_signature(body: bytes, signature: str) -> bool:
    if not settings.webhook_signing_secret:
        return False
    expected = hmac.new(settings.webhook_signing_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


@router.post("/telemetry")
async def telemetry_webhook(
    request: Request,
    x_tenant_id: str = Header(default=""),
    x_vexthub_signature: str = Header(default=""),
):
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id header is required")

    body = await request.body()
    if not verify_signature(body, x_vexthub_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload: Dict[str, Any] = await request.json()
    matches = detection_engine.scan(payload)
    return {"accepted": True, "tenant_id": x_tenant_id, "detections": matches}
