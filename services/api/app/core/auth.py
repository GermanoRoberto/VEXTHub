import hmac
import os
from dataclasses import dataclass

from fastapi import Header, HTTPException

from app.core.config import get_settings


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str


def _bearer_token(authorization: str) -> str:
    if not authorization.lower().startswith("bearer "):
        return ""
    return authorization[7:].strip()


async def require_tenant_context(
    authorization: str = Header(default=""),
    x_tenant_id: str = Header(default=""),
    x_internal_secret: str = Header(default=""),
    x_agent_secret: str = Header(default=""),
) -> TenantContext:
    settings = get_settings()

    presented_token = (
        _bearer_token(authorization)
        or x_internal_secret.strip()
        or x_agent_secret.strip()
    )

    is_dev = (
        settings.environment.lower() not in {"production", "prod"}
        or os.getenv("VEXTHUB_ENABLE_SIMULATION_FALLBACK", "").lower() == "true"
    )

    valid = False
    if presented_token:
        if settings.api_internal_token and hmac.compare_digest(presented_token, settings.api_internal_token):
            valid = True
        elif hasattr(settings, "agent_shared_secret") and settings.agent_shared_secret and hmac.compare_digest(presented_token, settings.agent_shared_secret):
            valid = True
        elif os.getenv("AGENT_SHARED_SECRET") and hmac.compare_digest(presented_token, os.getenv("AGENT_SHARED_SECRET", "")):
            valid = True

    if not valid:
        if is_dev and not settings.api_internal_token:
            valid = True
        else:
            raise HTTPException(status_code=401, detail="Invalid API token or internal secret")

    tenant_id = x_tenant_id.strip()
    if not tenant_id:
        if is_dev:
            tenant_id = "00000000-0000-0000-0000-000000000000"
        else:
            raise HTTPException(status_code=400, detail="X-Tenant-Id header is required")

    return TenantContext(tenant_id=tenant_id)
