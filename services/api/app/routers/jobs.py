from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app.core.auth import TenantContext, require_tenant_context
from app.core.config import get_settings
from app.core.queue import JobQueue
from app.core.rate_limit import enforce_rate_limit

router = APIRouter(prefix="/jobs", tags=["jobs"])
settings = get_settings()


class JobRequest(BaseModel):
    type: str = Field(pattern="^(telemetry.scan|compliance.sync|webhook.deliver)$")
    payload: Dict[str, Any] = Field(default_factory=dict)


@router.post("")
async def create_job(
    request: Request,
    job: JobRequest,
    tenant: TenantContext = Depends(require_tenant_context),
):
    await enforce_rate_limit(request, request.app.state.redis, settings.rate_limit_per_minute, tenant.tenant_id)
    job_id = await JobQueue(request.app.state.redis).enqueue(tenant.tenant_id, job.type, job.payload)
    return {"id": job_id, "status": "queued"}
