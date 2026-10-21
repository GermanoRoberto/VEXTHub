from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.auth import TenantContext, require_tenant_context
from app.core.queue import JobQueue

router = APIRouter(prefix="/plugins", tags=["plugins"])


class PluginRunRequest(BaseModel):
    image: str = Field(min_length=12, description="Container image reference pinned by digest.")
    sha256: str = Field(min_length=64, max_length=64)
    parameters: Dict[str, Any] = Field(default_factory=dict)


@router.post("/run")
async def run_plugin(
    request: Request,
    payload: PluginRunRequest,
    tenant: TenantContext = Depends(require_tenant_context),
):
    if "@sha256:" not in payload.image:
        raise HTTPException(status_code=400, detail="Plugin images must be pinned by digest")

    job_id = await JobQueue(request.app.state.redis).enqueue(
        tenant.tenant_id,
        "plugin.run",
        {
            "image": payload.image,
            "sha256": payload.sha256,
            "parameters": payload.parameters,
            "sandbox": {"network": "none", "read_only_root": True},
        },
    )
    return {"id": job_id, "status": "queued"}
