from fastapi import APIRouter

router = APIRouter()


@router.get("/v1/health")
def health():
    return {"status": "ok", "offline_mode": True, "gpu_required": False}

