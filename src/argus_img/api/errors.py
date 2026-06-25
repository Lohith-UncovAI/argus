from fastapi import HTTPException

from argus_img.core.exceptions import ArtifactAccessDenied, ArgusError


def to_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ArtifactAccessDenied):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ArgusError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="internal error")

