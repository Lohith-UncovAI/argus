from pathlib import Path
import tempfile

from fastapi import APIRouter, File, Form, UploadFile

from argus_img.artifacts.store import ArtifactStore
from argus_img.core.config import load_config
from argus_img.core.enums import ScanMode, UseProfile
from argus_img.core.models import ScanReport, ScanRequest
from argus_img.intake.upload import write_bounded_stream
from argus_img.orchestration.pipeline import scan_file

router = APIRouter()


@router.post("/v1/scans")
def create_scan(
    file: UploadFile = File(...),
    mode: ScanMode = Form(ScanMode.FAST),
    use_profile: UseProfile = Form(UseProfile.AGENT_WITH_TOOLS),
    sanitize: bool = Form(True),
    redact: bool = Form(False),
):
    config = load_config()
    temporary_dir = Path(config.data_dir) / "temporary"
    temporary_dir.mkdir(parents=True, exist_ok=True)
    temp = tempfile.NamedTemporaryFile(dir=str(temporary_dir), delete=False)
    temp_path = Path(temp.name)
    temp.close()
    try:
        write_bounded_stream(file.file, temp_path, config.limits.max_input_bytes)
        request = ScanRequest(
            original_filename=file.filename,
            declared_mime=file.content_type,
            mode=mode,
            use_profile=use_profile,
            sanitize=sanitize,
            redact=redact,
            include_raw_text=False,
        )
        report = scan_file(temp_path, request, config)
        return report.model_dump(mode="json")
    finally:
        temp_path.unlink(missing_ok=True)


@router.get("/v1/scans/{scan_id}")
def get_scan(scan_id: str):
    store = ArtifactStore(Path(load_config().data_dir))
    return ScanReport.model_validate_json(store.load_report(scan_id)).model_dump(mode="json")
