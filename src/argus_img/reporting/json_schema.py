from argus_img.core.models import ScanReport


def scan_report_schema() -> dict:
    return ScanReport.model_json_schema()

