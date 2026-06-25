from argus_img.core.models import ScanReport


def report_to_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)

