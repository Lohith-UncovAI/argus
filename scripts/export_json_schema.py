from pathlib import Path
import json

from argus_img.reporting.json_schema import scan_report_schema


def main():
    Path("schemas").mkdir(exist_ok=True)
    Path("schemas/scan-report.schema.json").write_text(
        json.dumps(scan_report_schema(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    Path("schemas/detector-report.schema.json").write_text(
        json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "DetectorReport"}, indent=2),
        encoding="utf-8",
    )
    Path("schemas/policy.schema.json").write_text(
        json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "Policy"}, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

