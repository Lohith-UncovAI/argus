from pathlib import Path

from argus_img.orchestration.pipeline import scan_file


if __name__ == "__main__":
    report = scan_file(Path("tests/fixtures/clean.png"))
    print(report.model_dump_json(indent=2))

