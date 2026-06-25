.PHONY: test fixtures schema verify-offline

test:
	PYTHONPATH=src pytest

fixtures:
	PYTHONPATH=src python3 scripts/generate_test_images.py

schema:
	PYTHONPATH=src python3 scripts/export_json_schema.py

verify-offline:
	PYTHONPATH=src python3 scripts/verify_offline.py

