import json
import shutil


if __name__ == "__main__":
    binaries = ["tesseract", "exiftool", "clamscan", "yara", "binwalk", "zsteg", "c2patool"]
    print(json.dumps({binary: bool(shutil.which(binary)) for binary in binaries}, indent=2, sort_keys=True))

