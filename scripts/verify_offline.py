import json

from argus_img.core.config import load_config
from argus_img.core.offline_guard import OfflineGuard


if __name__ == "__main__":
    config = load_config()
    print(json.dumps(OfflineGuard(strict=config.offline.strict).self_test(), indent=2, sort_keys=True))

