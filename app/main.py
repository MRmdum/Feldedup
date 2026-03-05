from app.normalyzer import zap

import json
import os


if __name__ == "__main__":

    base_dir = os.path.dirname(__file__)
    report_path = os.path.join(
        base_dir,
        "..",
        "app",
        "security-reports",
        "zap.json"
    )

    with open(report_path, "r") as f:
        data = json.load(f)

    vulns = zap.normalize(data)
