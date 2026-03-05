import uuid
from datetime import datetime
from typing import Dict, Any, List

from app.models.canonical import (
    CanonicalVulnerability, Asset, Location,
    Severity, Metadata
)
# from app.fingerprint.generator import generate_fingerprint


def normalize(report: Dict[str, Any]) -> List[CanonicalVulnerability]:
    results = []

    for site in report.get("site", []):
        host = site.get("@name")

        for alert in site.get("alerts", []):
            systemic = alert.get("systemic", False)
            rule_id = alert.get("pluginid")

            asset = Asset(kind="url", identifier=host)

            location = None
            if not systemic:
                instance = alert.get("instances", [{}])[0]
                location = Location(
                    path=instance.get("uri"),
                    param=instance.get("param")
                )

            fingerprint = "FGP"
            # generate_fingerprint(
            #     "DAST",
            #     rule_id,
            #     asset,
            #     location,
            #     systemic
            # )

            now = datetime.utcnow()

            vuln = CanonicalVulnerability(
                id=str(uuid.uuid4()),
                fingerprint=fingerprint,
                source=["zap"],
                type="DAST",
                vuln_class=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                scanner_rule_id=rule_id,
                title=alert.get("alert"),
                asset=asset,
                location=location,
                severity=Severity(scanner=alert.get("riskdesc")),
                metadata=Metadata(
                    cwe=[f"CWE-{alert.get('cweid')}"] if alert.get("cweid") else None,
                    systemic=systemic
                ),
                first_seen=now,
                last_seen=now,
                raw=alert
            )

            results.append(vuln)

    return results