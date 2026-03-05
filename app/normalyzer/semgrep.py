import uuid
from datetime import datetime
from typing import Dict, Any, List

from app.models.canonical import (
    CanonicalVulnerability, Asset, Location,
    Severity, Metadata
)
from app.fingerprint.generator import generate_fingerprint


def normalize(report: Dict[str, Any]) -> List[CanonicalVulnerability]:
    results = []

    for finding in report.get("results", []):
        rule_id = finding.get("check_id")
        path = finding.get("path")

        asset = Asset(kind="file", identifier=path)

        location = Location(
            path=path,
            line_start=finding.get("start", {}).get("line"),
            line_end=finding.get("end", {}).get("line")
        )

        fingerprint = generate_fingerprint(
            "SAST",
            rule_id,
            asset,
            location
        )

        now = datetime.utcnow()

        vuln = CanonicalVulnerability(
            id=str(uuid.uuid4()),
            fingerprint=fingerprint,
            source=["semgrep"],
            type="SAST",
            vuln_class=",".join(
                finding.get("extra", {})
                .get("metadata", {})
                .get("vulnerability_class", [])
            ),
            scanner_rule_id=rule_id,
            title=finding.get("extra", {}).get("message"),
            asset=asset,
            location=location,
            severity=Severity(
                scanner=finding.get("extra", {}).get("severity")
            ),
            metadata=Metadata(
                cwe=finding.get("extra", {})
                .get("metadata", {})
                .get("cwe"),
                confidence=finding.get("extra", {})
                .get("metadata", {})
                .get("confidence")
            ),
            first_seen=now,
            last_seen=now,
            raw=finding
        )

        results.append(vuln)

    return results