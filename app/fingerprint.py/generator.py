from app.models.canonical import Asset, Location
from app.utils.hashing import sha256_hash


def generate_fingerprint(vuln_type: str,
                         rule_id: str,
                         asset: Asset,
                         location: Location = None,
                         systemic: bool = False) -> str:

    if vuln_type == "SAST":
        bucket = None
        if location and location.line_start:
            bucket = location.line_start // 5

        parts = [
            vuln_type,
            rule_id,
            asset.identifier,
            f"bucket_{bucket}"
        ]
        return sha256_hash(parts)

    if vuln_type == "DAST":
        if systemic:
            parts = [
                vuln_type,
                rule_id,
                asset.identifier
            ]
        else:
            parts = [
                vuln_type,
                rule_id,
                asset.identifier,
                location.param if location else ""
            ]
        return sha256_hash(parts)

    return sha256_hash([vuln_type, rule_id, asset.identifier])