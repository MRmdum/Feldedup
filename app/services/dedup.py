from datetime import datetime
from app.models.canonical import CanonicalVulnerability
from app.services.storage import VULN_DB


def upsert_vulnerability(vuln: CanonicalVulnerability):

    if vuln.fingerprint in VULN_DB:
        existing = VULN_DB[vuln.fingerprint]
        existing.last_seen = datetime.utcnow()

        for src in vuln.source:
            if src not in existing.source:
                existing.source.append(src)

    else:
        VULN_DB[vuln.fingerprint] = vuln