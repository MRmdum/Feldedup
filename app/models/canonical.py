from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from app.models.enums import VulnerabilityType


class Asset(BaseModel):
    kind: str
    identifier: str
    sub_identifier: Optional[str] = None


class Location(BaseModel):
    path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    param: Optional[str] = None


class Severity(BaseModel):
    scanner: Optional[str] = None
    normalized: Optional[str] = None
    cvss: Optional[float] = None


class Metadata(BaseModel):
    cwe: Optional[List[str]] = None
    systemic: Optional[bool] = False
    confidence: Optional[str] = None


class CanonicalVulnerability(BaseModel):
    id: str
    fingerprint: str
    source: List[str]
    type: VulnerabilityType
    vuln_class: Optional[str]
    scanner_rule_id: str
    title: str
    asset: Asset
    location: Optional[Location]
    severity: Optional[Severity]
    metadata: Optional[Metadata]
    first_seen: datetime
    last_seen: datetime
    raw: Dict[str, Any]