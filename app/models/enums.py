from enum import Enum


class VulnerabilityType(str, Enum):
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"
    SECRET = "SECRET"