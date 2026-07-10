from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class NormalizedVuln(BaseModel):
    # Identity
    vuln_id: str                          # scanner_type + plugin_id + ip + port
    source_scanner: str                   # "nessus" | "openvas" | "qualys"

    # Host
    host_ip: str
    hostname: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None        # "tcp" | "udp"

    # Vulnerability
    cve_ids: list[str] = Field(default_factory=list)
    plugin_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None   # "2.0" | "3.0" | "3.1"

    # Fix
    solution: Optional[str] = None

    # Debug
    raw_data: Optional[dict] = None
