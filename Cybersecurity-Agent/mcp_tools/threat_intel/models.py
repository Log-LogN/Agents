from __future__ import annotations

from pydantic import BaseModel, Field


class EpssRequest(BaseModel):
    cve: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")


class EpssData(BaseModel):
    cve: str
    epss: float = Field(..., ge=0.0, le=1.0)
    percentile: float = Field(..., ge=0.0, le=1.0)


class ExploitCheckRequest(BaseModel):
    cve: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")


class ExploitCheckData(BaseModel):
    cve: str
    exploit_available: bool
    source: str


class KevCheckRequest(BaseModel):
    cve: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")


class KevCheckData(BaseModel):
    cve: str
    in_kev: bool

