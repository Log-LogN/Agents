from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class RiskRequest(BaseModel):
    cvss: float = Field(..., ge=0.0, le=10.0)
    epss: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    exploit_available: bool = False
    internet_exposed: bool = False
    open_ports: List[int] = Field(default_factory=list)
    in_kev: bool = False


class RiskResponse(BaseModel):
    overall_score: float = Field(..., ge=0.0, le=10.0)
    severity: str
    reasons: List[str] = Field(default_factory=list)
    recommended_priority: str

