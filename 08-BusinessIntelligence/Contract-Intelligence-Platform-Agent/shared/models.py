"""shared/models.py — Pydantic models for contracts, obligations, and agents."""

from datetime import date, datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr


class ContractBase(BaseModel):
    title: str
    contract_type: str
    party_a_name: Optional[str] = None
    party_b_name: Optional[str] = None
    party_a_email: Optional[str] = None
    party_b_email: Optional[str] = None
    value: Optional[float] = 0.0
    currency: Optional[str] = "USD"
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    renewal_date: Optional[date] = None
    jurisdiction: Optional[str] = None
    content: Optional[str] = None


class ContractCreate(ContractBase):
    template_id: Optional[int] = None
    created_by: Optional[int] = None
    owner_id: Optional[int] = None


class ContractResponse(ContractBase):
    id: int
    contract_number: str
    status: str
    risk_score: int = 0
    risk_flags: List[Any] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ObligationCreate(BaseModel):
    contract_id: int
    obligation_type: str
    description: str
    owner_email: Optional[str] = None
    due_date: Optional[date] = None
    priority: Optional[str] = "MEDIUM"
    amount: Optional[float] = None


class AgentRequest(BaseModel):
    message: str
    user_id: int = 1
    session_id: str = "default"
    role: str = "viewer"
    contract_id: Optional[int] = None


class AgentResponse(BaseModel):
    response: str
    intent: str = "UNKNOWN"
    duration_ms: int = 0
    error: str = ""
    contract_id: Optional[int] = None
