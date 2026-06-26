from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Language = Literal["en", "bn", "mixed"]
Channel = Literal["in_app_chat", "call_center", "email", "merchant_portal", "field_agent"]
UserType = Literal["customer", "merchant", "agent", "unknown"]
TxnType = Literal["transfer", "payment", "cash_in", "cash_out", "settlement", "refund"]
TxnStatus = Literal["completed", "failed", "pending", "reversed"]
EvidenceVerdict = Literal["consistent", "inconsistent", "insufficient_data"]
CaseType = Literal[
    "wrong_transfer",
    "payment_failed",
    "refund_request",
    "duplicate_payment",
    "merchant_settlement_delay",
    "agent_cash_in_issue",
    "phishing_or_social_engineering",
    "other",
]
Severity = Literal["low", "medium", "high", "critical"]
Department = Literal[
    "customer_support",
    "dispute_resolution",
    "payments_ops",
    "merchant_operations",
    "agent_operations",
    "fraud_risk",
]


class TransactionEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    transaction_id: str
    timestamp: str
    type: TxnType
    amount: float = Field(ge=0)
    counterparty: str
    status: TxnStatus

    @field_validator("transaction_id", "counterparty")
    @classmethod
    def fields_must_not_be_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("field must not be empty")
        return value


class AnalyzeTicketRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ticket_id: str
    complaint: str
    language: Language | None = None
    channel: Channel | None = None
    user_type: UserType | None = None
    campaign_context: str | None = None
    transaction_history: list[TransactionEntry] = Field(default_factory=list)
    metadata: dict | None = None

    @field_validator("ticket_id")
    @classmethod
    def ticket_id_must_not_be_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("ticket_id must not be empty")
        return value

    @field_validator("complaint")
    @classmethod
    def complaint_must_not_be_blank(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("complaint must not be empty")
        return value


class AnalyzeTicketResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ticket_id: str
    relevant_transaction_id: str | None
    evidence_verdict: EvidenceVerdict
    case_type: CaseType
    severity: Severity
    department: Department
    agent_summary: str
    recommended_next_action: str
    customer_reply: str
    human_review_required: bool
    confidence: float | None = Field(default=None, ge=0, le=1)
    reason_codes: list[str] | None = None
