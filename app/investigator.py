from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable

from .schemas import AnalyzeTicketRequest, AnalyzeTicketResponse, TransactionEntry
from .safety import (
    build_safe_customer_reply,
    contains_sensitive_request,
    contains_suspicious_third_party_ref,
    contains_unsafe_financial_promise,
    looks_like_prompt_injection,
)


@dataclass(frozen=True)
class CaseDecision:
    case_type: str
    department: str
    severity: str
    human_review_required: bool
    confidence: float
    reason_codes: list[str]


COMPLAINT_KEYWORDS = {
    "wrong_transfer": [
        # English
        "wrong number", "wrong account", "sent to wrong", "mistaken transfer", "wrong recipient",
        # Banglish (romanized Bangla)
        "vul number", "vul number e", "vul number e pathiechi", "vul number e taka pathiechi",
        "vul number e pathalam", "bhul number", "bhul number e", "vul account", "bhul account",
        "vul manush", "vul lok", "taka vul number e", "taka vul manush ke", "taka bhul number e",
        "sent to wrong", "send to wrong", "send korlam vul", "vul e pathiechi", "vul e pathalam",
        # Bangla (Unicode)
        "ভুল নম্বরে", "ভুল নাম্বারে", "ভুল নাম্বার", "ভুল অ্যাকাউন্টে", "ভুল একাউন্টে",
        "ভুল মানুষকে", "ভুল নম্বর", "ভুল নাম্বার", "ভুলে টাকা", "ভুলে পাঠিয়েছি",
        "ভুলে পাঠালাম", "ভুল ট্রান্সফার",
    ],
    "payment_failed": [
        # English
        "payment failed", "failed payment", "deducted", "money gone", "charged but failed",
        # Banglish
        "payment fail", "payment hocche na", "payment hoy nai", "taka keteche", "taka kete geche",
        "taka gone", "taka katche na", "taka katena", "deduct hoyeche", "katte parchi na",
        # Bangla
        "পেমেন্ট ব্যর্থ", "পেমেন্ট ফেইল", "টাকা কেটে গেছে", "টাকা কাটা হয়েছে", "টাকা কেটেছে",
        "টাকা গেছে", "পেমেন্ট হচ্ছে না", "পেমেন্ট হয়নি",
    ],
    "refund_request": [
        # English
        "refund", "money back", "return my money", "reversal",
        # Banglish
        "taka ferat", "taka ferot", "taka fira", "taka uthano", "ferot chai", "ferat chai",
        "taka pabo", "taka pawa jabe", "refund chai", "money back chai",
        # Bangla
        "টাকা ফেরত", "টাকা ফেরত চাই", "টাকা ফেরত দিন", "রিফান্ড", "টাকা উঠান",
        "টাকা ফেরত পাব",
    ],
    "duplicate_payment": [
        # English
        "charged twice", "duplicate", "double charged", "same payment twice",
        # Banglish
        "do bar charge", "dui bar cut", "duibar keteche", "abar keteche", "double katche",
        "duplicate payment", "dobbar charge",
        # Bangla
        "দুইবার চার্জ", "দুইবার কেটেছে", "আবার কেটেছে", "ডুপ্লিকেট পেমেন্ট",
    ],
    "merchant_settlement_delay": [
        # English
        "settlement", "merchant not received", "merchant payout", "merchant settlement",
        # Banglish
        "merchant taka pai nai", "merchant pabeni", "merchant paisa nai", "settlement delay",
        "payout delay", "merchant payment hold",
        # Bangla
        "মার্চেন্ট পেমেন্ট", "মার্চেন্ট টাকা পাইনি", "সেটেলমেন্ট", "পেমেন্ট পাইনি",
        "মার্চেন্ট পেমেন্ট আটকে",
    ],
    "agent_cash_in_issue": [
        # English
        "cash in", "agent cash", "agent did not add", "deposit through agent",
        # Banglish
        "agent taka diyechi", "agent kache taka diyechi", "agent cash in koreni",
        "agent taka add koreni", "deposit hoy nai",
        # Bangla
        "এজেন্ট ক্যাশ ইন", "এজেন্ট টাকা দিয়েছি", "এজেন্ট টাকা যোগ করেনি", "ক্যাশ ইন হয়নি",
    ],
    "phishing_or_social_engineering": [
        # English
        "otp", "pin", "password", "suspicious call", "scam", "phishing", "hack",
        # Banglish
        "otp dilam", "pin dilam", "password dilam", "scam hoyeche", "phishing hoyeche",
        "hack hoyeche", "jhamela", "dhokhabeli", "dhorabo", "fake call", "fake message",
        # Bangla
        "ওটিপি দিয়েছি", "পিন দিয়েছি", "পাসওয়ার্ড দিয়েছি", "স্ক্যাম", "ফিশিং", "হ্যাক",
        "ধোকাবাজি", "প্রতারণা",
    ],
}

DEPARTMENT_BY_CASE = {
    "wrong_transfer": "dispute_resolution",
    "payment_failed": "payments_ops",
    "refund_request": "customer_support",
    "duplicate_payment": "payments_ops",
    "merchant_settlement_delay": "merchant_operations",
    "agent_cash_in_issue": "agent_operations",
    "phishing_or_social_engineering": "fraud_risk",
    "other": "customer_support",
}


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def complaint_mentions(text: str, phrases: Iterable[str]) -> bool:
    normalized = normalize_text(text)
    return any(phrase in normalized for phrase in phrases)


def extract_money_amounts(text: str) -> list[float]:
    matches = re.findall(r"(?:bdt|tk|taka)?\s*([0-9]+(?:\.[0-9]+)?)", text, flags=re.IGNORECASE)
    amounts = []
    for match in matches:
        try:
            amounts.append(float(match))
        except ValueError:
            continue
    return amounts


def history_sorted(history: list[TransactionEntry]) -> list[TransactionEntry]:
    def parse_time(entry: TransactionEntry) -> datetime:
        try:
            return datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
        except ValueError:
            return datetime.min

    return sorted(history, key=parse_time, reverse=True)


# Priority scores for infer_case_type. When a complaint matches keywords from
# multiple buckets, the bucket with the highest score wins. Phishing / fraud
# indicators (OTP, PIN, scam, phishing) always beat a refund request because
# fraud risk is a safety escalation (§7.2 maps phishing → fraud_risk).
# "other" is the fallback when nothing matches.
CASE_TYPE_PRIORITY: dict[str, int] = {
    "phishing_or_social_engineering": 100,  # fraud indicators always escalate (§7.2)
    "duplicate_payment": 60,                # more specific than payment_failed when both match
    "wrong_transfer": 50,
    "payment_failed": 50,
    "refund_request": 50,
    "merchant_settlement_delay": 50,
    "agent_cash_in_issue": 50,
    "other": 0,
}


def infer_case_type(complaint: str, history: list[TransactionEntry]) -> str:
    normalized = normalize_text(complaint)
    matches: list[tuple[int, str]] = []
    for case_type, phrases in COMPLAINT_KEYWORDS.items():
        if any(phrase in normalized for phrase in phrases):
            matches.append((CASE_TYPE_PRIORITY.get(case_type, 0), case_type))

    if matches:
        # Tie-breaker: keep dictionary (insertion) order so the rule list is
        # still easy to read; the score does the real disambiguation.
        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1]

    if history:
        top = history[0]
        if top.type == "refund":
            return "refund_request"
        if top.type == "settlement":
            return "merchant_settlement_delay"
        if top.type == "cash_in":
            return "agent_cash_in_issue"
        if top.type == "payment" and top.status == "failed":
            return "payment_failed"

    return "other"


def infer_relevant_transaction(complaint: str, history: list[TransactionEntry], case_type: str) -> tuple[str | None, list[str]]:
    if not history:
        return None, ["no_transaction_history"]

    ordered = history_sorted(history)
    amounts = extract_money_amounts(complaint)
    normalized = normalize_text(complaint)

    candidates: list[tuple[int, TransactionEntry, list[str]]] = []
    for idx, entry in enumerate(ordered):
        score = 0
        reasons: list[str] = []

        if amounts and any(abs(entry.amount - amount) < 0.5 for amount in amounts):
            score += 4
            reasons.append("amount_match")

        if entry.transaction_id.lower() in normalized:
            score += 5
            reasons.append("id_match")

        if case_type == "wrong_transfer" and entry.type == "transfer":
            score += 3
            reasons.append("transfer_match")
        elif case_type == "payment_failed" and entry.type == "payment":
            score += 3
            reasons.append("payment_match")
        elif case_type == "refund_request" and entry.type == "refund":
            score += 3
            reasons.append("refund_match")
        elif case_type == "duplicate_payment" and entry.type == "payment":
            score += 3
            reasons.append("payment_match")
        elif case_type == "merchant_settlement_delay" and entry.type == "settlement":
            score += 3
            reasons.append("settlement_match")
        elif case_type == "agent_cash_in_issue" and entry.type == "cash_in":
            score += 3
            reasons.append("cash_in_match")

        if any(term in normalized for term in [entry.counterparty.lower(), entry.status.lower()]):
            score += 1
            reasons.append("metadata_match")

        if score > 0:
            candidates.append((score + max(0, 3 - idx), entry, reasons))

    if not candidates:
        return None, ["no_clear_transaction_match"]

    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1].transaction_id, sorted(set(candidates[0][2]))


def infer_evidence_verdict(complaint: str, transaction: TransactionEntry | None, case_type: str) -> str:
    if transaction is None:
        return "insufficient_data"

    normalized = normalize_text(complaint)
    if case_type == "wrong_transfer":
        if transaction.type == "transfer" and transaction.status == "completed":
            return "consistent"
        return "inconsistent"
    if case_type == "payment_failed":
        if transaction.type == "payment" and transaction.status in {"failed", "completed"}:
            return "consistent"
        return "inconsistent"
    if case_type == "refund_request":
        return "consistent" if "refund" in normalized or transaction.type == "refund" else "insufficient_data"
    if case_type == "duplicate_payment":
        return "consistent" if transaction.type == "payment" else "insufficient_data"
    if case_type == "merchant_settlement_delay":
        return "consistent" if transaction.type == "settlement" else "insufficient_data"
    if case_type == "agent_cash_in_issue":
        return "consistent" if transaction.type == "cash_in" else "insufficient_data"
    if case_type == "phishing_or_social_engineering":
        return "consistent" if any(token in normalized for token in ["otp", "pin", "password", "scam", "phishing"]) else "insufficient_data"
    return "insufficient_data"


def infer_severity(case_type: str, verdict: str, transaction: TransactionEntry | None, complaint: str) -> str:
    if case_type == "phishing_or_social_engineering":
        return "critical"
    if transaction and transaction.amount >= 50000:
        return "critical"
    if transaction and transaction.amount >= 10000:
        return "high"
    if case_type in {"wrong_transfer", "duplicate_payment", "merchant_settlement_delay", "agent_cash_in_issue"}:
        return "high"
    if case_type == "payment_failed":
        return "medium" if verdict == "consistent" else "high"
    if case_type == "refund_request":
        return "medium"
    return "medium"


def should_escalate(case_type: str, verdict: str, transaction: TransactionEntry | None, complaint: str) -> bool:
    if case_type == "phishing_or_social_engineering":
        return True
    if verdict == "insufficient_data":
        return True
    if transaction and transaction.amount >= 10000:
        return True
    if case_type in {"wrong_transfer", "duplicate_payment", "merchant_settlement_delay", "agent_cash_in_issue"}:
        return True
    return False


def build_templates(case_type: str, verdict: str, transaction_id: str | None) -> tuple[str, str, str]:
    tx_fragment = f"transaction {transaction_id}" if transaction_id else "the provided transaction history"

    summaries = {
        "wrong_transfer": f"Customer reports a wrong transfer tied to {tx_fragment}. Evidence is {verdict}.",
        "payment_failed": f"Customer reports a payment issue tied to {tx_fragment}. Evidence is {verdict}.",
        "refund_request": f"Customer is asking for a refund review for {tx_fragment}. Evidence is {verdict}.",
        "duplicate_payment": f"Customer reports a possible duplicate payment involving {tx_fragment}. Evidence is {verdict}.",
        "merchant_settlement_delay": f"Merchant settlement issue detected for {tx_fragment}. Evidence is {verdict}.",
        "agent_cash_in_issue": f"Agent cash-in issue detected for {tx_fragment}. Evidence is {verdict}.",
        "phishing_or_social_engineering": f"Suspicious or credential-seeking activity detected. Evidence is {verdict}.",
        "other": f"Case could not be mapped confidently from the available history. Evidence is {verdict}.",
    }

    actions = {
        "wrong_transfer": "Verify the transfer details against the provided history and escalate for dispute review.",
        "payment_failed": "Check the payment outcome and balance impact in the ledger.",
        "refund_request": "Review the case through the official support workflow and confirm next steps.",
        "duplicate_payment": "Check for duplicate settlement or duplicate authorization before any action is taken.",
        "merchant_settlement_delay": "Check merchant settlement batches and confirm the expected payout window.",
        "agent_cash_in_issue": "Verify the cash-in record with the agent and reconcile the balance ledger.",
        "phishing_or_social_engineering": "Warn the customer not to share credentials and route the case to fraud review.",
        "other": "Review the complaint manually and classify it using the full ticket context.",
    }

    replies = {
        "wrong_transfer": build_safe_customer_reply("We have noted your concern about the transfer and will review the transaction details through official support."),
        "payment_failed": build_safe_customer_reply("We have noted your payment concern and will review the transaction status through official support."),
        "refund_request": build_safe_customer_reply("We have noted your request and will review it through official support."),
        "duplicate_payment": build_safe_customer_reply("We have noted your duplicate payment concern and will review the transaction records through official support."),
        "merchant_settlement_delay": build_safe_customer_reply("We have noted your settlement concern and will review the merchant payout status through official support."),
        "agent_cash_in_issue": build_safe_customer_reply("We have noted your cash-in concern and will review the agent record through official support."),
        "phishing_or_social_engineering": build_safe_customer_reply("This looks like a suspicious request. Please do not share any credentials, and only use official support channels."),
        "other": build_safe_customer_reply("We have noted your case and will review it through official support channels."),
    }

    return summaries[case_type], actions[case_type], replies[case_type]


def decide_case(request: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    complaint = request.complaint
    if looks_like_prompt_injection(complaint):
        case_type = "phishing_or_social_engineering"
        department = "fraud_risk"
        verdict = "consistent"
        relevant_transaction_id = None
        severity = "critical"
        human_review_required = True
        reason_codes = ["prompt_injection", "fraud_risk"]
        summary, action, reply = build_templates(case_type, verdict, relevant_transaction_id)
        return AnalyzeTicketResponse(
            ticket_id=request.ticket_id,
            relevant_transaction_id=relevant_transaction_id,
            evidence_verdict=verdict,
            case_type=case_type,
            severity=severity,
            department=department,
            agent_summary=summary,
            recommended_next_action=action,
            customer_reply=reply,
            human_review_required=human_review_required,
            confidence=0.95,
            reason_codes=reason_codes,
        )

    case_type = infer_case_type(complaint, request.transaction_history)
    relevant_transaction_id, transaction_reason_codes = infer_relevant_transaction(
        complaint, request.transaction_history, case_type
    )
    transaction = next((entry for entry in request.transaction_history if entry.transaction_id == relevant_transaction_id), None)
    verdict = infer_evidence_verdict(complaint, transaction, case_type)
    severity = infer_severity(case_type, verdict, transaction, complaint)
    department = DEPARTMENT_BY_CASE[case_type]
    human_review_required = should_escalate(case_type, verdict, transaction, complaint)

    reason_codes = [case_type, verdict]
    reason_codes.extend(transaction_reason_codes)
    if transaction:
        reason_codes.append(f"txn_{transaction.type}")
        if transaction.status != "completed":
            reason_codes.append(f"status_{transaction.status}")
    if human_review_required:
        reason_codes.append("human_review")

    if contains_sensitive_request(complaint):
        reason_codes.append("sensitive_request_detected")
    if contains_unsafe_financial_promise(complaint):
        reason_codes.append("promise_guard")
    if contains_suspicious_third_party_ref(complaint):
        reason_codes.append("official_channels_only")

    summary, action, reply = build_templates(case_type, verdict, relevant_transaction_id)

    confidence_map = {
        "consistent": 0.92,
        "inconsistent": 0.83,
        "insufficient_data": 0.55,
    }

    confidence = confidence_map[verdict]
    if case_type == "other":
        confidence = 0.45
    if not request.transaction_history:
        confidence = min(confidence, 0.5)

    return AnalyzeTicketResponse(
        ticket_id=request.ticket_id,
        relevant_transaction_id=relevant_transaction_id,
        evidence_verdict=verdict,
        case_type=case_type,
        severity=severity,
        department=department,
        agent_summary=summary,
        recommended_next_action=action,
        customer_reply=reply,
        human_review_required=human_review_required,
        confidence=round(confidence, 2),
        reason_codes=reason_codes,
    )
