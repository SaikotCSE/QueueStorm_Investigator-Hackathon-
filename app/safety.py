from __future__ import annotations

import re

PROMPT_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"disregard above",
    r"system prompt",
    r"developer message",
    r"jailbreak",
    r"reveal.*prompt",
]

SENSITIVE_REQUEST_PATTERNS = [
    r"\bpin\b",
    r"\botp\b",
    r"password",
    r"full card number",
    r"card number",
    r"cvv",
]

UNAUTHORIZED_PROMISE_PATTERNS = [
    r"refund",
    r"reversal",
    r"account unblock",
    r"recover[y|ies]",
]

SUSPICIOUS_THIRD_PARTY_PATTERNS = [
    r"contact .*agent",
    r"contact .*person",
    r"call this number",
    r"whatsapp",
    r"telegram",
]


def contains_any_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def looks_like_prompt_injection(text: str) -> bool:
    return contains_any_pattern(text, PROMPT_INJECTION_PATTERNS)


def contains_sensitive_request(text: str) -> bool:
    return contains_any_pattern(text, SENSITIVE_REQUEST_PATTERNS)


def contains_unsafe_financial_promise(text: str) -> bool:
    return contains_any_pattern(text, UNAUTHORIZED_PROMISE_PATTERNS)


def contains_suspicious_third_party_ref(text: str) -> bool:
    return contains_any_pattern(text, SUSPICIOUS_THIRD_PARTY_PATTERNS)


def build_safe_customer_reply(message: str) -> str:
    return (
        f"{message} Please do not share sensitive credentials. "
        "We will review the case through official support channels and update you if any eligible action is confirmed."
    )
