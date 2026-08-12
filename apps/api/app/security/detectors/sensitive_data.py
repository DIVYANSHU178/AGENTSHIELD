import re
from typing import List, Tuple, Optional, Dict, Set
from app.security.models import (
    ToolRequest,
    SecurityContext,
    ThreatSignal,
    ThreatType,
    Severity,
)
from app.security.detectors.base import BaseDetector
from app.security.detectors.utils import extract_text_fields

def is_luhn_valid(card_str: str) -> bool:
    """Validate a digit sequence using the Luhn algorithm."""
    digits = [int(d) for d in card_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def redact_string(value: str) -> str:
    """Redact sensitive value leaving at most 4 trailing characters visible."""
    if not value:
        return ""
    clean = value.strip()
    if len(clean) <= 4:
        return "****"
    return "*" * (len(clean) - 4) + clean[-4:]

class SensitiveDataDetector(BaseDetector):
    """
    Deterministic detector identifying sensitive data patterns (API keys, credit cards, emails,
    phone numbers, IP addresses, Aadhaar, PAN) within request parameters.
    """

    NAME = "sensitive_data_detector"
    SUPPORTED_THREATS = (ThreatType.SENSITIVE_DATA_ACCESS,)

    # Regex patterns for deterministic matching
    PATTERNS: Dict[str, Tuple[str, str, Severity]] = {
        "api_key": (
            "API Key or Secret Token Pattern",
            r"(?:sk-proj-[a-zA-Z0-9_-]{15,}|sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|api[_-]?key\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{16,})",
            Severity.HIGH,
        ),
        "email_address": (
            "Email Address",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            Severity.LOW,
        ),
        "phone_number": (
            "Phone Number Pattern",
            r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            Severity.MEDIUM,
        ),
        "ip_address": (
            "IPv4 Address Pattern",
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            Severity.MEDIUM,
        ),
        "aadhaar_number": (
            "Aadhaar Identifier Pattern",
            r"\b[2-9]{1}\d{3}\s?\d{4}\s?\d{4}\b",
            Severity.HIGH,
        ),
        "pan_number": (
            "PAN Card Identifier Pattern",
            r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            Severity.HIGH,
        ),
    }

    # Credit card digit extraction pattern
    CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def supported_threat_types(self) -> Tuple[ThreatType, ...]:
        return self.SUPPORTED_THREATS

    def detect(
        self,
        request: ToolRequest,
        context: Optional[SecurityContext] = None,
    ) -> List[ThreatSignal]:
        signals: List[ThreatSignal] = []
        seen_rules_per_field: Set[Tuple[str, str]] = set()

        text_fields = extract_text_fields(request)

        for field_path, raw_value in text_fields:
            if not raw_value:
                continue

            # 1. Regex rule checks
            for category_key, (cat_title, pattern_str, severity) in self.PATTERNS.items():
                dedup_key = (field_path, category_key)
                if dedup_key in seen_rules_per_field:
                    continue

                match = re.search(pattern_str, raw_value, re.IGNORECASE if category_key != "pan_number" else 0)
                if match:
                    matched_str = match.group(0)
                    signals.append(
                        ThreatSignal(
                            threat_type=ThreatType.SENSITIVE_DATA_ACCESS,
                            severity=severity,
                            title=f"Sensitive Data Detected: {cat_title}",
                            description=(
                                f"Field '{field_path}' contains sensitive data pattern matching '{category_key}'."
                            ),
                            confidence=0.85 if category_key in ["phone_number", "ip_address"] else 0.95,
                            source=self.NAME,
                            evidence={
                                "field": field_path,
                                "category": category_key,
                                "redacted_value": redact_string(matched_str),
                                "redacted": True,
                            },
                        )
                    )
                    seen_rules_per_field.add(dedup_key)

            # 2. Credit Card Luhn Check
            dedup_cc_key = (field_path, "credit_card")
            if dedup_cc_key not in seen_rules_per_field:
                for cc_match in self.CARD_REGEX.finditer(raw_value):
                    candidate = cc_match.group(0)
                    if is_luhn_valid(candidate):
                        signals.append(
                            ThreatSignal(
                                threat_type=ThreatType.SENSITIVE_DATA_ACCESS,
                                severity=Severity.CRITICAL,
                                title="Sensitive Data Detected: Payment Card Number",
                                description=f"Field '{field_path}' contains a Luhn-validated payment card number.",
                                confidence=0.98,
                                source=self.NAME,
                                evidence={
                                    "field": field_path,
                                    "category": "credit_card",
                                    "redacted_value": redact_string(candidate),
                                    "redacted": True,
                                },
                            )
                        )
                        seen_rules_per_field.add(dedup_cc_key)
                        break

        return signals
