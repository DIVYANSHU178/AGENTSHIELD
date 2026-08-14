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
from app.security.detectors.utils import extract_text_fields, normalize_text

class CredentialDetector(BaseDetector):
    """
    Deterministic detector identifying attempts to access, read, or manipulate credential files,
    private key stores, API tokens, or sensitive configuration paths.
    """

    NAME = "credential_detector"
    SUPPORTED_THREATS = (ThreatType.CREDENTIAL_ACCESS,)

    # Categorized credential patterns
    PATTERNS: Dict[str, Tuple[str, List[str], Severity]] = {
        "sensitive_file_target": (
            "Access to Environment/Credential Configuration File",
            [
                r"(?:^|[\s/\\.]|\b)\.env(?:\.[a-zA-Z0-9_-]+)?(?:\b|$)",
                r"\bcredentials\.json\b",
                r"\bcredentials\.xml\b",
                r"\bsecrets\.json\b",
                r"\bsecrets\.yaml\b",
                r"\bsecrets\.yml\b",
                r"\bconfig\.json\b",
                r"(?:^|[/\\]|\b)application_default_credentials\.json(?:\b|$)",
                r"(?:^|[/\\]|\b)(?:cloud[/\\\.])?aws[/\\]credentials(?:\b|$)",
                r"(?:^|[/\\]|\b)(?:cloud[/\\\.])?aws[/\\]config(?:\b|$)",
                r"(?:^|[/\\]|\b)(?:cloud[/\\\.])?azure[/\\]credentials(?:\b|$)",
            ],
            Severity.HIGH,
        ),
        "ssh_private_key": (
            "Access to SSH Private Key / Certificate Store",
            [
                r"\.ssh(?:/|\\|$)",
                r"\bid_rsa\b",
                r"\bid_ed25519\b",
                r"\bid_ecdsa\b",
                r"\bid_dsa\b",
                r"\bprivate_key\b",
                r"\bprivate-key\b",
                r"\b\.pem\b",
            ],
            Severity.CRITICAL,
        ),
        "cloud_api_credentials": (
            "Access to Cloud / API Credential Identifier",
            [
                r"\bapi[_-]?key\b",
                r"\bcloud[_-]?api[_-]?key\b",
                r"\baccess[_-]?token\b",
                r"\brefresh[_-]?token\b",
                r"\bclient[_-]?secret\b",
                r"\bservice[_-]?account\b",
                r"\baws[_-]?access[_-]?key[_-]?id\b",
                r"\baws[_-]?secret[_-]?access[_-]?key\b",
            ],
            Severity.HIGH,
        ),
        "sensitive_sandbox_path": (
            "Access to Restricted Sensitive Sandbox Target",
            [
                r"sandbox/sensitive/",
                r"sandbox\\sensitive\\",
                r"credentials-placeholder\.txt",
            ],
            Severity.HIGH,
        ),
        "password_store": (
            "Access to Password Store / Vault",
            [
                r"\bpassword[s]?\b",
                r"\bshadow\b",
                r"\bhtpasswd\b",
                r"\bkeychain\b",
            ],
            Severity.HIGH,
        ),
    }

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
            normalized_value = normalize_text(raw_value)
            if not normalized_value:
                continue

            for category_key, (cat_title, patterns, severity) in self.PATTERNS.items():
                dedup_key = (field_path, category_key)
                if dedup_key in seen_rules_per_field:
                    continue

                for pattern in patterns:
                    match = re.search(pattern, normalized_value)
                    if match:
                        matched_str = match.group(0)
                        signals.append(
                            ThreatSignal(
                                threat_type=ThreatType.CREDENTIAL_ACCESS,
                                severity=severity,
                                title=f"Credential Access Detected: {cat_title}",
                                description=(
                                    f"Target parameter field '{field_path}' references credential category '{category_key}'."
                                ),
                                confidence=0.95,
                                source=self.NAME,
                                evidence={
                                    "field": field_path,
                                    "category": category_key,
                                    "matched_pattern": matched_str,
                                    "safe_target": raw_value if len(raw_value) < 100 else raw_value[:100] + "...",
                                },
                            )
                        )
                        seen_rules_per_field.add(dedup_key)
                        break

        return signals
