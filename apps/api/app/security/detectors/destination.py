import re
from typing import List, Tuple, Optional, Set
from urllib.parse import urlparse
from app.security.models import (
    ToolRequest,
    SecurityContext,
    ThreatSignal,
    ThreatType,
    Severity,
    ActionType,
)
from app.security.detectors.base import BaseDetector
from app.security.detectors.utils import extract_text_fields

class DestinationDetector(BaseDetector):
    """
    Deterministic detector analyzing destinations, URLs, and network parameters for potential
    data exfiltration vectors, raw IP destinations, suspicious schemes, or combinations of sensitive targets with outbound actions.
    """

    NAME = "destination_detector"
    SUPPORTED_THREATS = (ThreatType.DATA_EXFILTRATION, ThreatType.MALICIOUS_DESTINATION)

    SUSPICIOUS_SCHEMES = {"ftp", "tftp", "gopher", "file", "telnet"}
    RAW_IP_REGEX = re.compile(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$", re.IGNORECASE)
    SENSITIVE_TARGET_REGEX = re.compile(r"(\.env|credentials|id_rsa|private_key|secrets|sandbox/sensitive)", re.IGNORECASE)

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
        seen_rules: Set[str] = set()

        text_fields = extract_text_fields(request)

        # 1. Inspect destination field or target URL for raw IP address
        dest_val = request.destination or ""
        target_val = request.target or ""

        for candidate_url, source_field in [(dest_val, "destination"), (target_val, "target")]:
            if not candidate_url:
                continue

            # Check raw IP destination
            if self.RAW_IP_REGEX.match(candidate_url):
                rule_key = f"raw_ip_{source_field}"
                if rule_key not in seen_rules:
                    signals.append(
                        ThreatSignal(
                            threat_type=ThreatType.MALICIOUS_DESTINATION,
                            severity=Severity.HIGH,
                            title="Suspicious Network Destination: Raw IP Target",
                            description=(
                                f"Field '{source_field}' specifies a raw IP address ('{candidate_url}') rather than a domain."
                            ),
                            confidence=0.85,
                            source=self.NAME,
                            evidence={
                                "field": source_field,
                                "destination": candidate_url,
                                "rule": "raw_ip_destination",
                            },
                        )
                    )
                    seen_rules.add(rule_key)

            # Check suspicious URL schemes
            try:
                parsed = urlparse(candidate_url)
                if parsed.scheme and parsed.scheme.lower() in self.SUSPICIOUS_SCHEMES:
                    rule_key = f"scheme_{parsed.scheme.lower()}_{source_field}"
                    if rule_key not in seen_rules:
                        signals.append(
                            ThreatSignal(
                                threat_type=ThreatType.MALICIOUS_DESTINATION,
                                severity=Severity.HIGH,
                                title=f"Suspicious Protocol Scheme: {parsed.scheme.upper()}",
                                description=(
                                    f"Field '{source_field}' uses insecure or unapproved protocol scheme '{parsed.scheme}'."
                                ),
                                confidence=0.90,
                                source=self.NAME,
                                evidence={
                                    "field": source_field,
                                    "scheme": parsed.scheme,
                                    "destination": candidate_url,
                                    "rule": "suspicious_scheme",
                                },
                            )
                        )
                        seen_rules.add(rule_key)
            except Exception:
                pass

        # 2. Contextual Exfiltration Check: Sensitive target + Outbound Action + External Destination
        is_outbound_action = request.action in (ActionType.SEND, ActionType.UPLOAD, ActionType.WRITE, ActionType.EXECUTE)
        is_sensitive_target = bool(self.SENSITIVE_TARGET_REGEX.search(target_val))
        has_destination = bool(dest_val and dest_val != "local")

        if is_sensitive_target and is_outbound_action and has_destination:
            rule_key = "sensitive_exfiltration_combination"
            if rule_key not in seen_rules:
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.DATA_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        title="Data Exfiltration Vector Detected",
                        description=(
                            f"Action '{request.action.value}' combines sensitive target '{target_val}' with external destination '{dest_val}'."
                        ),
                        confidence=0.95,
                        source=self.NAME,
                        evidence={
                            "action": request.action.value,
                            "target": target_val,
                            "destination": dest_val,
                            "rule": "sensitive_target_outbound_combination",
                        },
                    )
                )
                seen_rules.add(rule_key)

        return signals
