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

class PromptInjectionDetector(BaseDetector):
    """
    Deterministic detector for prompt injection, jailbreak attempts, and instruction overrides.
    Inspects textual fields within a ToolRequest for known injection patterns.
    """

    NAME = "prompt_injection_detector"
    SUPPORTED_THREATS = (ThreatType.PROMPT_INJECTION,)

    # Categorized deterministic rules and patterns
    RULES: Dict[str, Tuple[str, List[str]]] = {
        "instruction_override": (
            "Instruction Override Attempt",
            [
                r"\bignore\s+(?:all\s+)?previous\s+instructions\b",
                r"\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
                r"\bforget\s+(?:your|all)\s+instructions\b",
                r"\boverride\s+(?:your|all)\s+instructions\b",
                r"\bignore\s+(?:all\s+)?above\s+instructions\b",
            ],
        ),
        "role_manipulation": (
            "Role or System Manipulation",
            [
                r"\byou\s+are\s+now\b",
                r"\bact\s+as\s+(?:a\s+)?system\b",
                r"\bsystem\s+message\s*:",
                r"\bdeveloper\s+message\s*:",
                r"\bassistant\s+instructions\b",
                r"\bnew\s+persona\b",
            ],
        ),
        "security_bypass": (
            "Security Safeguard Bypass",
            [
                r"\bbypass\s+security\b",
                r"\bdisable\s+security\b",
                r"\bdisable\s+safeguards\b",
                r"\bremove\s+restrictions\b",
                r"\bignore\s+safety\b",
                r"\bturn\s+off\s+safety\b",
                r"\boverride\s+security\b",
            ],
        ),
        "jailbreak": (
            "Jailbreak Language Pattern",
            [
                r"\bjailbreak\b",
                r"\bdo\s+anything\s+now\b",
                r"\bdeveloper\s+mode\b",
                r"\bunrestricted\s+mode\b",
                r"\bno\s+restrictions\b",
                r"\bdan\s+mode\b",
            ],
        ),
        "hidden_instruction": (
            "Hidden Instruction Attempt",
            [
                r"\bfollow\s+these\s+instructions\s+instead\b",
                r"\bnew\s+instructions\s*:",
                r"\byour\s+new\s+task\s+is\b",
                r"\bexecute\s+these\s+instructions\b",
            ],
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

            for rule_key, (rule_title, patterns) in self.RULES.items():
                dedup_key = (field_path, rule_key)
                if dedup_key in seen_rules_per_field:
                    continue

                for pattern in patterns:
                    match = re.search(pattern, normalized_value)
                    if match:
                        matched_str = match.group(0)
                        signals.append(
                            ThreatSignal(
                                threat_type=ThreatType.PROMPT_INJECTION,
                                severity=Severity.HIGH,
                                title=f"Prompt Injection Detected: {rule_title}",
                                description=(
                                    f"Detected prompt injection pattern '{rule_key}' in request field '{field_path}'."
                                ),
                                confidence=0.90,
                                source=self.NAME,
                                evidence={
                                    "field": field_path,
                                    "rule": rule_key,
                                    "matched_pattern": matched_str,
                                },
                            )
                        )
                        seen_rules_per_field.add(dedup_key)
                        break

        return signals
