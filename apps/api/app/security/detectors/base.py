from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from app.security.models import ToolRequest, SecurityContext, ThreatSignal, ThreatType

class BaseDetector(ABC):
    """
    Abstract base class for all deterministic AgentShield threat detectors.
    Detectors inspect ToolRequest and SecurityContext to produce zero or more ThreatSignal objects.
    
    CRITICAL CONTRACT RULES:
    - Detectors MUST be stateless and deterministic.
    - Detectors MUST NOT produce RiskAssessment or SecurityDecision objects.
    - Detectors MUST NOT execute shell commands, tools, or network calls.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier name of the detector."""
        pass

    @property
    @abstractmethod
    def supported_threat_types(self) -> Tuple[ThreatType, ...]:
        """Tuple of ThreatType classifications this detector can produce."""
        pass

    @abstractmethod
    def detect(
        self,
        request: ToolRequest,
        context: Optional[SecurityContext] = None,
    ) -> List[ThreatSignal]:
        """
        Inspect the given ToolRequest (and optional SecurityContext) and return a list of detected ThreatSignals.
        """
        pass
