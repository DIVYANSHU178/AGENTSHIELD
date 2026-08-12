from typing import List, Optional, Dict
from app.security.models import ToolRequest, SecurityContext, ThreatSignal
from app.security.detectors.base import BaseDetector

class DetectorError(Exception):
    """Raised when a detector encounters an unrecoverable failure during inspection."""
    pass

class DetectorRegistry:
    """
    Registry for managing and executing AgentShield threat detectors in a deterministic sequence.
    """

    def __init__(self) -> None:
        self._detectors: Dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        """Register a detector instance. Raises ValueError if detector name is already registered."""
        if detector.name in self._detectors:
            raise ValueError(f"Detector with name '{detector.name}' is already registered.")
        self._detectors[detector.name] = detector

    def unregister(self, detector_name: str) -> None:
        """Unregister a detector by name."""
        self._detectors.pop(detector_name, None)

    def get_detectors(self) -> List[BaseDetector]:
        """Return registered detectors in deterministic insertion order."""
        return list(self._detectors.values())

    def detect_all(
        self,
        request: ToolRequest,
        context: Optional[SecurityContext] = None,
    ) -> List[ThreatSignal]:
        """
        Execute all registered detectors sequentially against the request and aggregate ThreatSignals.
        Raises DetectorError if any detector fails unexpectedly.
        """
        signals: List[ThreatSignal] = []

        for detector in self.get_detectors():
            try:
                detector_signals = detector.detect(request, context)
                if detector_signals:
                    signals.extend(detector_signals)
            except Exception as exc:
                raise DetectorError(
                    f"Detector '{detector.name}' failed during inspection of request '{request.request_id}': {str(exc)}"
                ) from exc

        return signals

def create_default_registry() -> DetectorRegistry:
    """Factory function creating a DetectorRegistry loaded with default Phase 2 detectors."""
    from app.security.detectors.prompt_injection import PromptInjectionDetector
    from app.security.detectors.credential import CredentialDetector
    from app.security.detectors.sensitive_data import SensitiveDataDetector
    from app.security.detectors.destination import DestinationDetector

    registry = DetectorRegistry()
    registry.register(PromptInjectionDetector())
    registry.register(CredentialDetector())
    registry.register(SensitiveDataDetector())
    registry.register(DestinationDetector())
    return registry
