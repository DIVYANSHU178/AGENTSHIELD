import copy
from typing import List, Optional, Iterable, Tuple, Set
from app.security.models import SecurityEvent, EventType
from app.security.audit.errors import InvalidSecurityEventError

TERMINAL_DECISION_EVENT_TYPES: Set[EventType] = {
    EventType.ALLOWED,
    EventType.BLOCKED,
    EventType.APPROVAL_REQUIRED,
}

class SecurityAuditTrail:
    """
    Authoritative, deterministic audit trail service for AgentShield.

    CRITICAL CONTRACT RULES:
    - AUDIT ONLY: Never grants execution authorization, never alters security decisions,
      never executes tools, commands, or network calls.
    - IMMUTABILITY & DEFENSIVE COPYING: Exposes recorded events via defensive snapshot copies.
      Callers cannot modify stored audit events or internal collection state.
    - ORDERING PRESERVATION: Preserves exact chronological insertion order.
    - CORRELATION: Enables filtering and sequence retrieval by request_id.
    - FAIL-SAFE: Safely rejects invalid or malformed event objects.
    - EXACT LIFECYCLE INVARIANT & IDEMPOTENCY: Exactly one REQUESTED, one ANALYZED, and one terminal decision
      event per logical security evaluation lifecycle.
    """

    def __init__(self) -> None:
        self._events: List[SecurityEvent] = []

    def record(self, event: SecurityEvent) -> None:
        """
        Record a SecurityEvent in the audit trail.
        Stores a defensive deepcopy to ensure external callers cannot mutate internal state.
        Raises InvalidSecurityEventError if event is None or malformed.
        """
        if event is None or not isinstance(event, SecurityEvent):
            raise InvalidSecurityEventError(
                f"Cannot record invalid audit event: expected SecurityEvent instance, got {type(event).__name__}."
            )

        if not event.request_id or not event.request_id.strip():
            raise InvalidSecurityEventError("Cannot record SecurityEvent with empty request_id.")

        if not event.actor or not event.actor.strip():
            raise InvalidSecurityEventError("Cannot record SecurityEvent with empty actor.")

        self._events.append(copy.deepcopy(event))

    def record_all(self, events: Iterable[SecurityEvent]) -> None:
        """Record multiple SecurityEvents sequentially."""
        if events is None:
            raise InvalidSecurityEventError("Events collection cannot be None.")
        for ev in events:
            self.record(ev)

    def get_events(self, request_id: Optional[str] = None) -> List[SecurityEvent]:
        """
        Retrieve recorded SecurityEvents.
        Returns a defensive deepcopy list so that modifying the returned collection
        or any returned event instance does NOT alter internal audit trail storage.
        """
        if request_id is not None:
            req_id_clean = request_id.strip()
            return [copy.deepcopy(e) for e in self._events if e.request_id == req_id_clean]
        return [copy.deepcopy(e) for e in self._events]

    def get_event_sequence(self, request_id: str) -> List[EventType]:
        """
        Retrieve the exact sequence of EventType values recorded for a request_id in insertion order.
        """
        if not request_id or not request_id.strip():
            return []
        events = self.get_events(request_id=request_id.strip())
        return [e.event_type for e in events]

    def has_terminal_event(self, request_id: str) -> bool:
        """
        Check if a terminal decision event (ALLOWED, APPROVAL_REQUIRED, BLOCKED)
        has already been recorded for this request_id.
        """
        if not request_id or not request_id.strip():
            return False
        return any(
            e.event_type in TERMINAL_DECISION_EVENT_TYPES
            for e in self.get_events(request_id=request_id.strip())
        )

    def has_gateway_lifecycle(self, request_id: str) -> bool:
        """
        Determine whether the canonical 3-event gateway lifecycle has been recorded for this request_id:
        1. EventType.REQUESTED
        2. EventType.ANALYZED
        3. Terminal decision (ALLOWED, APPROVAL_REQUIRED, or BLOCKED)

        Returns True ONLY if all three stages are present in chronological order for this request_id.
        Partial sequences return False.
        """
        if not request_id or not request_id.strip():
            return False

        events = self.get_events(request_id=request_id.strip())
        types = [e.event_type for e in events]

        has_requested = EventType.REQUESTED in types
        has_analyzed = EventType.ANALYZED in types
        has_terminal = any(t in TERMINAL_DECISION_EVENT_TYPES for t in types)

        if not (has_requested and has_analyzed and has_terminal):
            return False

        # Verify chronological sequence order
        req_idx = types.index(EventType.REQUESTED)
        analyzed_indices = [i for i, t in enumerate(types) if t == EventType.ANALYZED and i > req_idx]
        if not analyzed_indices:
            return False

        first_analyzed_idx = analyzed_indices[0]
        has_terminal_after_analyzed = any(
            t in TERMINAL_DECISION_EVENT_TYPES
            for i, t in enumerate(types)
            if i > first_analyzed_idx
        )
        return has_terminal_after_analyzed

    def get_gateway_lifecycle_events(self, request_id: str) -> List[SecurityEvent]:
        """
        Retrieve the canonical 3-event gateway lifecycle events (REQUESTED, ANALYZED, terminal decision)
        for this request_id if present.
        """
        if not self.has_gateway_lifecycle(request_id):
            return []

        events = self.get_events(request_id=request_id)
        canonical_events: List[SecurityEvent] = []

        # 1. First REQUESTED event
        req_event = next((e for e in events if e.event_type == EventType.REQUESTED), None)
        if not req_event:
            return []
        canonical_events.append(req_event)

        req_idx = events.index(req_event)

        # 2. First ANALYZED event after REQUESTED
        analyzed_event = next(
            (e for i, e in enumerate(events) if i > req_idx and e.event_type == EventType.ANALYZED),
            None,
        )
        if not analyzed_event:
            return []
        canonical_events.append(analyzed_event)

        analyzed_idx = events.index(analyzed_event)

        # 3. First terminal decision event after ANALYZED
        terminal_event = next(
            (e for i, e in enumerate(events) if i > analyzed_idx and e.event_type in TERMINAL_DECISION_EVENT_TYPES),
            None,
        )
        if not terminal_event:
            return []
        canonical_events.append(terminal_event)

        return canonical_events

    def count(self, request_id: Optional[str] = None) -> int:
        """Return count of recorded events."""
        return len(self.get_events(request_id=request_id))

    def clear(self) -> None:
        """Clear recorded events from this audit trail instance."""
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)
