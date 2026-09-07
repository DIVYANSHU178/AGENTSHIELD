from app.security.approval.contracts import ApprovalStatus
from app.security.approval.errors import InvalidApprovalStateTransitionError

# Valid non-terminal to terminal state transitions
ALLOWED_TRANSITIONS = {
    ApprovalStatus.PENDING: {
        ApprovalStatus.CLAIMED,
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.EXPIRED,
        ApprovalStatus.CANCELLED,
    },
    ApprovalStatus.CLAIMED: {
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.CANCELLED,
    },
}

def validate_state_transition(current_status: ApprovalStatus, target_status: ApprovalStatus) -> None:
    """
    Validate that a proposed lifecycle state transition is legally permitted.
    
    ALLOWED GRAPH:
        PENDING -> APPROVED
        PENDING -> REJECTED
        PENDING -> EXPIRED
        PENDING -> CANCELLED
        
    INVARIANTS:
    - No terminal state may transition to any other state.
    - Double resolutions are strictly rejected.
    """
    if current_status not in ALLOWED_TRANSITIONS:
        raise InvalidApprovalStateTransitionError(
            f"Cannot transition from terminal state '{current_status.value}' to '{target_status.value}'. "
            f"Terminal approval states are final and immutable."
        )

    allowed_targets = ALLOWED_TRANSITIONS[current_status]
    if target_status not in allowed_targets:
        raise InvalidApprovalStateTransitionError(
            f"Invalid transition from '{current_status.value}' to '{target_status.value}'. "
            f"Permitted transitions from '{current_status.value}': {[s.value for s in allowed_targets]}."
        )
