import pytest
from app.security.approval.contracts import ApprovalStatus
from app.security.approval.workflow import validate_state_transition
from app.security.approval.errors import InvalidApprovalStateTransitionError

def test_valid_approval_state_transitions():
    # All valid transitions from PENDING
    validate_state_transition(ApprovalStatus.PENDING, ApprovalStatus.APPROVED)
    validate_state_transition(ApprovalStatus.PENDING, ApprovalStatus.REJECTED)
    validate_state_transition(ApprovalStatus.PENDING, ApprovalStatus.EXPIRED)
    validate_state_transition(ApprovalStatus.PENDING, ApprovalStatus.CANCELLED)

def test_terminal_states_cannot_transition():
    terminal_states = [
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.EXPIRED,
        ApprovalStatus.CANCELLED,
    ]
    all_states = [
        ApprovalStatus.PENDING,
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.EXPIRED,
        ApprovalStatus.CANCELLED,
    ]

    for terminal in terminal_states:
        for target in all_states:
            with pytest.raises(InvalidApprovalStateTransitionError):
                validate_state_transition(terminal, target)
