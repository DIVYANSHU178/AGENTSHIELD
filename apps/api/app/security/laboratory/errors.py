class ScenarioLaboratoryError(Exception):
    """Base exception for all Scenario and Attack Laboratory domain errors."""
    pass

class UnknownScenarioError(ScenarioLaboratoryError):
    """Raised when a scenario ID is not registered or cannot be resolved."""
    pass

class ScenarioExecutionError(ScenarioLaboratoryError):
    """Raised when a scenario fails during runner execution."""
    pass

class ScenarioValidationError(ScenarioLaboratoryError):
    """Raised when scenario input or configuration is invalid."""
    pass
