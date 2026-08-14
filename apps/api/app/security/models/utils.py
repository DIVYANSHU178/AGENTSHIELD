import copy
import uuid
from datetime import datetime, timezone
from typing import Any

class FrozenDict(dict):
    """
    Immutable dictionary subclass that blocks all in-place mutations.
    Integrates seamlessly with Pydantic V2 models, JSON serialization, and deepcopy.
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def __setitem__(self, key: Any, value: Any) -> None:
        raise TypeError("FrozenDict is immutable; item assignment is not permitted.")

    def __delitem__(self, key: Any) -> None:
        raise TypeError("FrozenDict is immutable; item deletion is not permitted.")

    def pop(self, *args, **kwargs) -> Any:
        raise TypeError("FrozenDict is immutable; pop is not permitted.")

    def popitem(self, *args, **kwargs) -> Any:
        raise TypeError("FrozenDict is immutable; popitem is not permitted.")

    def update(self, *args, **kwargs) -> None:
        raise TypeError("FrozenDict is immutable; update is not permitted.")

    def clear(self) -> None:
        raise TypeError("FrozenDict is immutable; clear is not permitted.")

    def setdefault(self, *args, **kwargs) -> Any:
        raise TypeError("FrozenDict is immutable; setdefault is not permitted.")

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: Any) -> "FrozenDict":
        copied = {copy.deepcopy(k, memo): copy.deepcopy(v, memo) for k, v in self.items()}
        res = FrozenDict.__new__(FrozenDict)
        dict.__init__(res, copied)
        return res

    def __reduce__(self) -> Any:
        return (FrozenDict, (dict(self),))


def deep_freeze(val: Any) -> Any:
    """
    Recursively convert nested mutable collections (dict -> FrozenDict, list -> tuple, set -> frozenset)
    into deeply immutable structures.
    """
    if isinstance(val, (FrozenDict, frozenset)):
        return val
    if isinstance(val, dict):
        return FrozenDict({k: deep_freeze(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)):
        return tuple(deep_freeze(x) for x in val)
    if isinstance(val, set):
        return frozenset(deep_freeze(x) for x in val)
    return val


def generate_uuid() -> str:
    """Generate a standard string representation of a UUID4."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return timezone-aware current UTC timestamp."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime object is timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
