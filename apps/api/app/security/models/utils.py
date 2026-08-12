import uuid
from datetime import datetime, timezone

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
