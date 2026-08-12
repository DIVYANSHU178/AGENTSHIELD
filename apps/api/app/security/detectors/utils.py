import re
import unicodedata
from typing import List, Tuple, Any, Dict
from app.security.models import ToolRequest

def normalize_text(text: str) -> str:
    """
    Normalize text for deterministic matching:
    1. Unicode normalization (NFKD)
    2. Lowercase conversion
    3. Collapse multiple whitespace characters into single space
    """
    if not text:
        return ""
    # Unicode decomposition
    normalized = unicodedata.normalize("NFKD", text)
    # Lowercase
    lowered = normalized.lower()
    # Collapse whitespace
    collapsed = re.sub(r"\s+", " ", lowered).strip()
    return collapsed

def extract_text_fields(
    request: ToolRequest, max_depth: int = 10
) -> List[Tuple[str, str]]:
    """
    Safely extract textual fields from a ToolRequest in a bounded, deterministic manner.
    Returns a list of (field_path, raw_text_value) tuples.
    """
    extracted: List[Tuple[str, str]] = []

    if request.tool_name:
        extracted.append(("tool_name", request.tool_name))
    if request.target:
        extracted.append(("target", request.target))
    if request.destination:
        extracted.append(("destination", request.destination))

    # Recursively extract parameters
    if request.parameters:
        _extract_recursive(request.parameters, "parameters", extracted, current_depth=1, max_depth=max_depth)

    # Recursively extract metadata
    if request.metadata:
        _extract_recursive(request.metadata, "metadata", extracted, current_depth=1, max_depth=max_depth)

    return extracted

def _extract_recursive(
    data: Any,
    path: str,
    extracted: List[Tuple[str, str]],
    current_depth: int,
    max_depth: int,
) -> None:
    if current_depth > max_depth:
        return

    if isinstance(data, str):
        if data.strip():
            extracted.append((path, data))
    elif isinstance(data, dict):
        for key, value in data.items():
            sub_path = f"{path}.{key}" if path else str(key)
            _extract_recursive(value, sub_path, extracted, current_depth + 1, max_depth)
    elif isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            sub_path = f"{path}[{idx}]"
            _extract_recursive(item, sub_path, extracted, current_depth + 1, max_depth)
    else:
        # Convert non-string primitives (int, float, bool) to string if relevant
        str_val = str(data)
        if str_val.strip():
            extracted.append((path, str_val))
