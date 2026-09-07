import re
import unicodedata
import urllib.parse
from typing import List, Tuple, Any, Dict
from app.security.models import ToolRequest

# Zero-width and invisible control characters
# \u200b: zero-width space
# \u200c: zero-width non-joiner
# \u200d: zero-width joiner
# \ufeff: zero-width no-break space (BOM)
# \u00ad: soft hyphen
# \u2060: word joiner
# \u200e, \u200f: left-to-right / right-to-left marks
# \u202a-\u202e: directional embedding/overrides
ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad\u2060\u200e\u200f\u202a-\u202e]")

# Strip ASCII control characters except \t, \n, \r
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

LEET_MAP = str.maketrans({
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's',
    '!': 'i',
})

def translate_leetspeak(text: str) -> str:
    """Translates common leetspeak substitutions to standard characters."""
    return text.translate(LEET_MAP)

def apply_leetspeak_translation(text: str) -> str:
    """Alias for translate_leetspeak."""
    return translate_leetspeak(text)

def strip_zero_width_characters(text: str) -> str:
    """Remove zero-width and invisible directional characters."""
    return ZERO_WIDTH_RE.sub("", text)

def recursive_unquote(text: str, max_passes: int = 3) -> str:
    """Recursively decode URL percent-encoded characters up to max_passes."""
    current = text
    for _ in range(max_passes):
        if "%" not in current:
            break
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current

def normalize_text(text: str) -> str:
    """
    Normalize text for deterministic matching (SEC-09):
    1. Bounded recursive URL-decoding (up to 3 passes)
    2. Zero-width and control character stripping
    3. Unicode NFKC normalization (resolves full-width and homoglyphs)
    4. Lowercase conversion
    5. Collapse multiple whitespace characters into single space
    """
    if not text:
        return ""

    # 1. Bounded recursive URL-decoding
    current = text
    for _ in range(3):
        if "%" not in current:
            break
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded

    # 2. Strip zero-width characters and control characters
    cleaned = ZERO_WIDTH_RE.sub("", current)
    cleaned = CONTROL_CHAR_RE.sub("", cleaned)

    # 3. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", cleaned)

    # 4. Lowercase
    lowered = normalized.lower()

    # 5. Collapse whitespace
    collapsed = re.sub(r"\s+", " ", lowered).strip()
    return collapsed

def get_normalized_variants(text: str) -> List[str]:
    """
    Produces canonical and leetspeak-decoded normalized representations
    for comprehensive threat pattern matching.
    """
    canonical = normalize_text(text)
    if not canonical:
        return []

    variants = [canonical]
    leet_decoded = translate_leetspeak(canonical)
    if leet_decoded != canonical:
        variants.append(leet_decoded)

    return variants

def extract_text_fields(
    request: Any, max_depth: int = 10
) -> List[Tuple[str, str]]:
    """
    Safely extract textual fields from a ToolRequest (or raw string/dict) in a bounded, deterministic manner.
    Returns a list of (field_path, raw_text_value) tuples.
    """
    if isinstance(request, str):
        return [("text", request)] if request.strip() else []

    extracted: List[Tuple[str, str]] = []

    if hasattr(request, "tool_name") and request.tool_name:
        extracted.append(("tool_name", request.tool_name))
    if hasattr(request, "target") and request.target:
        extracted.append(("target", request.target))
    if hasattr(request, "destination") and request.destination:
        extracted.append(("destination", request.destination))

    # Recursively extract parameters
    params = getattr(request, "parameters", None)
    if params and isinstance(params, dict):
        _extract_recursive(params, "parameters", extracted, current_depth=1, max_depth=max_depth)

    # Recursively extract metadata
    meta = getattr(request, "metadata", None)
    if meta and isinstance(meta, dict):
        _extract_recursive(meta, "metadata", extracted, current_depth=1, max_depth=max_depth)

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
