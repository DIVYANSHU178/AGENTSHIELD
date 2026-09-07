"""
Standardized and Sanitized Request Validation Error Handling for AgentShield Phase 17.

Intercepts Pydantic and query/path parameter validation errors, sanitizing input
payloads to prevent sensitive data leakage while preserving detailed field issues
and propagating correlation attribution.
"""

from typing import List, Dict, Any
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi import status

from app.core.observability.correlation import get_correlation_id, generate_correlation_id
from app.core.observability.logging import get_logger
from app.security.audit.redaction import sanitize_string_value

logger = get_logger("agentshield.hardening.errors")


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Authoritative exception handler for FastAPI RequestValidationError.
    Returns HTTP 422 with sanitized field-level error messages and correlation metadata.
    """
    corr_id = None
    if hasattr(request, "state") and hasattr(request.state, "correlation_id"):
        raw_cid = request.state.correlation_id
        if isinstance(raw_cid, str) and raw_cid:
            corr_id = raw_cid
    if not corr_id:
        cid = get_correlation_id()
        corr_id = cid if (isinstance(cid, str) and cid) else generate_correlation_id()

    # Extract and sanitize errors
    raw_errors = exc.errors()
    sanitized_errors: List[Dict[str, Any]] = []

    for err in raw_errors:
        err_dict = {
            "type": err.get("type", "value_error"),
            "loc": err.get("loc", []),
            "msg": err.get("msg", "Invalid value"),
        }

        # If context or input is present, ensure sensitive fields are sanitized
        if "ctx" in err:
            sanitized_ctx = {}
            for k, v in err["ctx"].items():
                if isinstance(v, str):
                    sanitized_ctx[k] = sanitize_string_value(v)
                elif isinstance(v, (int, float, bool)):
                    sanitized_ctx[k] = v
                else:
                    sanitized_ctx[k] = str(v)
            err_dict["ctx"] = sanitized_ctx

        # Sanitize input if present (redact passwords/tokens/dictionaries)
        if "input" in err:
            raw_input = err["input"]
            loc = [str(x).lower() for x in err.get("loc", [])]
            if any(sensitive_word in loc for sensitive_word in ("password", "secret", "token", "key")):
                err_dict["input"] = "[REDACTED]"
            elif isinstance(raw_input, (dict, list)):
                err_dict["input"] = "[COMPLEX_PAYLOAD]"
            elif isinstance(raw_input, str):
                if len(raw_input) > 100:
                    err_dict["input"] = sanitize_string_value(raw_input[:100]) + "..."
                else:
                    err_dict["input"] = sanitize_string_value(raw_input)
            else:
                err_dict["input"] = str(raw_input)

        sanitized_errors.append(err_dict)

    try:
        path = str(request.url.path)
        method = str(request.method)
    except Exception:
        path = "unknown"
        method = "unknown"

    logger.warning(
        f"Request validation failed on {method} {path}: {len(sanitized_errors)} field issue(s)",
        extra={
            "correlation_id": corr_id,
            "event": "VALIDATION_ERROR",
            "outcome": "REJECTED",
            "path": path,
            "method": method,
            "error_count": len(sanitized_errors),
        },
    )

    headers = {"X-Correlation-ID": corr_id}
    return JSONResponse(
        status_code=422,
        content={
            "detail": sanitized_errors,
            "correlation_id": corr_id,
        },
        headers=headers,
    )
