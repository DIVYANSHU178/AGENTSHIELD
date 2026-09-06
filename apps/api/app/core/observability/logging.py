"""
Centralized structured logging and secret redaction for AgentShield Observability.

Provides JSON-structured logging in production and QA, formatted readable logging in development,
and automated redaction of sensitive credentials, tokens, and secret material.
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.config.settings import settings
from app.core.observability.correlation import get_correlation_id


INLINE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|token|api_?key|secret|credential|session_?id|session_?token)\b\s*[:=]\s*([^\s,;'\"]+)"
)


def _sanitize_str(val: str) -> str:
    """Safely sanitize a string against sensitive patterns."""
    if not isinstance(val, str):
        val = str(val)
    try:
        from app.security.audit.redaction import sanitize_string_value
        val = sanitize_string_value(val)
    except Exception:
        pass
    val = INLINE_SECRET_PATTERN.sub(r"\1: [REDACTED]", val)
    return val


def _sanitize_payload(val: Any) -> Any:
    """Safely sanitize payloads against sensitive patterns."""
    try:
        from app.security.audit.redaction import sanitize_audit_payload
        return sanitize_audit_payload(val)
    except Exception:
        return val


def _clean_string_for_log(val: str) -> str:
    """Sanitize secrets and escape control characters / newlines to prevent log injection."""
    sanitized = _sanitize_str(val)
    cleaned = sanitized.replace("\r", "\\r").replace("\n", "\\n")
    return cleaned


class RedactingFilter(logging.Filter):
    """
    Logging filter that sanitizes all record messages, arguments, and extra fields
    using AgentShield's Phase 15 redaction boundary before formatting.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Sanitize msg
        if isinstance(record.msg, str):
            record.msg = _sanitize_str(record.msg)

        # Sanitize record.args if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = _sanitize_payload(record.args)
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(
                    _sanitize_str(a) if isinstance(a, str)
                    else (_sanitize_payload(a) if isinstance(a, (dict, list)) else a)
                    for a in record.args
                )

        # Ensure correlation_id is present on record
        if not hasattr(record, "correlation_id") or not record.correlation_id:
            record.correlation_id = get_correlation_id()

        # Ensure environment is present
        if not hasattr(record, "environment"):
            record.environment = getattr(settings, "ENVIRONMENT", "unknown")

        return True


class StructuredJsonFormatter(logging.Formatter):
    """
    JSON-structured log formatter for Production and QA environments.
    Produces deterministic, single-line JSON log lines with standardized schema.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Build base payload
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

        # Format message safely
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        sanitized_message = _sanitize_str(message)

        log_data: Dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "environment": getattr(record, "environment", getattr(settings, "ENVIRONMENT", "production")),
            "correlation_id": getattr(record, "correlation_id", get_correlation_id()),
            "message": sanitized_message,
        }

        # Optional structured operational fields
        for field in ("actor", "user_id", "event", "outcome", "duration_ms", "component", "status_code", "path", "method"):
            val = getattr(record, field, None)
            if val is not None:
                if isinstance(val, str):
                    log_data[field] = _sanitize_str(val)
                elif isinstance(val, (int, float, bool)):
                    log_data[field] = val
                else:
                    log_data[field] = _sanitize_payload(val)

        # Extra metadata dictionary if supplied
        extra_meta = getattr(record, "metadata", None)
        if isinstance(extra_meta, dict):
            log_data["metadata"] = _sanitize_payload(extra_meta)

        # Include sanitized exception information if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else "UnknownException",
                "message": _sanitize_str(str(record.exc_info[1])),
            }
            if settings.is_dev_mode():
                # In development only, format sanitized traceback
                formatted_tb = self.formatException(record.exc_info)
                log_data["exception"]["traceback"] = _sanitize_str(formatted_tb)

        return json.dumps(log_data, ensure_ascii=True, default=str)


class DevelopmentConsoleFormatter(logging.Formatter):
    """
    Readable terminal formatter for Development environment.
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        corr_id = getattr(record, "correlation_id", get_correlation_id())

        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        sanitized_msg = _clean_string_for_log(msg)

        event_str = f" [{record.event}]" if hasattr(record, "event") else ""
        outcome_str = f" ({record.outcome})" if hasattr(record, "outcome") else ""
        duration_str = f" in {record.duration_ms:.1f}ms" if hasattr(record, "duration_ms") else ""

        line = f"[{timestamp}] [{record.levelname:<5}] [{corr_id[:16]}] {record.name}{event_str}: {sanitized_msg}{outcome_str}{duration_str}"

        if record.exc_info and settings.is_dev_mode():
            line += "\n" + _sanitize_str(self.formatException(record.exc_info))
        return line


def configure_logging(environment: Optional[str] = None, log_level: str = "INFO") -> None:
    """
    Centralized logging configuration for AgentShield application.
    Reconfigures root and application loggers to enforce structured logging and redaction.
    """
    env = environment or getattr(settings, "ENVIRONMENT", "production").lower()
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicate output
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)
    handler.addFilter(RedactingFilter())

    if env == "development":
        handler.setFormatter(DevelopmentConsoleFormatter())
    else:
        # Production and QA enforce structured JSON
        handler.setFormatter(StructuredJsonFormatter())

    root_logger.addHandler(handler)

    # Configure agentshield logger specifically
    shield_logger = logging.getLogger("agentshield")
    shield_logger.setLevel(numeric_level)


def get_logger(name: str = "agentshield") -> logging.Logger:
    """Retrieve or create an application logger pre-configured with the redacting filter."""
    logger = logging.getLogger(name)
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger
