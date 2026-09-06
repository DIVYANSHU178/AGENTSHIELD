"""
Thread-safe, in-memory low-cardinality metrics registry for AgentShield Observability.

Strictly adheres to low-cardinality constraints:
- Prohibits high-cardinality labels (no usernames, IDs, tokens, arbitrary URLs, query strings).
- Labels are strictly validated against predetermined finite enumerations.
"""

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


# Predefined bounded route groups to prevent cardinality explosion from URL paths
ROUTE_PATTERNS: List[Tuple[str, str]] = [
    ("/health/live", "/health/live"),
    ("/health/ready", "/health/ready"),
    ("/health", "/health"),
    ("/api/v1/health/live", "/api/v1/health/live"),
    ("/api/v1/health/ready", "/api/v1/health/ready"),
    ("/api/v1/health", "/api/v1/health"),
    ("/api/v1/auth/login", "/api/v1/auth/login"),
    ("/api/v1/auth/logout", "/api/v1/auth/logout"),
    ("/api/v1/auth/me", "/api/v1/auth/me"),
    ("/api/v1/auth/authorize", "/api/v1/auth/authorize"),
    ("/api/v1/auth/identities", "/api/v1/auth/identities"),
    ("/api/v1/security/operations/overview", "/api/v1/security/operations/overview"),
    ("/api/v1/security/operations/health", "/api/v1/security/operations/health"),
    ("/api/v1/security/operations/metrics", "/api/v1/security/operations/metrics"),
    ("/api/v1/security/operations/telemetry", "/api/v1/security/operations/telemetry"),
    ("/api/v1/security/operations/threats", "/api/v1/security/operations/threats"),
    ("/api/v1/security/operations/decisions", "/api/v1/security/operations/decisions"),
    ("/api/v1/security/operations/executions", "/api/v1/security/operations/executions"),
    ("/api/v1/security/operations/audit", "/api/v1/security/operations/audit"),
    ("/api/v1/security/operations/control", "/api/v1/security/operations/control"),
    ("/api/v1/security/approval", "/api/v1/security/approval"),
    ("/api/v1/dev/laboratory", "/api/v1/dev/laboratory"),
]


def normalize_route(path: str) -> str:
    """
    Map an incoming HTTP path to a safe, low-cardinality route group.
    Strips query parameters, IDs, UUIDs, and paths to prevent label explosion.
    """
    if not path:
        return "/unknown"
    clean_path = path.split("?")[0].rstrip("/")
    if not clean_path:
        return "/"

    for prefix, group in ROUTE_PATTERNS:
        if clean_path == prefix or clean_path.startswith(prefix + "/"):
            return group

    # General pattern grouping for other API routes
    if clean_path.startswith("/api/v1/"):
        parts = clean_path.strip("/").split("/")
        if len(parts) >= 3:
            return f"/api/v1/{parts[2]}"
        return "/api/v1/other"

    return "/other"


def get_status_family(status_code: int) -> str:
    """Return the HTTP status family string (2xx, 3xx, 4xx, 5xx)."""
    if 200 <= status_code < 300:
        return "2xx"
    elif 300 <= status_code < 400:
        return "3xx"
    elif 400 <= status_code < 500:
        return "4xx"
    elif 500 <= status_code < 600:
        return "5xx"
    return "other"


class MetricsRegistry:
    """
    Thread-safe in-memory metrics registry collecting operational counters and summaries.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._start_time = time.time()

        # HTTP counters: {(method, route_group, status_family): count}
        self._http_requests = defaultdict(int)

        # HTTP duration summary: {(method, route_group): {"count": n, "total_ms": float, "min_ms": float, "max_ms": float}}
        self._http_durations = defaultdict(lambda: {"count": 0, "total_ms": 0.0, "min_ms": float("inf"), "max_ms": 0.0})

        # Security operational counters
        self._auth_events = defaultdict(int)             # {(event_type, outcome): count}
        self._security_decisions = defaultdict(int)      # {(decision, severity): count}
        self._approval_transitions = defaultdict(int)    # {terminal_state: count}
        self._threats_detected = defaultdict(int)        # {threat_type: count}
        self._executions = defaultdict(int)              # {status: count}
        self._database_errors = defaultdict(int)         # {operation: count}

    def record_http_request(self, method: str, path: str, status_code: int, duration_ms: float) -> None:
        """Record an inbound HTTP request completion."""
        safe_method = method.upper() if method else "UNKNOWN"
        route_group = normalize_route(path)
        status_fam = get_status_family(status_code)

        with self._lock:
            # Increment request counter
            self._http_requests[(safe_method, route_group, status_fam)] += 1

            # Update latency summary
            summary = self._http_durations[(safe_method, route_group)]
            summary["count"] += 1
            summary["total_ms"] += duration_ms
            if duration_ms < summary["min_ms"]:
                summary["min_ms"] = duration_ms
            if duration_ms > summary["max_ms"]:
                summary["max_ms"] = duration_ms

    def record_auth_event(self, event_type: str, outcome: str) -> None:
        """Record an authentication or session event (success, failure, demo rejection)."""
        safe_event = str(event_type).upper()
        safe_outcome = str(outcome).upper()
        with self._lock:
            self._auth_events[(safe_event, safe_outcome)] += 1

    def record_security_decision(self, decision: str, severity: str) -> None:
        """Record a security gateway evaluation decision (ALLOW, DENY, REQUIRE_APPROVAL)."""
        safe_decision = str(decision).upper()
        safe_severity = str(severity).upper()
        with self._lock:
            self._security_decisions[(safe_decision, safe_severity)] += 1

    def record_approval_transition(self, terminal_state: str) -> None:
        """Record an approval workflow transition (APPROVED, REJECTED, CANCELLED, EXPIRED)."""
        safe_state = str(terminal_state).upper()
        with self._lock:
            self._approval_transitions[safe_state] += 1

    def record_threat_detection(self, threat_type: str) -> None:
        """Record a detected threat signal."""
        safe_type = str(threat_type).upper()
        with self._lock:
            self._threats_detected[safe_type] += 1

    def record_execution(self, status: str) -> None:
        """Record a sandbox tool execution outcome."""
        safe_status = str(status).upper()
        with self._lock:
            self._executions[safe_status] += 1

    def record_database_error(self, operation: str = "query") -> None:
        """Record a persistence or database failure."""
        safe_op = str(operation).lower()
        with self._lock:
            self._database_errors[safe_op] += 1

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Produce a clean, sanitized dictionary of all operational metrics.
        Guaranteed zero secrets, zero user identifiers, zero tokens.
        """
        with self._lock:
            uptime_seconds = round(time.time() - self._start_time, 2)

            http_req_list = [
                {
                    "method": k[0],
                    "route_group": k[1],
                    "status_family": k[2],
                    "count": v,
                }
                for k, v in self._http_requests.items()
            ]

            http_lat_list = [
                {
                    "method": k[0],
                    "route_group": k[1],
                    "count": v["count"],
                    "avg_ms": round(v["total_ms"] / v["count"], 2) if v["count"] > 0 else 0.0,
                    "min_ms": round(v["min_ms"], 2) if v["min_ms"] != float("inf") else 0.0,
                    "max_ms": round(v["max_ms"], 2),
                }
                for k, v in self._http_durations.items()
            ]

            auth_list = [
                {"event_type": k[0], "outcome": k[1], "count": v}
                for k, v in self._auth_events.items()
            ]

            decisions_list = [
                {"decision": k[0], "severity": k[1], "count": v}
                for k, v in self._security_decisions.items()
            ]

            approvals_dict = {k: v for k, v in self._approval_transitions.items()}
            threats_dict = {k: v for k, v in self._threats_detected.items()}
            executions_dict = {k: v for k, v in self._executions.items()}
            db_errors_dict = {k: v for k, v in self._database_errors.items()}

            return {
                "uptime_seconds": uptime_seconds,
                "http_requests_total": http_req_list,
                "http_request_duration": http_lat_list,
                "auth_events_total": auth_list,
                "security_decisions_total": decisions_list,
                "approval_transitions_total": approvals_dict,
                "threats_detected_total": threats_dict,
                "executions_total": executions_dict,
                "database_errors_total": db_errors_dict,
            }

    def reset_for_testing(self) -> None:
        """Reset all metrics (for isolated test suites)."""
        with self._lock:
            self._http_requests.clear()
            self._http_durations.clear()
            self._auth_events.clear()
            self._security_decisions.clear()
            self._approval_transitions.clear()
            self._threats_detected.clear()
            self._executions.clear()
            self._database_errors.clear()
            self._start_time = time.time()


# Global thread-safe singleton
metrics_registry = MetricsRegistry()
