"""
RealHttpTool: Safe outbound HTTP client with strict SSRF and DNS rebinding defense.
Blocks all private, loopback, link-local, multicast, and cloud metadata targets.
Connects directly to pre-validated IP addresses to prevent DNS rebinding TOCTOU attacks.
"""

import ipaddress
import socket
import ssl
import http.client
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple
from app.security.models import ToolCategory
from app.security.execution.tools.base import BaseTool

MAX_RESPONSE_SIZE_BYTES = 512 * 1024  # 512 KB
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 5
BLOCKED_IPS = frozenset({"169.254.169.254"})  # AWS/GCP/Azure instance metadata
BLOCKED_HOSTNAMES = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "metadata.google.internal", "instance-data", "metadata.azure.com", "metadata"
})


def _validate_ip_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    ip_str = str(ip)
    if ip_str in BLOCKED_IPS:
        raise PermissionError(f"SSRF Protection: Access to metadata IP '{ip_str}' is blocked.")
    if ip.is_private:
        raise PermissionError(f"SSRF Protection: Access to private RFC1918 IP range '{ip_str}' is blocked.")
    if ip.is_loopback:
        raise PermissionError(f"SSRF Protection: Access to loopback IP '{ip_str}' is blocked.")
    if ip.is_link_local:
        raise PermissionError(f"SSRF Protection: Access to link-local IP '{ip_str}' is blocked.")
    if ip.is_multicast or ip.is_reserved:
        raise PermissionError(f"SSRF Protection: Access to reserved/multicast IP '{ip_str}' is blocked.")


def _resolve_and_validate_destination(hostname: str, port: int) -> str:
    """
    Resolve hostname to IP address, validating all resolved addresses against SSRF policies.
    Returns the first validated IP address to connect to directly (preventing DNS rebinding TOCTOU).
    """
    clean_host = hostname.lower().strip()
    if clean_host in BLOCKED_HOSTNAMES:
        raise PermissionError(f"SSRF Protection: Access to destination '{hostname}' is blocked.")

    # Check for integer/hex numeric IP encodings (e.g. 0x7f000001 or 2130706433)
    try:
        int_val = int(clean_host, 0) if (clean_host.isdigit() or clean_host.startswith("0x")) else None
        if int_val is not None:
            ip_obj = ipaddress.ip_address(int_val)
            _validate_ip_address(ip_obj)
            return str(ip_obj)
    except (ValueError, OverflowError):
        pass

    # Check if direct IP string
    try:
        ip_direct = ipaddress.ip_address(clean_host)
        _validate_ip_address(ip_direct)
        return str(ip_direct)
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(clean_host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host '{hostname}': {str(exc)}") from exc

    if not addr_info:
        raise ValueError(f"No IP addresses resolved for host '{hostname}'.")

    validated_ips: List[str] = []
    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
            _validate_ip_address(ip)
            validated_ips.append(ip_str)
        except ValueError:
            continue

    if not validated_ips:
        raise PermissionError(f"SSRF Protection: All resolved IP addresses for '{hostname}' were blocked.")

    return validated_ips[0]


def _validate_safe_url(url_str: str) -> urllib.parse.ParseResult:
    """
    Validate that URL uses safe scheme and does not resolve to a private/forbidden IP address.
    """
    parsed = urllib.parse.urlparse(url_str)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Unauthorized URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    _resolve_and_validate_destination(hostname, port)
    return parsed


class RealHttpTool(BaseTool):
    """
    SSRF-protected HTTP client for outbound API interactions with DNS-rebinding immunity.
    """

    @property
    def name(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "SSRF-protected outbound HTTP client (GET, POST, HEAD)"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.NETWORK_ACCESS

    def execute(self, parameters: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raw_url = str(parameters.get("url", "")).strip()
        if not raw_url:
            raise ValueError("Parameter 'url' is required for HTTP operations.")

        method = str(parameters.get("method", "GET")).upper().strip()
        if method not in ("GET", "POST", "HEAD"):
            raise ValueError(f"Unauthorized HTTP method: '{method}'. Only GET, POST, HEAD are permitted.")

        headers = dict(parameters.get("headers") or {})
        data = parameters.get("data")
        encoded_data = None
        if data is not None:
            if isinstance(data, str):
                encoded_data = data.encode("utf-8")
            elif isinstance(data, (dict, list)):
                import json
                encoded_data = json.dumps(data).encode("utf-8")
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"

        current_url = raw_url
        redirect_count = 0

        while redirect_count <= MAX_REDIRECTS:
            parsed = urllib.parse.urlparse(current_url)
            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError(f"Unauthorized URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed.")

            hostname = parsed.hostname
            if not hostname:
                raise ValueError("URL must contain a valid hostname.")

            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            target_ip = _resolve_and_validate_destination(hostname, port)

            request_path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

            conn_headers = dict(headers)
            conn_headers["Host"] = hostname if not parsed.port else f"{hostname}:{parsed.port}"
            conn_headers["User-Agent"] = "AgentShield-SecureGateway/1.0"
            if encoded_data is not None and "Content-Length" not in conn_headers:
                conn_headers["Content-Length"] = str(len(encoded_data))

            conn: Optional[http.client.HTTPConnection] = None
            try:
                if parsed.scheme.lower() == "https":
                    ssl_ctx = ssl.create_default_context()
                    # Connect directly to pinned target_ip, while preserving SNI verification for hostname
                    conn = http.client.HTTPSConnection(
                        host=target_ip,
                        port=port,
                        timeout=DEFAULT_TIMEOUT_SECONDS,
                        context=ssl_ctx,
                    )
                    conn._server_hostname = hostname
                else:
                    conn = http.client.HTTPConnection(
                        host=target_ip,
                        port=port,
                        timeout=DEFAULT_TIMEOUT_SECONDS,
                    )

                conn.request(method=method, url=request_path, body=encoded_data, headers=conn_headers)
                response = conn.getresponse()

                # Handle redirects defensively: validate each hop against SSRF rules
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if location:
                        current_url = urllib.parse.urljoin(current_url, location)
                        redirect_count += 1
                        conn.close()
                        continue

                status_code = response.status
                body = response.read(MAX_RESPONSE_SIZE_BYTES + 1)
                truncated = len(body) > MAX_RESPONSE_SIZE_BYTES
                if truncated:
                    body = body[:MAX_RESPONSE_SIZE_BYTES]

                response_headers = {k: v for k, v in response.getheaders()}
                content_type = response_headers.get("Content-Type", "")
                text_output = body.decode("utf-8", errors="replace")

                return {
                    "url": current_url,
                    "status_code": status_code,
                    "headers": response_headers,
                    "content_type": content_type,
                    "body": text_output,
                    "size_bytes": len(body),
                    "truncated": truncated,
                }
            except (socket.timeout, TimeoutError) as exc:
                raise TimeoutError(f"HTTP request timed out after {DEFAULT_TIMEOUT_SECONDS}s.") from exc
            except (PermissionError, ValueError):
                raise
            except Exception as exc:
                raise RuntimeError(f"HTTP request failed: {str(exc)}") from exc
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

        raise RuntimeError(f"Exceeded maximum redirect limit of {MAX_REDIRECTS} hops.")
