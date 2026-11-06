import asyncio
import hmac
import ipaddress
import logging
import re
import socket
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

from playwright.async_api import Request as PwRequest, Route
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import settings

logger = logging.getLogger("camoufox.security")

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOST_EXACT = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
}
BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".cluster.local",
    ".svc",
    ".internal",
    ".local",
    ".home.arpa",
)

PROFILE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def _is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """Validate an IPv4 or IPv6 address against private, loopback, link-local, and reserved ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return True, f"Loopback address blocked ({ip_obj})"
    if ip_obj.is_private:
        return True, f"Private network address blocked ({ip_obj})"
    if ip_obj.is_link_local:
        return True, f"Link-local / Cloud metadata address blocked ({ip_obj})"
    if ip_obj.is_multicast:
        return True, f"Multicast address blocked ({ip_obj})"
    if ip_obj.is_reserved:
        return True, f"Reserved IP address blocked ({ip_obj})"
    if ip_obj.is_unspecified:
        return True, f"Unspecified IP address blocked ({ip_obj})"

    # Carrier-Grade NAT (100.64.0.0/10) check (often used in k8s CNI like Tailscale/Cilium)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
        if ip_obj in cgnat_net:
            return True, f"Shared/CGNAT address space blocked ({ip_obj})"

    return False, "OK"


def is_safe_url_sync(url: str) -> Tuple[bool, str]:
    """Synchronously validate URL scheme, hostname suffix, and DNS-resolved IP addresses."""
    if not url or not isinstance(url, str):
        return False, "Empty or non-string URL"

    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Disallowed URL scheme '{scheme}'. Only http and https are allowed."

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        return False, "URL is missing a valid hostname."

    if hostname in BLOCKED_HOST_EXACT:
        return False, f"Hostname '{hostname}' is explicitly blocked."

    for suffix in BLOCKED_HOST_SUFFIXES:
        if hostname.endswith(suffix):
            return False, f"Internal domain suffix '{suffix}' is blocked."

    # Check if hostname is already a literal IP address
    try:
        ipaddress.ip_address(hostname)
        blocked, reason = _is_ip_blocked(hostname)
        if blocked:
            return False, reason
        return True, "OK"
    except ValueError:
        pass

    # Perform DNS resolution and inspect every resolved record
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_info_list = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for '{hostname}': {exc}"
    except Exception as exc:
        return False, f"Error resolving hostname '{hostname}': {exc}"

    if not addr_info_list:
        return False, f"No DNS records resolved for '{hostname}'"

    for family, _, _, _, sockaddr in addr_info_list:
        ip_str = sockaddr[0]
        # Strip IPv6 scope ID if present (e.g., fe80::1%eth0)
        if "%" in ip_str:
            ip_str = ip_str.split("%", 1)[0]
        blocked, reason = _is_ip_blocked(ip_str)
        if blocked:
            return False, f"Host '{hostname}' resolved to blocked IP: {reason}"

    return True, "OK"


async def is_safe_url(url: str) -> Tuple[bool, str]:
    """Asynchronous wrapper around is_safe_url_sync to avoid blocking the asyncio event loop."""
    return await asyncio.to_thread(is_safe_url_sync, url)


async def ssrf_route_interceptor(route: Route, request: PwRequest) -> None:
    """
    Playwright route interceptor attached via context.route('**/*', ssrf_route_interceptor).
    Blocks third-party redirects, iframes, XHR/fetch, and subresources targeting internal/private networks.
    """
    target_url = request.url
    safe, reason = await is_safe_url(target_url)
    if not safe:
        logger.warning(
            "SSRF interceptor blocked request to '%s' (resource_type=%s): %s",
            target_url,
            request.resource_type,
            reason,
        )
        try:
            await route.abort("accessdenied")
        except Exception:
            pass
        return

    try:
        await route.continue_()
    except Exception:
        # Request may have been canceled or page closed concurrently
        pass


def sanitize_profile_path(profile_name: str) -> Path:
    """Validate profile_name and prevent path traversal attacks outside PROFILE_STORAGE_DIR."""
    clean_name = (profile_name or "").strip()
    if clean_name.endswith(".json"):
        clean_name = clean_name[:-5]

    if not PROFILE_NAME_PATTERN.match(clean_name):
        raise ValueError(
            "Invalid profile_name. Only alphanumeric characters, hyphens (-), and underscores (_) "
            "up to 64 characters are permitted."
        )

    base_dir = settings.profile_dir_path
    target_path = (base_dir / f"{clean_name}.json").resolve()

    if base_dir not in target_path.parents:
        raise ValueError("Path traversal detected in profile_name.")

    return target_path


class AuthMiddleware:
    """
    Pure ASGI Dual-Authentication Middleware.
    1. Allows unauthenticated access to `/healthz`.
    2. Authenticates requests carrying `Authorization: Bearer <token>` matching `MCP_API_KEYS`.
    3. Authenticates requests whose path begins with `/s/{SECRET_URL_TOKEN}/...`, automatically
       stripping `/s/{SECRET_URL_TOKEN}` from `scope["path"]` and `scope["raw_path"]` and setting
       `scope["root_path"]` so downstream MCP Streamable HTTP / SSE routers work seamlessly.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # 1. Bypass auth for Kubernetes liveness/readiness probes
        if path == "/healthz" or path == "/healthz/":
            await self.app(scope, receive, send)
            return

        # 2. Check URL Path Secret Token (/s/{SECRET_URL_TOKEN}/...)
        secret_token = settings.SECRET_URL_TOKEN.strip()
        if path.startswith("/s/"):
            parts = path.split("/", 3)
            # parts: ["", "s", "<candidate_token>", "<remainder_optional>"]
            candidate_token = parts[2] if len(parts) > 2 else ""
            if secret_token and candidate_token and hmac.compare_digest(candidate_token, secret_token):
                prefix = f"/s/{candidate_token}"
                remainder = "/" + parts[3] if len(parts) > 3 else "/"
                new_scope = dict(scope)
                new_scope["path"] = remainder
                new_scope["raw_path"] = remainder.encode("utf-8")
                existing_root = scope.get("root_path", "")
                new_scope["root_path"] = f"{existing_root.rstrip('/')}{prefix}"
                await self.app(new_scope, receive, send)
                return
            else:
                response = JSONResponse(
                    status_code=403,
                    content={
                        "error": "Forbidden",
                        "message": "Invalid or unconfigured URL secret token.",
                    },
                )
                await response(scope, receive, send)
                return

        # 3. Check Authorization: Bearer <token> header
        headers = dict(scope.get("headers") or [])
        auth_header_bytes = headers.get(b"authorization", b"")
        auth_header = auth_header_bytes.decode("latin1").strip()

        valid_api_keys = settings.api_keys_list
        if auth_header.lower().startswith("bearer "):
            provided_token = auth_header[7:].strip()
            if provided_token and any(
                hmac.compare_digest(provided_token, valid_key) for valid_key in valid_api_keys
            ):
                await self.app(scope, receive, send)
                return

            response = JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "message": "Invalid Bearer API key.",
                },
            )
            await response(scope, receive, send)
            return

        # Neither URL token nor valid Bearer token was supplied
        response = JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "message": "Missing authentication. Provide 'Authorization: Bearer <API_KEY>' header or use '/s/<SECRET_URL_TOKEN>/mcp'.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, receive, send)
