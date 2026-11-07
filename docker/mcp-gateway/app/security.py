import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from playwright.async_api import Request as PwRequest, Route
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
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

OAUTH_PUBLIC_PATHS = {
    "/healthz",
    "/healthz/",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-protected-resource/sse",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_signed_token(payload: Dict[str, Any], ttl_seconds: int) -> str:
    """Create a stateless HMAC-SHA256 signed token (used for OAuth code, access_token, and refresh_token)."""
    body = dict(payload)
    now = int(time.time())
    body["iat"] = now
    body["exp"] = now + ttl_seconds
    body["jti"] = secrets.token_hex(8)
    raw_payload = _b64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    key = settings.effective_signing_secret.encode("utf-8")
    sig = hmac.new(key, raw_payload.encode("ascii"), hashlib.sha256).digest()
    return f"cfx_oauth.{raw_payload}.{_b64url_encode(sig)}"


def verify_signed_token(token: str, expected_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Verify a stateless HMAC-SHA256 signed token and return its payload if valid and unexpired."""
    if not token or not token.startswith("cfx_oauth."):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    _, raw_payload, raw_sig = parts
    key = settings.effective_signing_secret.encode("utf-8")
    expected_sig = _b64url_encode(
        hmac.new(key, raw_payload.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(raw_sig, expected_sig):
        return None
    try:
        payload = json.loads(_b64url_decode(raw_payload).decode("utf-8"))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    if expected_type and payload.get("typ") != expected_type:
        return None
    return payload


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """Verify OAuth 2.1 PKCE code_verifier against code_challenge."""
    if not code_challenge:
        return True
    if not code_verifier:
        return False
    method_upper = (method or "S256").upper()
    if method_upper == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = _b64url_encode(digest)
        return hmac.compare_digest(computed, code_challenge)
    elif method_upper == "PLAIN":
        return hmac.compare_digest(code_verifier, code_challenge)
    return False


def get_external_base_url(request: Request) -> str:
    """Reconstruct external HTTPS base URL including BASE_PATH_PREFIX when behind a reverse proxy."""
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    # Force https for non-localhost domains (e.g., behind Cloudflare / NGINX Gateway)
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
        or "localhost:8000"
    )
    if not host.startswith("localhost") and not host.startswith("127.") and not host.startswith("10."):
        proto = "https"
    base_prefix = (settings.BASE_PATH_PREFIX or "").strip().rstrip("/")
    if base_prefix and not base_prefix.startswith("/"):
        base_prefix = "/" + base_prefix
    return f"{proto}://{host}{base_prefix}"


async def oauth_authorization_server_metadata(request: Request) -> JSONResponse:
    """RFC 8414 OAuth 2.0 Authorization Server Metadata & OpenID Configuration endpoint."""
    base_url = get_external_base_url(request)
    return JSONResponse(
        status_code=200,
        content={
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "none",
            ],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": ["mcp", "openid", "profile", "offline_access"],
        },
        headers={"Access-Control-Allow-Origin": "*"},
    )


async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 OAuth 2.0 Protected Resource Metadata endpoint for MCP discovery."""
    base_url = get_external_base_url(request)
    return JSONResponse(
        status_code=200,
        content={
            "resource": f"{base_url}/mcp",
            "authorization_servers": [base_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
        },
        headers={"Access-Control-Allow-Origin": "*"},
    )


async def oauth_register_endpoint(request: Request) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration endpoint."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    redirect_uris = body.get("redirect_uris", [])
    client_name = body.get("client_name", "MCP OAuth Client")
    return JSONResponse(
        status_code=201,
        content={
            "client_id": settings.OAUTH_CLIENT_ID,
            "client_secret": settings.effective_oauth_secret,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        },
        headers={"Access-Control-Allow-Origin": "*"},
    )


async def oauth_authorize_endpoint(request: Request) -> Response:
    """
    OAuth 2.0 Authorization Endpoint (`/oauth/authorize`).
    Supports both GET and POST. When `client_id` matches `OAUTH_CLIENT_ID` (or if auto-approve
    is triggered by Gemini Web / Claude Web), issues a signed authorization `code` and redirects
    back to `redirect_uri` with `code` and `state`.
    """
    params = dict(request.query_params)
    if request.method == "POST":
        try:
            form = await request.form()
            for k, v in form.items():
                params[k] = str(v)
        except Exception:
            pass

    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    scope = params.get("scope", "mcp")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "S256")

    if not redirect_uri:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Missing redirect_uri parameter."},
        )

    expected_client_id = settings.OAUTH_CLIENT_ID.strip()
    if expected_client_id and client_id and client_id != expected_client_id:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "Unknown client_id."},
        )

    code = create_signed_token(
        {
            "typ": "auth_code",
            "cid": client_id or expected_client_id,
            "ruri": redirect_uri,
            "scope": scope,
            "cc": code_challenge,
            "ccm": code_challenge_method,
        },
        ttl_seconds=600,
    )

    parsed_redirect = urlparse(redirect_uri)
    query_dict = dict(parse_qsl(parsed_redirect.query, keep_blank_values=True))
    query_dict["code"] = code
    if state:
        query_dict["state"] = state

    target_redirect = urlunparse(
        parsed_redirect._replace(query=urlencode(query_dict))
    )
    return RedirectResponse(url=target_redirect, status_code=302)


def _extract_basic_auth(request: Request) -> Tuple[str, str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
            if ":" in decoded:
                cid, csec = decoded.split(":", 1)
                return cid, csec
        except Exception:
            pass
    return "", ""


async def oauth_token_endpoint(request: Request) -> JSONResponse:
    """
    OAuth 2.0 Token Endpoint (`/oauth/token`).
    Supports:
    - `authorization_code` (with Client Secret and/or PKCE verification)
    - `client_credentials` (direct Client ID & Client Secret exchange)
    - `refresh_token`
    """
    params: Dict[str, str] = {}
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body_json = await request.json()
            if isinstance(body_json, dict):
                params = {str(k): str(v) for k, v in body_json.items() if v is not None}
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            params = {str(k): str(v) for k, v in form.items() if v is not None}
        except Exception:
            raw_body = (await request.body()).decode("utf-8", errors="ignore")
            params = dict(parse_qsl(raw_body))

    basic_cid, basic_csec = _extract_basic_auth(request)
    client_id = params.get("client_id") or basic_cid
    client_secret = params.get("client_secret") or basic_csec
    grant_type = params.get("grant_type", "authorization_code")

    expected_cid = settings.OAUTH_CLIENT_ID.strip()
    expected_csec = settings.effective_oauth_secret

    def _is_valid_secret(sec: str) -> bool:
        if not sec:
            return False
        if expected_csec and hmac.compare_digest(sec, expected_csec):
            return True
        return any(hmac.compare_digest(sec, k) for k in settings.api_keys_list)

    if grant_type == "client_credentials":
        if expected_cid and client_id and not hmac.compare_digest(client_id, expected_cid):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "Invalid client_id."},
                headers={"Access-Control-Allow-Origin": "*"},
            )
        if not _is_valid_secret(client_secret):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "Invalid client_secret."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        ttl = settings.OAUTH_TOKEN_TTL_SECONDS
        access_token = create_signed_token(
            {"typ": "access_token", "cid": client_id or expected_cid, "scope": params.get("scope", "mcp")},
            ttl_seconds=ttl,
        )
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ttl,
                "scope": params.get("scope", "mcp"),
            },
            headers={"Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"},
        )

    if grant_type == "authorization_code":
        code = params.get("code", "")
        code_payload = verify_signed_token(code, expected_type="auth_code")
        if not code_payload:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        if client_secret and not _is_valid_secret(client_secret):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "Invalid client_secret."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        code_challenge = code_payload.get("cc", "")
        code_challenge_method = code_payload.get("ccm", "S256")
        code_verifier = params.get("code_verifier", "")
        if code_challenge and not verify_pkce(code_verifier, code_challenge, code_challenge_method):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "PKCE verification failed."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        # Require either valid client_secret or valid PKCE challenge
        if not client_secret and not code_challenge and expected_csec:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "client_secret or PKCE is required."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        ttl = settings.OAUTH_TOKEN_TTL_SECONDS
        scope = code_payload.get("scope", "mcp")
        access_token = create_signed_token(
            {"typ": "access_token", "cid": code_payload.get("cid", expected_cid), "scope": scope},
            ttl_seconds=ttl,
        )
        refresh_token = create_signed_token(
            {"typ": "refresh_token", "cid": code_payload.get("cid", expected_cid), "scope": scope},
            ttl_seconds=ttl * 2,
        )
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ttl,
                "refresh_token": refresh_token,
                "scope": scope,
            },
            headers={"Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"},
        )

    if grant_type == "refresh_token":
        refresh_tok = params.get("refresh_token", "")
        rt_payload = verify_signed_token(refresh_tok, expected_type="refresh_token")
        if not rt_payload:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid or expired refresh_token."},
                headers={"Access-Control-Allow-Origin": "*"},
            )
        if client_secret and not _is_valid_secret(client_secret):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "Invalid client_secret."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        ttl = settings.OAUTH_TOKEN_TTL_SECONDS
        scope = rt_payload.get("scope", "mcp")
        access_token = create_signed_token(
            {"typ": "access_token", "cid": rt_payload.get("cid", expected_cid), "scope": scope},
            ttl_seconds=ttl,
        )
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ttl,
                "refresh_token": refresh_tok,
                "scope": scope,
            },
            headers={"Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"},
        )

    return JSONResponse(
        status_code=400,
        content={"error": "unsupported_grant_type", "error_description": f"Unsupported grant_type '{grant_type}'."},
        headers={"Access-Control-Allow-Origin": "*"},
    )


def _is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """Validate an IPv4 or IPv6 address against private, loopback, link-local, and reserved ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

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

    try:
        ipaddress.ip_address(hostname)
        blocked, reason = _is_ip_blocked(hostname)
        if blocked:
            return False, reason
        return True, "OK"
    except ValueError:
        pass

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
    Pure ASGI Triple-Authentication & Multi-Purpose Path Prefix Middleware.
    0. Supports an optional service prefix (`BASE_PATH_PREFIX`, default `/camoufox`) so a single
       domain (e.g., `mcp.kimohy.kr`) can host multiple MCP servers under distinct path prefixes.
    1. Allows unauthenticated access to `/healthz` and OAuth 2.0 discovery/authorization/token endpoints.
    2. Authenticates requests carrying `Authorization: Bearer <token>` matching:
       - An OAuth 2.0 signed `access_token` (`cfx_oauth....`) issued via `/oauth/token`
       - Any static key in `MCP_API_KEYS` or `OAUTH_CLIENT_SECRET`
    3. Authenticates requests whose path begins with `/s/{SECRET_URL_TOKEN}/...`.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        existing_root: str = scope.get("root_path", "").rstrip("/")

        # 0. Strip BASE_PATH_PREFIX (e.g., "/camoufox") if present in incoming request path
        base_prefix = (settings.BASE_PATH_PREFIX or "").strip().rstrip("/")
        if base_prefix and not base_prefix.startswith("/"):
            base_prefix = "/" + base_prefix

        if base_prefix and (path == base_prefix or path.startswith(base_prefix + "/")):
            path = path[len(base_prefix) :] or "/"
            existing_root = f"{existing_root}{base_prefix}"
            scope = dict(scope)
            scope["path"] = path
            scope["raw_path"] = path.encode("utf-8")
            scope["root_path"] = existing_root

        # 1. Bypass auth for Kubernetes probes and OAuth 2.0 discovery / token endpoints
        if path in OAUTH_PUBLIC_PATHS or path.startswith("/.well-known/"):
            await self.app(scope, receive, send)
            return

        # 2. Check URL Path Secret Token (/s/{SECRET_URL_TOKEN}/...)
        secret_token = settings.SECRET_URL_TOKEN.strip()
        if path.startswith("/s/"):
            parts = path.split("/", 3)
            candidate_token = parts[2] if len(parts) > 2 else ""
            if secret_token and candidate_token and hmac.compare_digest(candidate_token, secret_token):
                token_prefix = f"/s/{candidate_token}"
                remainder = "/" + parts[3] if len(parts) > 3 else "/"
                new_scope = dict(scope)
                new_scope["path"] = remainder
                new_scope["raw_path"] = remainder.encode("utf-8")
                new_scope["root_path"] = f"{existing_root}{token_prefix}"
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

        # 3. Check Authorization: Bearer <token> header (OAuth access_token OR static API key)
        headers = dict(scope.get("headers") or [])
        auth_header_bytes = headers.get(b"authorization", b"")
        auth_header = auth_header_bytes.decode("latin1").strip()

        valid_api_keys = settings.api_keys_list
        oauth_secret = settings.effective_oauth_secret
        if oauth_secret and oauth_secret not in valid_api_keys:
            valid_api_keys.append(oauth_secret)

        if auth_header.lower().startswith("bearer "):
            provided_token = auth_header[7:].strip()
            if provided_token:
                # 3a. Verify OAuth 2.0 signed access_token
                if verify_signed_token(provided_token, expected_type="access_token") is not None:
                    await self.app(scope, receive, send)
                    return
                # 3b. Verify static API key or OAuth Client Secret
                if any(hmac.compare_digest(provided_token, valid_key) for valid_key in valid_api_keys):
                    await self.app(scope, receive, send)
                    return

            response = JSONResponse(
                status_code=403,
                content={
                    "error": "invalid_token",
                    "message": "Invalid or expired Bearer token.",
                },
            )
            await response(scope, receive, send)
            return

        # Construct RFC 9728 WWW-Authenticate header so MCP OAuth clients auto-discover OAuth endpoints
        req = Request(scope)
        ext_base = get_external_base_url(req)
        www_auth = (
            f'Bearer realm="camoufox-mcp", '
            f'resource_metadata="{ext_base}/.well-known/oauth-protected-resource"'
        )
        hint_prefix = base_prefix if base_prefix else ""
        response = JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "message": (
                    f"Authentication required via OAuth 2.0, 'Authorization: Bearer <API_KEY>', "
                    f"or '{hint_prefix}/s/<SECRET_URL_TOKEN>/mcp'."
                ),
            },
            headers={"WWW-Authenticate": www_auth},
        )
        await response(scope, receive, send)
