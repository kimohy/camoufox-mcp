import asyncio
import base64
import contextvars
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import urllib.request

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

# ContextVariables holding the authenticated tenant namespace and client connection key per request
current_tenant_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_tenant_id", default="anonymous"
)
current_client_key: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_client_key", default=""
)
current_base_url: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_base_url", default=""
)


def _derive_tenant_id(prefix: str, raw_identity: str) -> str:
    """Create a deterministic, filesystem-safe tenant namespace identifier."""
    digest = hashlib.sha256(raw_identity.strip().lower().encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def get_current_tenant_id() -> str:
    """Return the authenticated tenant namespace ID for the current async execution context."""
    return current_tenant_id.get()


def get_current_client_key() -> str:
    """Return the client-level connection key (e.g., OAuth token jti) for default session isolation."""
    return current_client_key.get()


def get_current_base_url() -> str:
    """Return the external base URL (e.g., https://mcp.kimohy.kr/camoufox) for the current request."""
    return current_base_url.get() or settings.PUBLIC_BASE_URL.rstrip("/")

OAUTH_PUBLIC_PATHS = {
    "/healthz",
    "/healthz/",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-protected-resource/sse",
    "/oauth/authorize",
    "/oauth/callback",
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


def derive_dcr_client_secret(client_id: str) -> str:
    """Derive a stateless, deterministic HMAC-SHA256 client_secret for dynamically registered clients."""
    key = settings.effective_signing_secret.encode("utf-8")
    digest = hmac.new(key, f"dcr:{client_id}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"cfx-dcr-sec-{digest[:32]}"


def is_valid_dcr_client(client_id: str, client_secret: str = "") -> bool:
    """Validate whether client_id is a dynamically registered client (or static configured client)."""
    if not client_id:
        return False
    expected_cid = settings.OAUTH_CLIENT_ID.strip()
    if client_id == expected_cid:
        return True
    if client_id.startswith("cfx-dcr-"):
        if not client_secret:
            return True
        return hmac.compare_digest(client_secret, derive_dcr_client_secret(client_id))
    return False


async def oauth_register_endpoint(request: Request) -> Response:
    """
    RFC 7591 Dynamic Client Registration (DCR) endpoint (`/oauth/register`).
    Supports both public (`token_endpoint_auth_method="none"`) and confidential
    (`client_secret_post` / `client_secret_basic`) dynamic OAuth 2.0 / 2.1 clients
    such as Gemini Web, ChatGPT MCP Connectors, Claude Web/Desktop, and Cursor.
    """
    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        )

    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    redirect_uris = body.get("redirect_uris", [])
    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]

    client_name = body.get("client_name", "MCP Dynamic OAuth Client")
    requested_auth_method = body.get("token_endpoint_auth_method", "client_secret_post")
    grant_types = body.get("grant_types") or ["authorization_code", "refresh_token", "client_credentials"]
    response_types = body.get("response_types") or ["code"]
    scope = body.get("scope", "mcp openid profile offline_access")

    dcr_client_id = f"cfx-dcr-{secrets.token_hex(8)}"
    dcr_client_secret = derive_dcr_client_secret(dcr_client_id)
    issued_at = int(time.time())

    response_payload: Dict[str, Any] = {
        "client_id": dcr_client_id,
        "client_id_issued_at": issued_at,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": requested_auth_method,
        "scope": scope,
    }

    # Always provide client_secret unless the client explicitly registered as a public client ("none")
    if requested_auth_method != "none":
        response_payload["client_secret"] = dcr_client_secret
        response_payload["client_secret_expires_at"] = 0

    for optional_field in ("client_uri", "logo_uri", "tos_uri", "policy_uri", "software_id", "software_version"):
        if optional_field in body:
            response_payload[optional_field] = body[optional_field]

    logger.info(
        "DCR registered new OAuth client: client_id=%s client_name=%s auth_method=%s redirect_uris=%s",
        dcr_client_id,
        client_name,
        requested_auth_method,
        redirect_uris,
    )

    return JSONResponse(
        status_code=201,
        content=response_payload,
        headers={
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": "*",
        },
    )


def _resolve_google_callback_url(request: Request) -> str:
    """Resolve the Google OAuth 2.0 redirect_uri pointing to this MCP Gateway's `/oauth/callback`."""
    if settings.GOOGLE_CALLBACK_URL and settings.GOOGLE_CALLBACK_URL.strip():
        return settings.GOOGLE_CALLBACK_URL.strip()
    base_url = get_external_base_url(request)
    return f"{base_url}/oauth/callback"


async def oauth_authorize_endpoint(request: Request) -> Response:
    """
    OAuth 2.0 Authorization Endpoint (`/oauth/authorize`).
    When Google SSO (`GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET`) is configured:
      - Encodes the downstream MCP client's OAuth parameters (`client_id`, `redirect_uri`,
        `state`, `code_challenge`, `code_challenge_method`, `scope`) into a signed state token
        and redirects the user's browser to Google's OIDC login (`accounts.google.com`).
    Otherwise (fallback):
      - Immediately issues a signed authorization `code` and redirects back to `redirect_uri`.
    """
    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        )

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
    if client_id and not is_valid_dcr_client(client_id):
        logger.info("Allowing external/DCR client_id in /oauth/authorize: %s", client_id)

    # Federated Google SSO flow when GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET are configured
    if settings.google_sso_enabled:
        google_callback = _resolve_google_callback_url(request)
        federated_state = create_signed_token(
            {
                "typ": "google_sso_state",
                "cid": client_id or expected_client_id,
                "ruri": redirect_uri,
                "st": state,
                "scope": scope,
                "cc": code_challenge,
                "ccm": code_challenge_method,
                "gcb": google_callback,
            },
            ttl_seconds=600,
        )
        google_auth_params = urlencode(
            {
                "client_id": settings.GOOGLE_CLIENT_ID.strip(),
                "redirect_uri": google_callback,
                "response_type": "code",
                "scope": "openid email profile",
                "state": federated_state,
                "prompt": "select_account",
            }
        )
        google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{google_auth_params}"
        logger.info(
            "Redirecting OAuth authorize request (client_id=%s) to Google SSO (callback=%s)",
            client_id or expected_client_id,
            google_callback,
        )
        return RedirectResponse(url=google_auth_url, status_code=302)

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


def _exchange_google_code_for_userinfo_sync(code: str, redirect_uri: str) -> Dict[str, Any]:
    """Synchronously exchange Google authorization code for access_token/id_token and fetch verified userinfo."""
    token_data = urlencode(
        {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID.strip(),
            "client_secret": settings.GOOGLE_CLIENT_SECRET.strip(),
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
    ).encode("utf-8")

    token_req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(token_req, timeout=15) as resp:
        token_json = json.loads(resp.read().decode("utf-8"))

    google_access_token = token_json.get("access_token", "")
    if not google_access_token:
        raise ValueError("Google token endpoint did not return an access_token")

    userinfo_req = urllib.request.Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {google_access_token}"},
    )
    with urllib.request.urlopen(userinfo_req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def oauth_google_callback_endpoint(request: Request) -> Response:
    """
    Google OIDC Callback Endpoint (`/oauth/callback`).
    Verifies the signed `federated_state`, exchanges Google's `code` for the user's verified email,
    checks `ALLOWED_GOOGLE_EMAILS`, and redirects back to the MCP client (`redirect_uri`) with a
    signed MCP authorization `code`.
    """
    params = dict(request.query_params)
    error = params.get("error")
    if error:
        return HTMLResponse(
            status_code=403,
            content=(
                f"<html><body style='font-family:sans-serif;padding:2rem;'>"
                f"<h2>Google SSO Authentication Failed</h2><p>Error: {error}</p></body></html>"
            ),
        )

    google_code = params.get("code", "")
    federated_state = params.get("state", "")
    state_payload = verify_signed_token(federated_state, expected_type="google_sso_state")
    if not google_code or not state_payload:
        return HTMLResponse(
            status_code=400,
            content=(
                "<html><body style='font-family:sans-serif;padding:2rem;'>"
                "<h2>Invalid or Expired OAuth State</h2>"
                "<p>Please close this window and start the MCP connection again.</p></body></html>"
            ),
        )

    google_callback = state_payload.get("gcb") or _resolve_google_callback_url(request)
    try:
        userinfo = await asyncio.to_thread(
            _exchange_google_code_for_userinfo_sync,
            google_code,
            google_callback,
        )
    except Exception as exc:
        logger.error("Failed to exchange Google OAuth code: %s", exc)
        return HTMLResponse(
            status_code=502,
            content=(
                "<html><body style='font-family:sans-serif;padding:2rem;'>"
                "<h2>Google OAuth Token Exchange Failed</h2>"
                f"<p>Could not verify Google credentials ({exc}). Check redirect_uri configuration.</p></body></html>"
            ),
        )

    email = (userinfo.get("email") or "").strip().lower()
    email_verified = bool(userinfo.get("email_verified", False))
    allowed_emails = settings.allowed_google_emails_list

    if not email or not email_verified or (allowed_emails and email not in allowed_emails):
        logger.warning(
            "Blocked unauthorized Google SSO login attempt: email=%s verified=%s allowed=%s",
            email,
            email_verified,
            allowed_emails,
        )
        return HTMLResponse(
            status_code=403,
            content=(
                "<html><body style='font-family:sans-serif;padding:2rem;color:#b91c1c;'>"
                "<h2>403 Access Denied — 허용되지 않은 계정입니다</h2>"
                f"<p>로그인한 Google 계정(<b>{email or 'unknown'}</b>)은 이 Camoufox MCP 서버에 접근할 권한이 없습니다.</p>"
                "</body></html>"
            ),
        )

    logger.info("Google SSO authorized user '%s' for MCP client '%s'", email, state_payload.get("cid"))

    mcp_code = create_signed_token(
        {
            "typ": "auth_code",
            "cid": state_payload.get("cid", settings.OAUTH_CLIENT_ID),
            "ruri": state_payload.get("ruri", ""),
            "scope": state_payload.get("scope", "mcp"),
            "cc": state_payload.get("cc", ""),
            "ccm": state_payload.get("ccm", "S256"),
            "sub": email,
        },
        ttl_seconds=600,
    )

    redirect_uri = state_payload["ruri"]
    original_state = state_payload.get("st", "")
    parsed_redirect = urlparse(redirect_uri)
    query_dict = dict(parse_qsl(parsed_redirect.query, keep_blank_values=True))
    query_dict["code"] = mcp_code
    if original_state:
        query_dict["state"] = original_state

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


async def oauth_token_endpoint(request: Request) -> Response:
    """
    OAuth 2.0 Token Endpoint (`/oauth/token`).
    Supports:
    - `authorization_code` (with Client Secret and/or PKCE verification)
    - `client_credentials` (direct Client ID & Client Secret exchange)
    - `refresh_token`
    """
    if request.method == "OPTIONS":
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        )

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

    def _is_valid_secret(sec: str, cid: str = "") -> bool:
        if not sec:
            return False
        if expected_csec and hmac.compare_digest(sec, expected_csec):
            return True
        if cid and cid.startswith("cfx-dcr-") and hmac.compare_digest(sec, derive_dcr_client_secret(cid)):
            return True
        return any(hmac.compare_digest(sec, k) for k in settings.api_keys_list)

    logger.info(
        "OAuth token request: grant_type=%s client_id=%s has_secret=%s has_verifier=%s",
        grant_type,
        client_id,
        bool(client_secret),
        bool(params.get("code_verifier")),
    )

    if grant_type == "client_credentials":
        if not _is_valid_secret(client_secret, client_id):
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

        effective_cid = client_id or code_payload.get("cid", expected_cid)
        if client_secret and not _is_valid_secret(client_secret, effective_cid):
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
        sub_identity = code_payload.get("sub", "")
        effective_cid_for_token = code_payload.get("cid", expected_cid)
        access_token = create_signed_token(
            {
                "typ": "access_token",
                "cid": effective_cid_for_token,
                "scope": scope,
                "sub": sub_identity,
            },
            ttl_seconds=ttl,
        )
        refresh_token = create_signed_token(
            {
                "typ": "refresh_token",
                "cid": effective_cid_for_token,
                "scope": scope,
                "sub": sub_identity,
            },
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
        effective_cid = client_id or rt_payload.get("cid", expected_cid)
        if client_secret and not _is_valid_secret(client_secret, effective_cid):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "Invalid client_secret."},
                headers={"Access-Control-Allow-Origin": "*"},
            )

        ttl = settings.OAUTH_TOKEN_TTL_SECONDS
        scope = rt_payload.get("scope", "mcp")
        access_token = create_signed_token(
            {
                "typ": "access_token",
                "cid": rt_payload.get("cid", expected_cid),
                "scope": scope,
                "sub": rt_payload.get("sub", ""),
            },
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


SCREENSHOT_ID_PATTERN = re.compile(r"^[0-9]{10}_[a-f0-9]{24}\.png$")


def save_temporary_screenshot(png_bytes: bytes, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Save screenshot PNG bytes to `SCREENSHOT_STORAGE_DIR` with a 1-day TTL (`SCREENSHOT_TTL_SECONDS`)
    and return a signed temporary URL metadata dictionary.
    """
    effective_tenant = (tenant_id or get_current_tenant_id() or "anonymous").strip()
    if not PROFILE_NAME_PATTERN.match(effective_tenant):
        effective_tenant = _derive_tenant_id("tenant", effective_tenant)

    now_ts = int(time.time())
    ttl = int(settings.SCREENSHOT_TTL_SECONDS)
    expires_at = now_ts + ttl
    rand_id = secrets.token_hex(12)
    filename = f"{expires_at:010d}_{rand_id}.png"

    tenant_dir = (settings.screenshot_dir_path / effective_tenant).resolve()
    tenant_dir.mkdir(parents=True, exist_ok=True)
    file_path = (tenant_dir / filename).resolve()
    if tenant_dir not in file_path.parents:
        raise ValueError("Invalid screenshot path resolution.")

    tmp_path = file_path.with_name(f".{filename}.tmp")
    with open(tmp_path, "wb") as f:
        f.write(png_bytes)
    os.replace(str(tmp_path), str(file_path))

    sig = hmac.new(
        settings.effective_signing_secret.encode("utf-8"),
        f"shot:{effective_tenant}:{filename}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]

    base_url = get_current_base_url().rstrip("/")
    url = f"{base_url}/screenshots/{effective_tenant}/{filename}?sig={sig}"
    expires_at_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "url": url,
        "expires_at": expires_at,
        "expires_at_iso": expires_at_iso,
        "ttl_seconds": ttl,
        "size_bytes": len(png_bytes),
        "filename": filename,
        "tenant_id": effective_tenant,
    }


def cleanup_expired_screenshots_sync() -> int:
    """Delete all screenshot files whose embedded expiration timestamp or mtime has passed."""
    base_dir = settings.screenshot_dir_path
    if not base_dir.exists():
        return 0

    now_ts = int(time.time())
    ttl = int(settings.SCREENSHOT_TTL_SECONDS)
    deleted_count = 0

    for root, _, files in os.walk(base_dir):
        for fname in files:
            fpath = Path(root) / fname
            expired = False
            if SCREENSHOT_ID_PATTERN.match(fname):
                try:
                    exp_ts = int(fname.split("_", 1)[0])
                    if now_ts >= exp_ts:
                        expired = True
                except Exception:
                    pass
            if not expired:
                try:
                    mtime = int(fpath.stat().st_mtime)
                    if (now_ts - mtime) >= ttl:
                        expired = True
                except Exception:
                    pass
            if expired:
                try:
                    fpath.unlink()
                    deleted_count += 1
                except Exception:
                    pass
    return deleted_count


async def screenshot_download_endpoint(request: Request) -> Response:
    """
    Serve a temporary screenshot PNG (`/screenshots/{tenant_id}/{filename}?sig=...`)
    if its HMAC signature is valid and its 1-day TTL has not expired.
    """
    tenant_id = request.path_params.get("tenant_id", "")
    filename = request.path_params.get("filename", "")
    sig = request.query_params.get("sig", "")

    if not PROFILE_NAME_PATTERN.match(tenant_id) or not SCREENSHOT_ID_PATTERN.match(filename) or not sig:
        return JSONResponse(
            status_code=404,
            content={"error": "Not Found", "message": "Invalid screenshot identifier or signature."},
        )

    expected_sig = hmac.new(
        settings.effective_signing_secret.encode("utf-8"),
        f"shot:{tenant_id}:{filename}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]

    if not hmac.compare_digest(sig, expected_sig):
        return JSONResponse(
            status_code=403,
            content={"error": "Forbidden", "message": "Invalid screenshot signature."},
        )

    exp_ts = int(filename.split("_", 1)[0])
    now_ts = int(time.time())
    if now_ts >= exp_ts:
        file_path = (settings.screenshot_dir_path / tenant_id / filename).resolve()
        if file_path.is_file():
            try:
                file_path.unlink()
            except Exception:
                pass
        return JSONResponse(
            status_code=410,
            content={"error": "Gone", "message": "Screenshot URL has expired (TTL 1 day) and been deleted."},
        )

    tenant_dir = (settings.screenshot_dir_path / tenant_id).resolve()
    file_path = (tenant_dir / filename).resolve()
    if tenant_dir not in file_path.parents or not file_path.is_file():
        return JSONResponse(
            status_code=404,
            content={"error": "Not Found", "message": "Screenshot file not found or already expired."},
        )

    remaining_ttl = max(0, exp_ts - now_ts)
    png_bytes = await asyncio.to_thread(file_path.read_bytes)
    return Response(
        content=png_bytes,
        media_type="image/png",
        headers={
            "Cache-Control": f"public, max-age={remaining_ttl}",
            "X-Expires-At": str(exp_ts),
            "Access-Control-Allow-Origin": "*",
        },
    )


def sanitize_profile_path(profile_name: str, tenant_id: Optional[str] = None) -> Path:
    """
    Validate profile_name, isolate storage per authenticated tenant (`/data/profiles/{tenant_id}/{profile_name}.json`),
    and prevent path traversal attacks outside the tenant's profile directory.
    """
    clean_name = (profile_name or "").strip()
    if clean_name.endswith(".json"):
        clean_name = clean_name[:-5]

    if not PROFILE_NAME_PATTERN.match(clean_name):
        raise ValueError(
            "Invalid profile_name. Only alphanumeric characters, hyphens (-), and underscores (_) "
            "up to 64 characters are permitted."
        )

    effective_tenant = (tenant_id or get_current_tenant_id() or "anonymous").strip()
    if not PROFILE_NAME_PATTERN.match(effective_tenant):
        effective_tenant = _derive_tenant_id("tenant", effective_tenant)

    tenant_dir = (settings.profile_dir_path / effective_tenant).resolve()
    if settings.profile_dir_path not in tenant_dir.parents and tenant_dir != settings.profile_dir_path:
        raise ValueError("Invalid tenant directory resolution.")
    tenant_dir.mkdir(parents=True, exist_ok=True)

    target_path = (tenant_dir / f"{clean_name}.json").resolve()
    if tenant_dir not in target_path.parents:
        raise ValueError("Path traversal detected in profile_name.")

    return target_path


class AuthMiddleware:
    """
    Pure ASGI Triple-Authentication, Multi-Tenant Isolation & Multi-Purpose Path Prefix Middleware.
    0. Supports an optional service prefix (`BASE_PATH_PREFIX`, default `/camoufox`) so a single
       domain (e.g., `mcp.kimohy.kr`) can host multiple MCP servers under distinct path prefixes.
    1. Allows unauthenticated access to `/healthz` and OAuth 2.0 discovery/authorization/token endpoints.
    2. Authenticates requests carrying `Authorization: Bearer <token>` matching:
       - An OAuth 2.0 signed `access_token` (`cfx_oauth....`) issued via `/oauth/token`
       - Any static key in `MCP_API_KEYS` or `OAUTH_CLIENT_SECRET`
    3. Authenticates requests whose path begins with `/s/{SECRET_URL_TOKEN}/...`.
    4. Binds a deterministic `tenant_id` and `client_key` to `contextvars` so every user's browser
       sessions (`{tenant_id}:{session_id}`) and saved profiles (`/data/profiles/{tenant_id}/`)
       are strictly isolated from other users.
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

        # 1. Bypass auth for Kubernetes probes, temporary signed screenshots, and OAuth 2.0 discovery / token endpoints
        if path in OAUTH_PUBLIC_PATHS or path.startswith("/.well-known/") or path.startswith("/screenshots/"):
            await self.app(scope, receive, send)
            return

        req_for_base = Request(scope)
        resolved_ext_base = get_external_base_url(req_for_base)

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
                tenant_val = _derive_tenant_id("urltok", candidate_token)
                t_tok = current_tenant_id.set(tenant_val)
                c_tok = current_client_key.set(tenant_val)
                b_tok = current_base_url.set(resolved_ext_base)
                try:
                    await self.app(new_scope, receive, send)
                finally:
                    current_tenant_id.reset(t_tok)
                    current_client_key.reset(c_tok)
                    current_base_url.reset(b_tok)
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
                oauth_payload = verify_signed_token(provided_token, expected_type="access_token")
                if oauth_payload is not None:
                    sub = (oauth_payload.get("sub") or "").strip()
                    cid = (oauth_payload.get("cid") or "oauth").strip()
                    jti = (oauth_payload.get("jti") or cid).strip()
                    tenant_val = (
                        _derive_tenant_id("sso", sub)
                        if sub
                        else _derive_tenant_id("cid", cid)
                    )
                    client_val = _derive_tenant_id("tok", f"{cid}:{jti}")
                    t_tok = current_tenant_id.set(tenant_val)
                    c_tok = current_client_key.set(client_val)
                    b_tok = current_base_url.set(resolved_ext_base)
                    try:
                        await self.app(scope, receive, send)
                    finally:
                        current_tenant_id.reset(t_tok)
                        current_client_key.reset(c_tok)
                        current_base_url.reset(b_tok)
                    return

                # 3b. Verify static API key or OAuth Client Secret
                if any(hmac.compare_digest(provided_token, valid_key) for valid_key in valid_api_keys):
                    tenant_val = _derive_tenant_id("apikey", provided_token)
                    t_tok = current_tenant_id.set(tenant_val)
                    c_tok = current_client_key.set(tenant_val)
                    b_tok = current_base_url.set(resolved_ext_base)
                    try:
                        await self.app(scope, receive, send)
                    finally:
                        current_tenant_id.reset(t_tok)
                        current_client_key.reset(c_tok)
                        current_base_url.reset(b_tok)
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
