import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

from mcp.server.fastmcp import Context, FastMCP, Image
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from app.config import settings
from app.security import (
    AuthMiddleware,
    get_current_client_key,
    get_current_tenant_id,
    is_safe_url,
    oauth_authorization_server_metadata,
    oauth_authorize_endpoint,
    oauth_google_callback_endpoint,
    oauth_protected_resource_metadata,
    oauth_register_endpoint,
    oauth_token_endpoint,
    sanitize_profile_path,
    save_temporary_screenshot,
    screenshot_download_endpoint,
)
from app.session_pool import SessionEntry, session_pool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("camoufox.main")

mcp = FastMCP(
    "Camoufox-Stealth-MaaS",
    stateless_http=False,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)


def resolve_session_id(ctx: Optional[Context], explicit_session_id: Optional[str] = None) -> str:
    """
    Resolve the tenant-isolated browser session ID (`{tenant_id}:{raw_session_id}`).
    Guarantees that even if two different users or API keys specify the exact same `session_id`
    (or omit `session_id`), they are strictly sandboxed into separate namespaces and can never
    view or hijack another user's browser tab or cookies.

    Priority for `raw_session_id`:
    1. Explicitly passed `session_id` tool parameter.
    2. HTTP Request header `mcp-session-id` or `x-session-id` from the MCP request context.
    3. MCP server session object ID or OAuth token client key (`jti`).
    4. Fallback `"default-session"`.
    """
    tenant_id = get_current_tenant_id() or "anonymous"
    raw_sid = ""

    if explicit_session_id and explicit_session_id.strip():
        raw_sid = explicit_session_id.strip()

    if not raw_sid and ctx is not None:
        try:
            req_ctx = getattr(ctx, "request_context", None)
            if req_ctx is not None:
                req = getattr(req_ctx, "request", None)
                if req is not None and hasattr(req, "headers"):
                    for header_name in ("mcp-session-id", "x-mcp-session-id", "x-session-id"):
                        hdr_val = req.headers.get(header_name)
                        if hdr_val and hdr_val.strip():
                            raw_sid = hdr_val.strip()
                            break
                if not raw_sid:
                    session_obj = getattr(req_ctx, "session", None)
                    if session_obj is not None:
                        raw_sid = f"mcp-sess-{id(session_obj)}"
        except Exception:
            pass

        if not raw_sid:
            try:
                if getattr(ctx, "client_id", None):
                    raw_sid = str(ctx.client_id)
            except Exception:
                pass

    if not raw_sid:
        client_key = get_current_client_key()
        raw_sid = client_key if client_key else "default-session"

    # Prefix with authenticated tenant_id so cross-tenant session collision is impossible
    if raw_sid.startswith(f"{tenant_id}:"):
        return raw_sid
    return f"{tenant_id}:{raw_sid}"


@asynccontextmanager
async def acquire_session_lock(entry: SessionEntry, tool_name: str) -> AsyncIterator[None]:
    """
    Acquire a session's concurrency lock with a bounded wait timeout (`SESSION_LOCK_TIMEOUT_SECONDS`)
    so concurrent calls on the same session never hang indefinitely behind a slow or stuck operation.
    """
    lock_timeout = float(settings.SESSION_LOCK_TIMEOUT_SECONDS)
    try:
        await asyncio.wait_for(entry.lock.acquire(), timeout=lock_timeout)
    except asyncio.TimeoutError as exc:
        raise TimeoutError(
            f"Session '{entry.session_id}' is busy with another operation "
            f"(failed to acquire session lock within {lock_timeout:.0f}s for '{tool_name}')."
        ) from exc
    try:
        entry.touch()
        yield
    finally:
        if entry.lock.locked():
            entry.lock.release()


async def run_with_tool_timeout(
    tool_name: str,
    sid: str,
    coro_factory: Callable[[], Awaitable[Any]],
    timeout_seconds: Optional[float] = None,
    entry_for_recovery: Optional[SessionEntry] = None,
) -> Any:
    """
    Execute a tool coroutine under a hard wall-clock deadline (`asyncio.wait_for`).
    If the tool exceeds `timeout_seconds` (or raises a Playwright timeout), cancels execution,
    attempts `window.stop()` recovery if appropriate, and returns a structured JSON timeout payload.
    """
    effective_timeout = float(timeout_seconds or settings.TOOL_TIMEOUT_SECONDS)
    try:
        return await asyncio.wait_for(coro_factory(), timeout=effective_timeout)
    except (asyncio.TimeoutError, TimeoutError, PlaywrightTimeoutError) as exc:
        logger.warning(
            "Tool '%s' timed out on session '%s' (limit=%.1fs): %s",
            tool_name,
            sid,
            effective_timeout,
            exc,
        )
        if entry_for_recovery is not None:
            try:
                await asyncio.wait_for(
                    entry_for_recovery.page.evaluate("() => { try { window.stop(); } catch (_) {} }"),
                    timeout=2.0,
                )
            except Exception:
                pass
        return json.dumps(
            {
                "status": "timeout",
                "tool": tool_name,
                "session_id": sid,
                "timeout_seconds": effective_timeout,
                "error": (
                    f"Tool '{tool_name}' exceeded its execution timeout of {effective_timeout:.0f}s "
                    f"and was forcefully terminated ({exc.__class__.__name__}: {exc})."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )


@mcp.tool()
async def navigate(
    url: str,
    session_id: Optional[str] = None,
    proxy_server: Optional[str] = None,
    wait_until: str = "domcontentloaded",
    ctx: Optional[Context] = None,
) -> str:
    """
    Navigate the isolated Camoufox stealth browser session to a target URL after SSRF verification.
    Waits 2 seconds after loading to allow anti-bot challenges (Cloudflare Turnstile / WAF) to settle,
    and returns the page title, final URL, and visible text content (up to 15,000 chars).
    Enforces a hard execution timeout (`TOOL_TIMEOUT_SECONDS`).
    """
    sid = resolve_session_id(ctx, session_id)

    async def _impl() -> str:
        safe, reason = await is_safe_url(url)
        if not safe:
            return json.dumps(
                {
                    "status": "blocked",
                    "error": f"SSRF Security Policy Blocked Navigation: {reason}",
                    "requested_url": url,
                },
                ensure_ascii=False,
                indent=2,
            )

        valid_wait_states = {"commit", "domcontentloaded", "load", "networkidle"}
        effective_wait = wait_until if wait_until in valid_wait_states else "domcontentloaded"

        entry = await session_pool.get_or_create_session(
            session_id=sid,
            proxy_server=proxy_server,
        )

        async with acquire_session_lock(entry, "navigate"):
            response = await entry.page.goto(
                url,
                wait_until=effective_wait,  # type: ignore[arg-type]
                timeout=settings.NAVIGATION_TIMEOUT_MS,
            )
            # Wait 2 seconds for JavaScript / anti-bot challenges to settle
            await asyncio.sleep(2.0)

            final_url = entry.page.url
            safe_final, final_reason = await is_safe_url(final_url)
            if not safe_final:
                await entry.page.goto("about:blank", timeout=5000)
                return json.dumps(
                    {
                        "status": "blocked",
                        "error": f"Post-navigation redirect blocked by SSRF policy: {final_reason}",
                        "final_url": final_url,
                    },
                    ensure_ascii=False,
                    indent=2,
                )

            title = await entry.page.title()
            body_text: str = await asyncio.wait_for(
                entry.page.evaluate(
                    """() => {
                        if (!document || !document.body) return "";
                        return document.body.innerText || "";
                    }"""
                ),
                timeout=float(settings.JS_EVAL_TIMEOUT_SECONDS),
            )
            truncated_text = body_text.strip()[:15000]
            http_status = response.status if response else None

            return json.dumps(
                {
                    "status": "ok",
                    "session_id": sid,
                    "http_status": http_status,
                    "title": title,
                    "url": final_url,
                    "content_length": len(body_text),
                    "content": truncated_text,
                },
                ensure_ascii=False,
                indent=2,
            )

    return await run_with_tool_timeout("navigate", sid, _impl, timeout_seconds=settings.TOOL_TIMEOUT_SECONDS)


@mcp.tool()
async def get_interactive_elements(
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Extract all currently visible interactive elements (`a, button, input, textarea, select, [role="button"]`)
    on the page with bounding boxes (`width > 0 && height > 0`), returning their index, tag, ID/classes,
    recommended CSS selector, and visible text or placeholder.
    Enforces a hard execution timeout (`TOOL_TIMEOUT_SECONDS`).
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async def _impl() -> str:
        async with acquire_session_lock(entry, "get_interactive_elements"):
            elements = await asyncio.wait_for(
                entry.page.evaluate(
                    """() => {
                        const selector = 'a, button, input, textarea, select, [role="button"]';
                        const nodes = Array.from(document.querySelectorAll(selector));
                        const results = [];
                        let idx = 0;

                        for (const el of nodes) {
                            const rect = el.getBoundingClientRect();
                            const style = window.getComputedStyle(el);
                            if (
                                rect.width <= 0 ||
                                rect.height <= 0 ||
                                style.visibility === 'hidden' ||
                                style.display === 'none' ||
                                parseFloat(style.opacity || '1') === 0
                            ) {
                                continue;
                            }

                            const tag = el.tagName.toLowerCase();
                            const id = el.id || '';
                            const className = (typeof el.className === 'string') ? el.className.trim() : '';
                            const type = el.getAttribute('type') || '';
                            const name = el.getAttribute('name') || '';
                            const role = el.getAttribute('role') || '';
                            const placeholder = el.getAttribute('placeholder') || '';
                            const ariaLabel = el.getAttribute('aria-label') || '';
                            const href = (tag === 'a') ? (el.getAttribute('href') || '') : '';
                            const text = (el.innerText || el.value || '').replace(/\\s+/g, ' ').trim().slice(0, 120);

                            let recommendedSelector = tag;
                            if (id) {
                                recommendedSelector = `#${CSS.escape(id)}`;
                            } else if (name) {
                                recommendedSelector = `${tag}[name="${CSS.escape(name)}"]`;
                            } else if (ariaLabel) {
                                recommendedSelector = `${tag}[aria-label="${CSS.escape(ariaLabel)}"]`;
                            } else if (placeholder) {
                                recommendedSelector = `${tag}[placeholder="${CSS.escape(placeholder)}"]`;
                            }

                            results.push({
                                index: idx++,
                                tag,
                                id,
                                class: className.slice(0, 100),
                                type,
                                name,
                                role,
                                text,
                                placeholder,
                                aria_label: ariaLabel,
                                href: href.slice(0, 200),
                                selector_hint: recommendedSelector,
                                rect: {
                                    x: Math.round(rect.x),
                                    y: Math.round(rect.y),
                                    width: Math.round(rect.width),
                                    height: Math.round(rect.height),
                                }
                            });
                        }
                        return results;
                    }"""
                ),
                timeout=float(settings.JS_EVAL_TIMEOUT_SECONDS),
            )

            return json.dumps(
                {
                    "status": "ok",
                    "session_id": sid,
                    "url": entry.page.url,
                    "count": len(elements),
                    "elements": elements,
                },
                ensure_ascii=False,
                indent=2,
            )

    return await run_with_tool_timeout(
        "get_interactive_elements",
        sid,
        _impl,
        timeout_seconds=settings.TOOL_TIMEOUT_SECONDS,
        entry_for_recovery=entry,
    )


@mcp.tool()
async def click(
    selector: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Perform a humanized click (`delay=100` ms) on the element matching `selector`
    and return the resulting page URL and title.
    Enforces a hard execution timeout (`TOOL_TIMEOUT_SECONDS`).
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async def _impl() -> str:
        async with acquire_session_lock(entry, "click"):
            await entry.page.click(selector, delay=100, timeout=20000)
            try:
                await entry.page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass

            current_url = entry.page.url
            safe, reason = await is_safe_url(current_url)
            if not safe and current_url != "about:blank":
                await entry.page.goto("about:blank", timeout=5000)
                return json.dumps(
                    {
                        "status": "blocked",
                        "error": f"Click navigated to SSRF-blocked destination: {reason}",
                    },
                    ensure_ascii=False,
                    indent=2,
                )

            title = await entry.page.title()
            return json.dumps(
                {
                    "status": "ok",
                    "session_id": sid,
                    "clicked_selector": selector,
                    "current_url": current_url,
                    "title": title,
                },
                ensure_ascii=False,
                indent=2,
            )

    return await run_with_tool_timeout(
        "click",
        sid,
        _impl,
        timeout_seconds=settings.TOOL_TIMEOUT_SECONDS,
        entry_for_recovery=entry,
    )


@mcp.tool()
async def fill(
    selector: str,
    text: str,
    press_enter: bool = False,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Click on the target input element, clear any existing value, and type `text`
    character-by-character using `press_sequentially` for human-like cadence
    (automatically scaling typing delay for long text so it never times out).
    Optionally presses Enter afterward.
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async def _impl() -> str:
        async with acquire_session_lock(entry, "fill"):
            locator = entry.page.locator(selector).first
            await locator.click(delay=80, timeout=15000)
            await locator.fill("", timeout=10000)
            # Cap total sequential typing duration to ~12s by dynamically scaling per-key delay
            if len(text) <= 180:
                key_delay = 65
                await locator.press_sequentially(text, delay=key_delay, timeout=20000)
            elif len(text) <= 800:
                key_delay = max(10, int(10000 / len(text)))
                await locator.press_sequentially(text, delay=key_delay, timeout=20000)
            else:
                await locator.fill(text, timeout=15000)

            if press_enter:
                await asyncio.sleep(0.15)
                await locator.press("Enter", timeout=5000)
                try:
                    await entry.page.wait_for_load_state("domcontentloaded", timeout=6000)
                except Exception:
                    pass

            return json.dumps(
                {
                    "status": "ok",
                    "session_id": sid,
                    "selector": selector,
                    "typed_length": len(text),
                    "pressed_enter": press_enter,
                    "current_url": entry.page.url,
                },
                ensure_ascii=False,
                indent=2,
            )

    return await run_with_tool_timeout(
        "fill",
        sid,
        _impl,
        timeout_seconds=settings.TOOL_TIMEOUT_SECONDS,
        entry_for_recovery=entry,
    )


@mcp.tool()
async def evaluate_js(
    script: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Evaluate a custom JavaScript expression or function in the current page context
    and return the JSON-serialized result.
    Enforces a strict execution timeout (`JS_EVAL_TIMEOUT_SECONDS`, default 20s) to prevent hung Promises or infinite loops.
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)
    js_timeout = float(settings.JS_EVAL_TIMEOUT_SECONDS)

    async def _impl() -> str:
        async with acquire_session_lock(entry, "evaluate_js"):
            result: Any = await asyncio.wait_for(
                entry.page.evaluate(script),
                timeout=js_timeout,
            )
            return json.dumps(
                {
                    "status": "ok",
                    "session_id": sid,
                    "url": entry.page.url,
                    "result": result,
                },
                ensure_ascii=False,
                default=str,
                indent=2,
            )

    return await run_with_tool_timeout(
        "evaluate_js",
        sid,
        _impl,
        timeout_seconds=js_timeout + float(settings.SESSION_LOCK_TIMEOUT_SECONDS),
        entry_for_recovery=entry,
    )


@mcp.tool()
async def take_screenshot(
    session_id: Optional[str] = None,
    full_page: bool = False,
    include_inline_image: bool = False,
    ctx: Optional[Context] = None,
) -> Any:
    """
    Capture a PNG screenshot of the current browser viewport (or full scrollable page),
    save it to isolated tenant storage, and return a signed temporary URL with a 1-day TTL
    (86,400 seconds) that automatically expires and self-deletes.
    Set `include_inline_image=True` if you also want the raw multimodal Image payload in addition to the URL.
    """
    sid = resolve_session_id(ctx, session_id)
    tenant_id = get_current_tenant_id()
    entry = await session_pool.get_or_create_session(session_id=sid)

    async def _impl() -> Any:
        async with acquire_session_lock(entry, "take_screenshot"):
            png_bytes = await entry.page.screenshot(type="png", full_page=full_page, timeout=25000)
            current_url = entry.page.url
            title = await entry.page.title()

        shot_meta = await asyncio.to_thread(save_temporary_screenshot, png_bytes, tenant_id)
        payload = {
            "status": "ok",
            "session_id": sid,
            "page_url": current_url,
            "page_title": title,
            "screenshot_url": shot_meta["url"],
            "markdown_image": f"![{title or 'screenshot'}]({shot_meta['url']})",
            "expires_at": shot_meta["expires_at"],
            "expires_at_iso": shot_meta["expires_at_iso"],
            "ttl_seconds": shot_meta["ttl_seconds"],
            "size_bytes": shot_meta["size_bytes"],
        }
        json_text = json.dumps(payload, ensure_ascii=False, indent=2)
        if include_inline_image:
            return [json_text, Image(data=png_bytes, format="png")]
        return json_text

    return await run_with_tool_timeout(
        "take_screenshot",
        sid,
        _impl,
        timeout_seconds=settings.TOOL_TIMEOUT_SECONDS,
        entry_for_recovery=entry,
    )


@mcp.tool()
async def save_profile(
    profile_name: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Persist the current BrowserContext's cookies and localStorage atomically to the authenticated
    tenant's isolated directory (`/data/profiles/{tenant_id}/{profile_name}.json`) with path traversal
    and concurrent-write corruption protection.
    """
    tenant_id = get_current_tenant_id()
    target_path = sanitize_profile_path(profile_name, tenant_id=tenant_id)
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async def _impl() -> str:
        async with acquire_session_lock(entry, "save_profile"):
            await session_pool.save_storage_state_atomic(entry.context, target_path)
            entry.profile_name = target_path.stem

        return json.dumps(
            {
                "status": "ok",
                "tenant_id": tenant_id,
                "session_id": sid,
                "profile_name": target_path.stem,
                "saved_path": str(target_path),
            },
            ensure_ascii=False,
            indent=2,
        )

    return await run_with_tool_timeout("save_profile", sid, _impl, timeout_seconds=30.0)


@mcp.tool()
async def load_profile(
    profile_name: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Re-initialize the session's BrowserContext using the saved cookies and localStorage
    from the authenticated tenant's isolated storage (`/data/profiles/{tenant_id}/{profile_name}.json`).
    """
    tenant_id = get_current_tenant_id()
    target_path = sanitize_profile_path(profile_name, tenant_id=tenant_id)
    if not target_path.is_file():
        return json.dumps(
            {
                "status": "error",
                "tenant_id": tenant_id,
                "error": f"Profile '{target_path.stem}' does not exist in tenant namespace '{tenant_id}'.",
            },
            ensure_ascii=False,
            indent=2,
        )

    sid = resolve_session_id(ctx, session_id)

    async def _impl() -> str:
        prof_lock = await session_pool.get_profile_lock(target_path)
        async with prof_lock:
            entry = await session_pool.get_or_create_session(
                session_id=sid,
                storage_state_path=target_path,
                profile_name=target_path.stem,
                force_recreate=True,
            )

        return json.dumps(
            {
                "status": "ok",
                "tenant_id": tenant_id,
                "session_id": sid,
                "profile_name": entry.profile_name,
                "loaded_from": str(target_path),
            },
            ensure_ascii=False,
            indent=2,
        )

    return await run_with_tool_timeout("load_profile", sid, _impl, timeout_seconds=30.0)


@mcp.tool()
async def close_session(
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Immediately close the isolated BrowserContext for `session_id` and release memory.
    """
    sid = resolve_session_id(ctx, session_id)

    async def _impl() -> str:
        closed = await session_pool.close_session(sid)
        return json.dumps(
            {
                "status": "ok",
                "session_id": sid,
                "closed": closed,
                "active_sessions": session_pool.active_session_count,
            },
            ensure_ascii=False,
            indent=2,
        )

    return await run_with_tool_timeout("close_session", sid, _impl, timeout_seconds=20.0)


async def healthz_endpoint(request: Request) -> JSONResponse:
    """Kubernetes liveness and readiness probe endpoint (unauthenticated)."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "healthy",
            "service": "camoufox-mcp-gateway",
            "browser_connected": session_pool.is_browser_connected,
            "active_sessions": session_pool.active_session_count,
            "max_sessions": settings.MAX_SESSIONS,
        },
    )


def _create_combined_asgi_app() -> AuthMiddleware:
    """
    Build the production Starlette ASGI application mounting:
    - GET `/healthz`
    - Streamable HTTP MCP transport (`/mcp`) via `mcp.streamable_http_app()`
    - Legacy SSE MCP transport (`/sse` and `/messages/`) via `mcp.sse_app()`
    Wrapped in `AuthMiddleware` supporting both Bearer tokens and `/s/{SECRET_URL_TOKEN}/...` URLs.
    """
    streamable_app = mcp.streamable_http_app()
    sse_app = mcp.sse_app()

    @asynccontextmanager
    async def lifespan(app_instance: Starlette) -> AsyncIterator[None]:
        await session_pool.start()
        try:
            # Manage the FastMCP session_manager lifecycle when running inside our parent Starlette app
            session_mgr = getattr(mcp, "session_manager", None)
            if session_mgr is not None and hasattr(session_mgr, "run"):
                async with session_mgr.run():
                    yield
            else:
                yield
        finally:
            await session_pool.stop()

    routes = [
        Route("/healthz", endpoint=healthz_endpoint, methods=["GET", "HEAD"]),
        Route(
            "/.well-known/oauth-authorization-server",
            endpoint=oauth_authorization_server_metadata,
            methods=["GET", "HEAD"],
        ),
        Route(
            "/.well-known/oauth-authorization-server/{subpath:path}",
            endpoint=oauth_authorization_server_metadata,
            methods=["GET", "HEAD"],
        ),
        Route(
            "/.well-known/openid-configuration",
            endpoint=oauth_authorization_server_metadata,
            methods=["GET", "HEAD"],
        ),
        Route(
            "/.well-known/openid-configuration/{subpath:path}",
            endpoint=oauth_authorization_server_metadata,
            methods=["GET", "HEAD"],
        ),
        Route(
            "/.well-known/oauth-protected-resource",
            endpoint=oauth_protected_resource_metadata,
            methods=["GET", "HEAD"],
        ),
        Route(
            "/.well-known/oauth-protected-resource/{subpath:path}",
            endpoint=oauth_protected_resource_metadata,
            methods=["GET", "HEAD"],
        ),
        Route("/oauth/authorize", endpoint=oauth_authorize_endpoint, methods=["GET", "POST", "OPTIONS"]),
        Route("/oauth/callback", endpoint=oauth_google_callback_endpoint, methods=["GET", "POST"]),
        Route("/oauth/token", endpoint=oauth_token_endpoint, methods=["POST", "OPTIONS"]),
        Route("/oauth/register", endpoint=oauth_register_endpoint, methods=["POST", "OPTIONS"]),
        Route(
            "/screenshots/{tenant_id}/{filename}",
            endpoint=screenshot_download_endpoint,
            methods=["GET", "HEAD"],
        ),
    ]

    # Collect routes from both streamable_http_app (/mcp) and sse_app (/sse, /messages)
    for sub_app in (streamable_app, sse_app):
        sub_routes = getattr(sub_app, "routes", None)
        if sub_routes:
            for r in sub_routes:
                routes.append(r)

    # Fallback Mount if a future FastMCP version returns a non-Router ASGI callable
    if len(routes) == 1:
        routes.append(Mount("/mcp", app=streamable_app))
        routes.append(Mount("/", app=sse_app))

    base_app = Starlette(
        debug=False,
        routes=routes,
        lifespan=lifespan,
    )

    return AuthMiddleware(base_app)


app = _create_combined_asgi_app()
