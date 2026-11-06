import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from mcp.server.fastmcp import Context, FastMCP, Image
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from app.config import settings
from app.security import AuthMiddleware, is_safe_url, sanitize_profile_path
from app.session_pool import session_pool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("camoufox.main")

mcp = FastMCP(
    "Camoufox-Stealth-MaaS",
    stateless_http=False,
)


def resolve_session_id(ctx: Optional[Context], explicit_session_id: Optional[str] = None) -> str:
    """
    Resolve the isolated browser session ID.
    Priority:
    1. Explicitly passed `session_id` tool parameter.
    2. HTTP Request header `mcp-session-id` or `x-session-id` from the MCP request context.
    3. Client ID or fallback `"default-session"`.
    """
    if explicit_session_id and explicit_session_id.strip():
        return explicit_session_id.strip()

    if ctx is not None:
        try:
            req_ctx = getattr(ctx, "request_context", None)
            if req_ctx is not None:
                req = getattr(req_ctx, "request", None)
                if req is not None and hasattr(req, "headers"):
                    for header_name in ("mcp-session-id", "x-mcp-session-id", "x-session-id"):
                        hdr_val = req.headers.get(header_name)
                        if hdr_val and hdr_val.strip():
                            return hdr_val.strip()
                session_obj = getattr(req_ctx, "session", None)
                if session_obj is not None:
                    return f"mcp-sess-{id(session_obj)}"
        except Exception:
            pass

        try:
            if getattr(ctx, "client_id", None):
                return str(ctx.client_id)
        except Exception:
            pass

    return "default-session"


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
    """
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
    sid = resolve_session_id(ctx, session_id)

    entry = await session_pool.get_or_create_session(
        session_id=sid,
        proxy_server=proxy_server,
    )

    async with entry.lock:
        entry.touch()
        response = await entry.page.goto(url, wait_until=effective_wait)  # type: ignore[arg-type]
        # Wait 2 seconds for JavaScript / anti-bot challenges to settle
        await asyncio.sleep(2.0)

        final_url = entry.page.url
        safe_final, final_reason = await is_safe_url(final_url)
        if not safe_final:
            await entry.page.goto("about:blank")
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
        body_text: str = await entry.page.evaluate(
            """() => {
                if (!document || !document.body) return "";
                return document.body.innerText || "";
            }"""
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


@mcp.tool()
async def get_interactive_elements(
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Extract all currently visible interactive elements (`a, button, input, textarea, select, [role="button"]`)
    on the page with bounding boxes (`width > 0 && height > 0`), returning their index, tag, ID/classes,
    recommended CSS selector, and visible text or placeholder.
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async with entry.lock:
        entry.touch()
        elements = await entry.page.evaluate(
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


@mcp.tool()
async def click(
    selector: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Perform a humanized click (`delay=100` ms) on the element matching `selector`
    and return the resulting page URL and title.
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async with entry.lock:
        entry.touch()
        await entry.page.click(selector, delay=100)
        try:
            await entry.page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass

        current_url = entry.page.url
        safe, reason = await is_safe_url(current_url)
        if not safe and current_url != "about:blank":
            await entry.page.goto("about:blank")
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
    character-by-character using `press_sequentially(text, delay=65)` for human-like cadence.
    Optionally presses Enter afterward.
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async with entry.lock:
        entry.touch()
        locator = entry.page.locator(selector).first
        await locator.click(delay=80)
        await locator.fill("")
        await locator.press_sequentially(text, delay=65)

        if press_enter:
            await asyncio.sleep(0.15)
            await locator.press("Enter")
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


@mcp.tool()
async def evaluate_js(
    script: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Evaluate a custom JavaScript expression or function in the current page context
    and return the JSON-serialized result.
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async with entry.lock:
        entry.touch()
        result: Any = await entry.page.evaluate(script)
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


@mcp.tool()
async def take_screenshot(
    session_id: Optional[str] = None,
    full_page: bool = False,
    ctx: Optional[Context] = None,
) -> Image:
    """
    Capture a PNG screenshot of the current browser viewport (or full scrollable page)
    and return it as an `mcp.server.fastmcp.Image` object for multimodal LLMs (e.g., Gemini).
    """
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async with entry.lock:
        entry.touch()
        png_bytes = await entry.page.screenshot(type="png", full_page=full_page)
        return Image(data=png_bytes, format="png")


@mcp.tool()
async def save_profile(
    profile_name: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Persist the current BrowserContext's cookies and localStorage to
    `/data/profiles/{profile_name}.json` with strict path traversal protection.
    """
    target_path = sanitize_profile_path(profile_name)
    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(session_id=sid)

    async with entry.lock:
        entry.touch()
        await entry.context.storage_state(path=str(target_path))
        entry.profile_name = target_path.stem

    return json.dumps(
        {
            "status": "ok",
            "session_id": sid,
            "profile_name": target_path.stem,
            "saved_path": str(target_path),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def load_profile(
    profile_name: str,
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Re-initialize the session's BrowserContext using the saved cookies and localStorage
    from `/data/profiles/{profile_name}.json`.
    """
    target_path = sanitize_profile_path(profile_name)
    if not target_path.is_file():
        return json.dumps(
            {
                "status": "error",
                "error": f"Profile '{target_path.stem}' does not exist at {target_path}",
            },
            ensure_ascii=False,
            indent=2,
        )

    sid = resolve_session_id(ctx, session_id)
    entry = await session_pool.get_or_create_session(
        session_id=sid,
        storage_state_path=target_path,
        profile_name=target_path.stem,
        force_recreate=True,
    )

    return json.dumps(
        {
            "status": "ok",
            "session_id": sid,
            "profile_name": entry.profile_name,
            "loaded_from": str(target_path),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
async def close_session(
    session_id: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> str:
    """
    Immediately close the isolated BrowserContext for `session_id` and release memory.
    """
    sid = resolve_session_id(ctx, session_id)
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
