import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

from app.config import settings
from app.security import ssrf_route_interceptor

logger = logging.getLogger("camoufox.session_pool")


@dataclass
class SessionEntry:
    """Represents an isolated Camoufox browser session tied to a single session_id."""

    session_id: str
    context: BrowserContext
    page: Page
    created_at: float = field(default_factory=time.monotonic)
    last_accessed: float = field(default_factory=time.monotonic)
    proxy_server: Optional[str] = None
    profile_name: Optional[str] = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def touch(self) -> None:
        self.last_accessed = time.monotonic()


class CamoufoxSessionPool:
    """
    Manages a persistent Playwright WebSocket connection to the Camoufox Browser Pool
    and multiplexes isolated BrowserContexts with LRU eviction and TTL garbage collection.
    """

    def __init__(self) -> None:
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._sessions: Dict[str, SessionEntry] = {}
        self._pool_lock = asyncio.Lock()
        self._browser_lock = asyncio.Lock()
        self._gc_task: Optional[asyncio.Task] = None
        self._closing: bool = False

    async def start(self) -> None:
        """Initialize background garbage collection task."""
        self._closing = False
        if self._gc_task is None or self._gc_task.done():
            self._gc_task = asyncio.create_task(self._gc_loop(), name="camoufox-session-gc")
            logger.info(
                "SessionPool started (MAX_SESSIONS=%d, SESSION_TTL_SECONDS=%d)",
                settings.MAX_SESSIONS,
                settings.SESSION_TTL_SECONDS,
            )

    async def stop(self) -> None:
        """Gracefully close all active BrowserContexts and disconnect from Camoufox."""
        self._closing = True
        if self._gc_task and not self._gc_task.done():
            self._gc_task.cancel()
            try:
                await self._gc_task
            except asyncio.CancelledError:
                pass

        async with self._pool_lock:
            session_ids = list(self._sessions.keys())
            for sid in session_ids:
                entry = self._sessions.pop(sid, None)
                if entry:
                    await self._safe_close_entry(entry)

        async with self._browser_lock:
            if self._browser:
                try:
                    await self._browser.close()
                except Exception:
                    pass
                self._browser = None
            if self._playwright:
                try:
                    await self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None

        logger.info("SessionPool stopped cleanly.")

    async def _ensure_browser(self) -> Browser:
        """Ensure an active Playwright Firefox WebSocket connection to Camoufox exists, reconnecting if dropped."""
        async with self._browser_lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser

            logger.info("Connecting to remote Camoufox server at %s ...", settings.BROWSER_WS_URL)
            if self._playwright is None:
                self._playwright = await async_playwright().start()

            try:
                self._browser = await self._playwright.firefox.connect(
                    settings.BROWSER_WS_URL,
                    timeout=30000,
                )
            except Exception as exc:
                logger.error("Failed to connect to Camoufox WebSocket (%s): %s", settings.BROWSER_WS_URL, exc)
                # Reset playwright instance on connection failure so next attempt starts fresh
                try:
                    await self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None
                self._browser = None
                raise RuntimeError(
                    f"Unable to connect to Camoufox Browser Pool at {settings.BROWSER_WS_URL}: {exc}"
                ) from exc

            def _on_disconnect(_: Browser) -> None:
                logger.warning("Remote Camoufox WebSocket disconnected.")

            self._browser.on("disconnected", _on_disconnect)
            logger.info("Successfully connected to remote Camoufox server.")
            return self._browser

    async def _safe_close_entry(self, entry: SessionEntry) -> None:
        """Safely close a SessionEntry's Page and BrowserContext without raising exceptions."""
        try:
            await entry.page.close()
        except Exception:
            pass
        try:
            await entry.context.close()
        except Exception as exc:
            logger.debug("Error closing BrowserContext for session '%s': %s", entry.session_id, exc)

    async def _create_session_entry_unlocked(
        self,
        session_id: str,
        proxy_server: Optional[str] = None,
        storage_state_path: Optional[Path] = None,
        profile_name: Optional[str] = None,
    ) -> SessionEntry:
        """
        Internal helper (called while holding self._pool_lock or after capacity check)
        to construct a new isolated BrowserContext and Page with SSRF route interception.
        """
        browser = await self._ensure_browser()

        context_kwargs: dict = {
            "viewport": {"width": 1920, "height": 1080},
            "ignore_https_errors": False,
        }

        effective_proxy = (proxy_server or settings.DEFAULT_PROXY_SERVER or "").strip()
        if effective_proxy:
            context_kwargs["proxy"] = {"server": effective_proxy}

        if storage_state_path is not None and storage_state_path.is_file():
            context_kwargs["storage_state"] = str(storage_state_path)

        context = await browser.new_context(**context_kwargs)
        context.set_default_navigation_timeout(settings.NAVIGATION_TIMEOUT_MS)
        context.set_default_timeout(30000)

        # Attach SSRF route interceptor to block internal/private network subresources and redirects
        await context.route("**/*", ssrf_route_interceptor)

        page = await context.new_page()
        entry = SessionEntry(
            session_id=session_id,
            context=context,
            page=page,
            proxy_server=effective_proxy or None,
            profile_name=profile_name,
        )
        return entry

    async def get_or_create_session(
        self,
        session_id: str,
        proxy_server: Optional[str] = None,
        storage_state_path: Optional[Path] = None,
        profile_name: Optional[str] = None,
        force_recreate: bool = False,
    ) -> SessionEntry:
        """
        Retrieve an existing session by `session_id` or create a new isolated BrowserContext.
        Performs automatic LRU eviction if `MAX_SESSIONS` is reached.
        """
        if self._gc_task is None or self._gc_task.done():
            await self.start()

        evicted_entry: Optional[SessionEntry] = None
        old_entry_to_close: Optional[SessionEntry] = None

        async with self._pool_lock:
            existing = self._sessions.get(session_id)

            # Verify existing session is still healthy and matches requested proxy/recreation policy
            if existing is not None and not force_recreate:
                page_closed = existing.page.is_closed()
                browser_connected = (
                    existing.context.browser is not None and existing.context.browser.is_connected()
                )
                proxy_changed = (
                    proxy_server is not None
                    and proxy_server.strip() != ""
                    and proxy_server.strip() != (existing.proxy_server or "")
                )
                if not page_closed and browser_connected and not proxy_changed:
                    existing.touch()
                    return existing
                else:
                    old_entry_to_close = self._sessions.pop(session_id, None)
            elif existing is not None and force_recreate:
                old_entry_to_close = self._sessions.pop(session_id, None)

            # Evict Least Recently Used (LRU) session if at capacity
            if len(self._sessions) >= settings.MAX_SESSIONS:
                lru_sid = min(
                    self._sessions.keys(),
                    key=lambda k: self._sessions[k].last_accessed,
                )
                evicted_entry = self._sessions.pop(lru_sid, None)
                logger.info(
                    "MAX_SESSIONS (%d) reached; evicting LRU session '%s'",
                    settings.MAX_SESSIONS,
                    lru_sid,
                )

            try:
                new_entry = await self._create_session_entry_unlocked(
                    session_id=session_id,
                    proxy_server=proxy_server,
                    storage_state_path=storage_state_path,
                    profile_name=profile_name,
                )
            except Exception:
                # Re-try once in case the cached browser websocket died mid-flight
                async with self._browser_lock:
                    self._browser = None
                new_entry = await self._create_session_entry_unlocked(
                    session_id=session_id,
                    proxy_server=proxy_server,
                    storage_state_path=storage_state_path,
                    profile_name=profile_name,
                )

            self._sessions[session_id] = new_entry
            logger.info(
                "Created session '%s' (active=%d/%d, proxy=%s, profile=%s)",
                session_id,
                len(self._sessions),
                settings.MAX_SESSIONS,
                new_entry.proxy_server or "direct",
                new_entry.profile_name or "none",
            )

        # Clean up replaced or evicted contexts outside the global lock
        if old_entry_to_close is not None:
            await self._safe_close_entry(old_entry_to_close)
        if evicted_entry is not None:
            await self._safe_close_entry(evicted_entry)

        return new_entry

    async def close_session(self, session_id: str) -> bool:
        """Explicitly close and remove a session by `session_id`."""
        async with self._pool_lock:
            entry = self._sessions.pop(session_id, None)

        if entry is None:
            return False

        async with entry.lock:
            await self._safe_close_entry(entry)

        logger.info("Closed session '%s'", session_id)
        return True

    async def _gc_loop(self) -> None:
        """Background task running every 60 seconds to close idle contexts exceeding SESSION_TTL_SECONDS."""
        while not self._closing:
            try:
                await asyncio.sleep(60)
                now = time.monotonic()
                ttl = float(settings.SESSION_TTL_SECONDS)
                expired_entries: list[SessionEntry] = []

                async with self._pool_lock:
                    expired_ids = [
                        sid
                        for sid, entry in self._sessions.items()
                        if (now - entry.last_accessed) > ttl and not entry.lock.locked()
                    ]
                    for sid in expired_ids:
                        entry = self._sessions.pop(sid, None)
                        if entry is not None:
                            expired_entries.append(entry)

                for entry in expired_entries:
                    logger.info(
                        "Garbage collecting idle session '%s' (idle=%.1fs > ttl=%ds)",
                        entry.session_id,
                        now - entry.last_accessed,
                        settings.SESSION_TTL_SECONDS,
                    )
                    await self._safe_close_entry(entry)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Unexpected error in session GC loop: %s", exc)

    @property
    def active_session_count(self) -> int:
        return len(self._sessions)

    @property
    def is_browser_connected(self) -> bool:
        return self._browser is not None and self._browser.is_connected()


session_pool = CamoufoxSessionPool()
