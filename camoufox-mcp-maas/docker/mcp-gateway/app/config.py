import os
from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    BROWSER_WS_URL: str = Field(
        default="ws://camoufox-browser-svc:9222/stealth-agent",
        description="Remote Camoufox Playwright WebSocket endpoint.",
    )
    MCP_API_KEYS: str = Field(
        default="",
        description="Comma-separated list of static Bearer tokens allowed to access the MCP gateway.",
    )
    SECRET_URL_TOKEN: str = Field(
        default="",
        description="Path-based secret token (/camoufox/s/{SECRET_URL_TOKEN}/mcp) for clients that cannot set custom headers.",
    )
    OAUTH_CLIENT_ID: str = Field(
        default="camoufox-mcp-client",
        description="OAuth 2.0 Client ID for Gemini Web and MCP OAuth 2.1 clients.",
    )
    OAUTH_CLIENT_SECRET: str = Field(
        default="",
        description="OAuth 2.0 Client Secret for Gemini Web and MCP OAuth 2.1 clients.",
    )
    OAUTH_SIGNING_SECRET: str = Field(
        default="",
        description="HMAC signing key for stateless OAuth authorization codes and access tokens (defaults to OAUTH_CLIENT_SECRET or MCP_API_KEYS).",
    )
    OAUTH_TOKEN_TTL_SECONDS: int = Field(
        default=86400 * 30,
        description="OAuth access token lifetime in seconds (default 30 days).",
    )
    GOOGLE_CLIENT_ID: str = Field(
        default="",
        description="Google OAuth 2.0 / OIDC Client ID for federated SSO user authentication.",
    )
    GOOGLE_CLIENT_SECRET: str = Field(
        default="",
        description="Google OAuth 2.0 / OIDC Client Secret for federated SSO user authentication.",
    )
    GOOGLE_CALLBACK_URL: str = Field(
        default="",
        description="Optional explicit Google OAuth redirect_uri override (e.g., 'https://mcp.kimohy.kr/camoufox/oauth/callback').",
    )
    ALLOWED_GOOGLE_EMAILS: str = Field(
        default="kimohy@gmail.com",
        description="Comma-separated list of Google email addresses allowed to authorize MCP OAuth sessions.",
    )
    BASE_PATH_PREFIX: str = Field(
        default="/camoufox",
        description="Optional service path prefix (e.g., '/camoufox') when sharing an MCP domain across multiple services.",
    )
    SESSION_TTL_SECONDS: int = Field(
        default=600,
        ge=30,
        description="Idle session TTL in seconds before automatic garbage collection.",
    )
    MAX_SESSIONS: int = Field(
        default=20,
        ge=1,
        description="Maximum concurrent isolated BrowserContext sessions.",
    )
    PROFILE_STORAGE_DIR: str = Field(
        default="/data/profiles",
        description="Persistent directory path for storing and loading BrowserContext storage states.",
    )
    SCREENSHOT_STORAGE_DIR: str = Field(
        default="/data/profiles/_screenshots",
        description="Directory path for storing temporary screenshot PNG files.",
    )
    SCREENSHOT_TTL_SECONDS: int = Field(
        default=86400,
        ge=60,
        description="Temporary screenshot URL & file TTL in seconds before automatic expiration and deletion (default 86400 = 1 day).",
    )
    PUBLIC_BASE_URL: str = Field(
        default="https://mcp.kimohy.kr/camoufox",
        description="Fallback external base URL used when constructing temporary screenshot links.",
    )
    DEFAULT_PROXY_SERVER: Optional[str] = Field(
        default=None,
        description="Optional default outbound proxy server URL (e.g., http://proxy:8080 or socks5://proxy:1080).",
    )
    NAVIGATION_TIMEOUT_MS: int = Field(
        default=45000,
        description="Default page navigation timeout in milliseconds.",
    )

    @property
    def api_keys_list(self) -> List[str]:
        """Return parsed list of non-empty Bearer API keys."""
        if not self.MCP_API_KEYS:
            return []
        return [key.strip() for key in self.MCP_API_KEYS.split(",") if key.strip()]

    @property
    def effective_oauth_secret(self) -> str:
        """Return the configured OAuth Client Secret (falling back to the first MCP API key if unset)."""
        if self.OAUTH_CLIENT_SECRET and self.OAUTH_CLIENT_SECRET.strip():
            return self.OAUTH_CLIENT_SECRET.strip()
        keys = self.api_keys_list
        return keys[0] if keys else ""

    @property
    def effective_signing_secret(self) -> str:
        """Return HMAC signing secret for stateless OAuth tokens."""
        if self.OAUTH_SIGNING_SECRET and self.OAUTH_SIGNING_SECRET.strip():
            return self.OAUTH_SIGNING_SECRET.strip()
        return self.effective_oauth_secret or self.SECRET_URL_TOKEN or "camoufox-default-signing-key"

    @property
    def google_sso_enabled(self) -> bool:
        """Return True when both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are configured."""
        return bool(self.GOOGLE_CLIENT_ID.strip() and self.GOOGLE_CLIENT_SECRET.strip())

    @property
    def allowed_google_emails_list(self) -> List[str]:
        """Return normalized lowercase list of allowed Google email addresses."""
        if not self.ALLOWED_GOOGLE_EMAILS:
            return []
        return [e.strip().lower() for e in self.ALLOWED_GOOGLE_EMAILS.split(",") if e.strip()]

    @property
    def profile_dir_path(self) -> Path:
        """Ensure profile directory exists and return Path instance."""
        path = Path(self.PROFILE_STORAGE_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def screenshot_dir_path(self) -> Path:
        """Ensure screenshot directory exists and return Path instance."""
        path = Path(self.SCREENSHOT_STORAGE_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
