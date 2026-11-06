#!/usr/bin/env bash
set -euo pipefail

rm -f /tmp/.X99-lock /tmp/.X11-unix/X99

echo "[camoufox-pool] Starting Xvfb virtual display on :99..."
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
XVFB_PID=$!
export DISPLAY=:99

sleep 1
if ! kill -0 "$XVFB_PID" 2>/dev/null; then
    echo "[camoufox-pool] ERROR: Xvfb failed to start." >&2
    exit 1
fi

echo "[camoufox-pool] Launching Camoufox WebSocket Server on port ${PORT:-9222}..."
exec python - <<'PYEOF'
import os
import sys
import inspect
from camoufox.server import launch_server

ws_path = os.getenv("WS_PATH", "stealth-agent").lstrip("/")
port = int(os.getenv("PORT", "9222"))
proxy_server = os.getenv("DEFAULT_PROXY_SERVER", "").strip()

kwargs = {
    "headless": False,
    "humanize": True,
    "geoip": True,
    "port": port,
    "ws_path": ws_path,
}

if proxy_server:
    kwargs["proxy"] = {"server": proxy_server}

# Ensure compatibility across minor versions of camoufox.server.launch_server
sig = inspect.signature(launch_server)
if "host" in sig.parameters:
    kwargs["host"] = "0.0.0.0"

print(f"[camoufox-pool] Binding Camoufox server: port={port}, ws_path=/{ws_path}, humanize=True, geoip=True", flush=True)
launch_server(**kwargs)
PYEOF
