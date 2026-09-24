"""
Process & Application Resolver Module.
Maps local network sockets (port + protocol) to active OS processes
(PID, executable name, and human-readable application labels) using psutil.
Includes a fast 1.5-second TTL cache to ensure zero latency overhead.
"""
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

_PORT_CACHE: dict[int, dict] = {}
_LAST_SCAN_TIME: float = 0.0
_SCAN_INTERVAL_SECONDS: float = 1.5

APP_MAPPINGS = {
    "antigravity.exe": ("Antigravity IDE", "code"),
    "code.exe": ("VS Code", "code"),
    "chrome.exe": ("Google Chrome", "globe"),
    "msedge.exe": ("Microsoft Edge", "globe"),
    "brave.exe": ("Brave Browser", "globe"),
    "firefox.exe": ("Mozilla Firefox", "globe"),
    "opera.exe": ("Opera Browser", "globe"),
    "python.exe": ("Python Service", "cpu"),
    "pythonw.exe": ("Python Service", "cpu"),
    "uvicorn.exe": ("Uvicorn Backend", "cpu"),
    "node.exe": ("Node.js / Vite", "zap"),
    "svchost.exe": ("Windows System", "shield"),
    "system": ("Windows Kernel", "shield"),
    "lsass.exe": ("Security Authority", "shield"),
    "powershell.exe": ("PowerShell", "terminal"),
    "cmd.exe": ("Command Prompt", "terminal"),
    "curl.exe": ("cURL Tool", "terminal"),
    "ping.exe": ("Ping Tool", "activity"),
    "discord.exe": ("Discord", "message"),
    "slack.exe": ("Slack", "message"),
    "telegram.exe": ("Telegram", "message"),
    "spotify.exe": ("Spotify", "activity"),
    "steam.exe": ("Steam Client", "activity"),
}

PORT_FALLBACKS = {
    8000: ("NetForecast API", "python.exe", "cpu"),
    5173: ("NetForecast UI", "node.exe", "zap"),
    3000: ("Web App (3000)", "node.exe", "zap"),
    80: ("HTTP Web", "web", "globe"),
    443: ("HTTPS Web", "web", "globe"),
    53: ("DNS Service", "dns", "globe"),
    22: ("SSH Remote", "ssh", "terminal"),
    445: ("SMB File Share", "smb", "shield"),
    3389: ("Remote Desktop", "rdp", "terminal"),
    8080: ("HTTP Proxy", "web", "globe"),
}


def _refresh_socket_table():
    global _LAST_SCAN_TIME, _PORT_CACHE
    now = time.time()
    if (now - _LAST_SCAN_TIME) < _SCAN_INTERVAL_SECONDS:
        return

    _LAST_SCAN_TIME = now
    new_cache = {}

    try:
        import psutil
        connections = psutil.net_connections(kind="inet")
        pids = {c.pid for c in connections if c.pid}

        proc_names = {}
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                proc_names[pid] = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_names[pid] = "System"

        for c in connections:
            if not c.laddr:
                continue
            lport = c.laddr.port
            pid = c.pid or 0
            raw_name = proc_names.get(pid, "Unknown")
            raw_name_lower = raw_name.lower()

            if (raw_name_lower in ("unknown", "system", "") or pid == 0) and lport in PORT_FALLBACKS:
                fallback_name, fallback_proc, fallback_icon = PORT_FALLBACKS[lport]
                app_name = fallback_name
                raw_name = fallback_proc
                app_icon = fallback_icon
            else:
                app_name, app_icon = APP_MAPPINGS.get(
                    raw_name_lower,
                    (raw_name.replace(".exe", "").capitalize(), "network")
                )

            new_cache[lport] = {
                "pid": pid,
                "process_name": raw_name,
                "app_name": app_name,
                "app_icon": app_icon,
                "cached_at": now,
            }

        _PORT_CACHE = new_cache
    except Exception as e:
        logger.debug("Socket-to-process scan failed (non-fatal): %s", e)


def resolve_process(port: Optional[int], protocol: Optional[str] = "TCP") -> dict:
    """
    Resolve local port to process metadata:
    Returns dict:
      {
        "pid": int,
        "process_name": str,
        "app_name": str,
        "app_icon": str,
      }
    """
    if not port or port <= 0:
        return {
            "pid": 0,
            "process_name": "Unknown",
            "app_name": "General Traffic",
            "app_icon": "network",
        }

    _refresh_socket_table()

    if port in _PORT_CACHE:
        return _PORT_CACHE[port]

    if port in PORT_FALLBACKS:
        app_name, proc_name, icon = PORT_FALLBACKS[port]
        return {
            "pid": 0,
            "process_name": proc_name,
            "app_name": app_name,
            "app_icon": icon,
        }

    return {
        "pid": 0,
        "process_name": "Port " + str(port),
        "app_name": f"Port {port} ({protocol or 'IP'})",
        "app_icon": "network",
    }
