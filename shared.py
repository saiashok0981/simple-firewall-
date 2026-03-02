"""
shared.py — Thread-safe shared state for the Smart Firewall.

All modules (API, sniffer, GUI) read/write through the helpers here
so that a single threading.Lock serialises access.
"""

import threading
from datetime import datetime
from typing import List, Tuple

# ── Shared Data ──────────────────────────────────────────────────────
blocked_domains: set[str] = set()
log_buffer: list[str] = []
auto_flush_dns: bool = True

_lock = threading.Lock()

# ── Stop signal for the sniffer thread ───────────────────────────────
stop_event = threading.Event()


def get_auto_flush() -> bool:
    """Return the current auto-flush-DNS setting (thread-safe)."""
    with _lock:
        return auto_flush_dns


def set_auto_flush(enabled: bool) -> None:
    """Update the auto-flush-DNS setting (thread-safe)."""
    global auto_flush_dns
    with _lock:
        auto_flush_dns = enabled
        _append_log(f"Auto-flush DNS {'enabled' if enabled else 'disabled'}")


# ── Helpers ──────────────────────────────────────────────────────────

def add_blocked_domain(domain: str) -> str:
    """Normalise *domain* to lowercase, add it to the blocked set,
    and append a timestamped log entry.  Returns the normalised domain."""
    domain = domain.strip().lower()
    with _lock:
        blocked_domains.add(domain)
        _append_log(f"Blocked domain: {domain}")
    return domain


def remove_blocked_domain(domain: str) -> bool:
    """Remove *domain* from the blocked set if present.
    Returns True if the domain was found and removed, False otherwise."""
    domain = domain.lower().strip()
    with _lock:
        if domain in blocked_domains:
            blocked_domains.remove(domain)
            _append_log(f"UNBLOCKED: {domain}")
            return True
        return False


def is_blocked(domain: str) -> bool:
    """Return True if *domain* (or any of its parent domains) is blocked."""
    domain = domain.strip().lower().rstrip(".")
    with _lock:
        # Check the domain itself and all parent zones,
        # e.g. "www.ads.example.com" matches "example.com".
        parts = domain.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in blocked_domains:
                return True
        return False


def get_and_flush_logs() -> Tuple[List[str], List[str]]:
    """Return (blocked_list, log_entries) and clear the log buffer."""
    with _lock:
        blocked_list = sorted(blocked_domains)
        logs = list(log_buffer)
        log_buffer.clear()
    return blocked_list, logs


def add_log(message: str) -> None:
    """Append a timestamped message to the log buffer."""
    with _lock:
        _append_log(message)


# ── Internal ─────────────────────────────────────────────────────────

def _append_log(message: str) -> None:
    """Append a timestamped entry (caller must already hold _lock)."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_buffer.append(f"[{timestamp}] {message}")
