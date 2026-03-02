"""
api.py — FastAPI control-plane for the Smart Firewall.

Endpoints
---------
POST /block      — add a domain to the block list
POST /unblock    — remove a domain from the block list
POST /flush-dns  — manually flush Windows DNS cache
POST /verify     — flush cache + verify if domain is blocked
GET  /settings   — read current settings (auto_flush_dns)
POST /settings   — update settings
GET  /logs       — retrieve (and flush) current blocked domains + log entries
"""

import logging
from pydantic import BaseModel
import uvicorn
from fastapi import FastAPI

import shared
import dns_utils

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger("firewall.api")

# ── FastAPI application ──────────────────────────────────────────────
app = FastAPI(title="Smart Firewall API", version="1.0.0")


# ── Request / Response schemas ───────────────────────────────────────

class DomainRequest(BaseModel):
    domain: str


class DomainResponse(BaseModel):
    status: str
    domain: str
    dns_flushed: bool = False
    hosts_updated: bool = False


class FlushResponse(BaseModel):
    success: bool
    message: str


class VerifyResponse(BaseModel):
    domain: str
    status: str
    ip: str | None = None
    message: str


class SettingsPayload(BaseModel):
    auto_flush_dns: bool


class SettingsResponse(BaseModel):
    auto_flush_dns: bool


class LogsResponse(BaseModel):
    blocked: list[str]
    logs: list[str]


# ── Endpoints ────────────────────────────────────────────────────────

@app.post("/block", response_model=DomainResponse)
async def block_domain(req: DomainRequest):
    """Add *req.domain* to the blocked-domains set."""
    domain = req.domain.strip().lower()

    # Layer 3: Windows Firewall rule (resolve IPs BEFORE hosts redirect & BEFORE sniffer blocks it)
    dns_utils.add_firewall_rule(domain)

    shared.add_blocked_domain(domain)
    logger.info("Domain blocked via API: %s", domain)

    # Layer 1: Hosts file redirect to 127.0.0.1
    hosts_result = dns_utils.add_hosts_entry(domain)
    hosts_ok = hosts_result.get("success", False)

    # Flush DNS cache so all changes take effect immediately
    dns_flushed = False
    if shared.get_auto_flush():
        flush_result = dns_utils.flush_dns_cache()
        dns_flushed = flush_result.get("success", False)

    return DomainResponse(status="blocked", domain=domain,
                          dns_flushed=dns_flushed, hosts_updated=hosts_ok)


@app.post("/unblock", response_model=DomainResponse)
async def unblock_domain(req: DomainRequest):
    """Remove *req.domain* from the blocked-domains set."""
    success = shared.remove_blocked_domain(req.domain)

    hosts_ok = False
    dns_flushed = False
    if success:
        # Remove all blocking layers
        dns_utils.remove_firewall_rule(req.domain)
        hosts_result = dns_utils.remove_hosts_entry(req.domain)
        hosts_ok = hosts_result.get("success", False)

        if shared.get_auto_flush():
            flush_result = dns_utils.flush_dns_cache()
            dns_flushed = flush_result.get("success", False)

        logger.info("Domain unblocked via API: %s", req.domain)
        return DomainResponse(status="unblocked", domain=req.domain,
                              dns_flushed=dns_flushed, hosts_updated=hosts_ok)
    return DomainResponse(status="not_found", domain=req.domain)


@app.post("/flush-dns", response_model=FlushResponse)
async def flush_dns():
    """Manually flush the Windows DNS resolver cache."""
    result = dns_utils.flush_dns_cache()
    return FlushResponse(**result)


@app.post("/verify", response_model=VerifyResponse)
async def verify_domain(req: DomainRequest):
    """Flush DNS cache and verify whether *req.domain* is effectively blocked."""
    result = dns_utils.verify_domain(req.domain)
    return VerifyResponse(**result)


@app.get("/settings", response_model=SettingsResponse)
async def get_settings():
    """Return current firewall settings."""
    return SettingsResponse(auto_flush_dns=shared.get_auto_flush())


@app.post("/settings", response_model=SettingsResponse)
async def update_settings(payload: SettingsPayload):
    """Update firewall settings."""
    shared.set_auto_flush(payload.auto_flush_dns)
    logger.info("Settings updated: auto_flush_dns=%s", payload.auto_flush_dns)
    return SettingsResponse(auto_flush_dns=shared.get_auto_flush())


@app.get("/logs", response_model=LogsResponse)
async def get_logs():
    """Return the current blocked list and all buffered log entries,
    then clear the buffer."""
    blocked, logs = shared.get_and_flush_logs()
    return LogsResponse(blocked=blocked, logs=logs)


# ── Runner ───────────────────────────────────────────────────────────

def run_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the uvicorn server.  Intended to be called from a daemon thread."""
    logger.info("Starting FastAPI server on %s:%d", host, port)
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",   # keep console noise low
    )