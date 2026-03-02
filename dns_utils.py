"""
dns_utils.py — Windows DNS cache flush, hosts-file management,
               Windows Firewall rules, and domain verification.

All functions are safe to call from any thread.  Heavy operations
(subprocess, socket, file I/O) are intentionally kept short-lived
so they can run in daemon worker threads without stalling the GUI.

Three-layer blocking strategy:
  1. Hosts file  → redirects domain to 127.0.0.1
  2. DNS sniffer → drops UDP port-53 queries (in sniffer.py)
  3. Windows Firewall → blocks outbound traffic to the domain's IPs
"""

import logging
import os
import socket
import subprocess
from typing import Any, Dict, List

import shared

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger("firewall.dns_utils")

# ── Constants ────────────────────────────────────────────────────────
HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "drivers", "etc", "hosts")
HOSTS_MARKER = "# SmartFirewall"
REDIRECT_IP = "127.0.0.1"
FW_RULE_PREFIX = "SmartFirewall_Block_"


# ── DNS Cache Flush ──────────────────────────────────────────────────

def flush_dns_cache() -> Dict[str, Any]:
    """Run ``ipconfig /flushdns`` and return a result dict."""
    try:
        result = subprocess.run(
            ["ipconfig", "/flushdns"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            msg = "DNS cache flushed successfully."
            logger.info(msg)
            shared.add_log(f"🔄 {msg}")
            return {"success": True, "message": msg}
        else:
            stderr = result.stderr.strip() or result.stdout.strip()
            msg = f"DNS flush failed (exit {result.returncode}): {stderr}"
            logger.warning(msg)
            shared.add_log(f"⚠️ {msg}")
            return {"success": False, "message": msg}

    except subprocess.TimeoutExpired:
        msg = "DNS flush timed out after 10 seconds."
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}

    except FileNotFoundError:
        msg = "ipconfig not found — is this running on Windows?"
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}

    except Exception as exc:
        msg = f"DNS flush error: {exc}"
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}


# ── Hosts File Management ───────────────────────────────────────────

def add_hosts_entry(domain: str) -> Dict[str, Any]:
    """Add a redirect entry for *domain* to the Windows hosts file."""
    domain = domain.strip().lower()
    entry_line = f"{REDIRECT_IP}    {domain}  {HOSTS_MARKER}\n"
    www_line = ""
    if not domain.startswith("www."):
        www_line = f"{REDIRECT_IP}    www.{domain}  {HOSTS_MARKER}\n"

    try:
        existing = _read_hosts()
        if f"{REDIRECT_IP}    {domain}  {HOSTS_MARKER}" in existing:
            return {"success": True, "message": f"{domain} already in hosts file."}

        with open(HOSTS_PATH, "a", encoding="utf-8") as f:
            f.write(entry_line)
            if www_line:
                f.write(www_line)

        msg = f"Hosts file: blocked {domain}"
        logger.info(msg)
        shared.add_log(f"📝 {msg}")
        return {"success": True, "message": msg}

    except PermissionError:
        msg = "Cannot write to hosts file — run as Administrator."
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}

    except Exception as exc:
        msg = f"Hosts file error: {exc}"
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}


def remove_hosts_entry(domain: str) -> Dict[str, Any]:
    """Remove the redirect entry for *domain* from the Windows hosts file."""
    domain = domain.strip().lower()
    www_domain = f"www.{domain}" if not domain.startswith("www.") else None

    try:
        existing = _read_hosts()
        new_lines = []
        removed = False

        for line in existing.splitlines():
            stripped = line.strip()
            if HOSTS_MARKER in stripped:
                parts = stripped.split()
                if len(parts) >= 2:
                    host_in_line = parts[1].lower()
                    if host_in_line == domain or host_in_line == www_domain:
                        removed = True
                        continue
            new_lines.append(line)

        if removed:
            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write("\n".join(new_lines))
                if new_lines and not new_lines[-1].endswith("\n"):
                    f.write("\n")

            msg = f"Hosts file: unblocked {domain}"
            logger.info(msg)
            shared.add_log(f"📝 {msg}")
            return {"success": True, "message": msg}
        else:
            return {"success": True, "message": f"{domain} not in hosts file."}

    except PermissionError:
        msg = "Cannot write to hosts file — run as Administrator."
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}

    except Exception as exc:
        msg = f"Hosts file error: {exc}"
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}


def _read_hosts() -> str:
    """Read the current hosts file contents."""
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


# ── Windows Firewall Rules ──────────────────────────────────────────

def _resolve_ips(domain: str) -> List[str]:
    """Resolve *domain* to a list of IP addresses using a public DNS (bypassing hosts file)."""
    ips = set()
    try:
        # Use 8.8.8.8 to bypass local hosts file and DoH complications
        result = subprocess.run(
            ["nslookup", domain, "8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            capture = False
            for line in lines:
                line = line.strip()
                if line.startswith("Name:"):
                    capture = True
                    continue
                if capture:
                    if line.startswith("Address:") or line.startswith("Addresses:"):
                        ip = line.split(":", 1)[1].strip()
                        if ip: ips.add(ip)
                    elif line and not line.startswith("Aliases:"):
                        # Continuation lines are usually just the IP
                        ips.add(line)
    except Exception as exc:
        logger.warning("nslookup failed for %s: %s", domain, exc)
        
    # Ensure no localhost IPs got through
    ips = {ip for ip in ips if not ip.startswith("127.") and ip != "::1"}
    
    # Fallback to OS resolver if nslookup failed to find anything
    if not ips:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                results = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                for r in results:
                    ip = str(r[4][0])
                    if not ip.startswith("127.") and ip != "::1":
                        ips.add(ip)
            except (socket.gaierror, OSError):
                pass
                
    return sorted(list(ips))


def add_firewall_rule(domain: str) -> Dict[str, Any]:
    """Create a Windows Firewall outbound-block rule for *domain*.

    Resolves the domain to IP addresses and blocks all outbound
    traffic to those IPs.  This is the most robust blocking method —
    it works regardless of DNS-over-HTTPS, browser caches, etc.
    """
    domain = domain.strip().lower()
    rule_name = f"{FW_RULE_PREFIX}{domain}"

    # First, remove any existing rule to avoid duplicates
    _delete_firewall_rule(rule_name)

    # Resolve IPs BEFORE adding hosts entry (so we get the real IPs)
    ips = _resolve_ips(domain)
    # Also try the www variant
    if not domain.startswith("www."):
        ips.extend(_resolve_ips(f"www.{domain}"))

    if not ips:
        msg = f"Could not resolve IPs for {domain} — firewall rule not created."
        logger.warning(msg)
        shared.add_log(f"⚠️ {msg}")
        return {"success": False, "message": msg}

    # De-duplicate
    unique_ips = sorted(set(ips))
    ip_list = ",".join(unique_ips)

    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip_list}",
                "protocol=any",
                "enable=yes",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            msg = f"Firewall rule: blocked {domain} (IPs: {ip_list})"
            logger.info(msg)
            shared.add_log(f"🛡️ {msg}")
            return {"success": True, "message": msg, "ips": unique_ips}
        else:
            stderr = result.stderr.strip() or result.stdout.strip()
            msg = f"Firewall rule failed: {stderr}"
            logger.error(msg)
            shared.add_log(f"❌ {msg}")
            return {"success": False, "message": msg}

    except PermissionError:
        msg = "Cannot create firewall rule — run as Administrator."
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}

    except Exception as exc:
        msg = f"Firewall rule error: {exc}"
        logger.error(msg)
        shared.add_log(f"❌ {msg}")
        return {"success": False, "message": msg}


def remove_firewall_rule(domain: str) -> Dict[str, Any]:
    """Remove the Windows Firewall outbound-block rule for *domain*."""
    domain = domain.strip().lower()
    rule_name = f"{FW_RULE_PREFIX}{domain}"
    return _delete_firewall_rule(rule_name)


def _delete_firewall_rule(rule_name: str) -> Dict[str, Any]:
    """Delete a Windows Firewall rule by name."""
    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            msg = f"Firewall rule removed: {rule_name}"
            logger.info(msg)
            shared.add_log(f"🛡️ {msg}")
            return {"success": True, "message": msg}
        else:
            # Rule didn't exist — that's fine
            return {"success": True, "message": f"No existing rule: {rule_name}"}

    except Exception as exc:
        msg = f"Firewall rule delete error: {exc}"
        logger.error(msg)
        return {"success": False, "message": msg}


# ── Domain Verification ─────────────────────────────────────────────

def verify_domain(domain: str) -> Dict[str, Any]:
    """Flush the DNS cache, then attempt to resolve *domain*.

    Returns a dict with status "blocked" / "resolved" / "unreachable".
    """
    domain = domain.strip().lower()
    shared.add_log(f"🔍 Verifying domain: {domain}")

    # Step 1: flush so Windows doesn't serve a stale cached entry
    flush_dns_cache()

    # Step 2: attempt resolution
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        try:
            results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC,
                                         socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_timeout)

        if results:
            ip = str(results[0][4][0])
            # If it resolves to localhost, it's redirected by hosts file
            if ip.startswith("127.") or ip == "::1":
                msg = (f"Domain {domain} resolves to {ip} "
                       f"(redirected by hosts file) — effectively BLOCKED.")
                logger.info(msg)
                shared.add_log(f"🟢 {msg}")
                return {"domain": domain, "status": "blocked",
                        "ip": ip, "message": msg}

            msg = f"Domain {domain} RESOLVED to {ip} — still reachable."
            logger.info(msg)
            shared.add_log(f"🔴 {msg}")
            return {"domain": domain, "status": "resolved",
                    "ip": ip, "message": msg}

    except socket.gaierror:
        msg = f"Domain {domain} is BLOCKED — DNS resolution failed."
        logger.info(msg)
        shared.add_log(f"🟢 {msg}")
        return {"domain": domain, "status": "blocked",
                "ip": None, "message": msg}

    except socket.timeout:
        msg = f"Domain {domain} verification timed out — inconclusive."
        logger.warning(msg)
        shared.add_log(f"🟡 {msg}")
        return {"domain": domain, "status": "unreachable",
                "ip": None, "message": msg}

    except OSError as exc:
        msg = f"Domain {domain} unreachable — network error: {exc}"
        logger.warning(msg)
        shared.add_log(f"🟡 {msg}")
        return {"domain": domain, "status": "unreachable",
                "ip": None, "message": msg}

    # Fallback
    msg = f"Domain {domain} — no results from DNS lookup."
    shared.add_log(f"🟢 {msg}")
    return {"domain": domain, "status": "blocked",
            "ip": None, "message": msg}
