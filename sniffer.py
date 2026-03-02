"""
sniffer.py — DNS packet sniffer using WinDivert + Scapy.

Intercepts UDP port-53 traffic.  If the queried domain matches
a blocked entry in shared.blocked_domains the packet is silently
dropped; otherwise it is re-injected into the network stack.
"""

import logging
import traceback

import pydivert
from scapy.layers.dns import DNS, DNSQR

import shared

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger("firewall.sniffer")

# WinDivert filter: capture all UDP traffic destined for or coming from port 53
WINDIVERT_FILTER = "udp.DstPort == 53 or udp.SrcPort == 53"


# ── Helpers ──────────────────────────────────────────────────────────

def _extract_dns_query(raw_payload: bytes) -> str | None:
    """Parse *raw_payload* with Scapy and return the queried domain name,
    or None if the packet is not a valid DNS query."""
    try:
        dns_packet = DNS(raw_payload)
        if dns_packet.haslayer(DNSQR):
            qname: bytes = dns_packet[DNSQR].qname
            # Scapy returns the QNAME as bytes ending with b"."
            return qname.decode("utf-8", errors="ignore").rstrip(".")
    except Exception:
        # Malformed packet — not a DNS query we care about
        logger.debug("Failed to parse DNS payload: %s", traceback.format_exc())
    return None


# ── Main loop ────────────────────────────────────────────────────────

def run_sniffer() -> None:
    """Open a WinDivert handle and inspect every DNS packet.

    The function blocks until ``shared.stop_event`` is set.
    Must be run with **Administrator privileges**.
    """
    logger.info("Starting DNS sniffer (filter: %s)", WINDIVERT_FILTER)
    shared.add_log("DNS sniffer started.")

    try:
        with pydivert.WinDivert(WINDIVERT_FILTER) as w:
            logger.info("WinDivert handle opened successfully.")
            while not shared.stop_event.is_set():
                # recv() blocks until a packet arrives or the handle is closed
                try:
                    packet = w.recv()
                except Exception:
                    if shared.stop_event.is_set():
                        break
                    logger.error("Error receiving packet: %s", traceback.format_exc())
                    continue

                raw = packet.payload  # UDP payload (DNS message)
                if raw is None:
                    # No payload — reinject as-is
                    w.send(packet)
                    continue

                domain = _extract_dns_query(raw)

                if domain and shared.is_blocked(domain):
                    # ── DROP ──
                    log_msg = f"DNS query BLOCKED: {domain}"
                    logger.info(log_msg)
                    shared.add_log(log_msg)
                    # Do NOT call w.send() → packet is silently dropped
                else:
                    # ── PASS ──
                    w.send(packet)

    except PermissionError:
        error_msg = "Sniffer requires Administrator privileges.  Restart as admin."
        logger.error(error_msg)
        shared.add_log(f"ERROR: {error_msg}")
    except Exception:
        error_msg = f"Sniffer error: {traceback.format_exc()}"
        logger.error(error_msg)
        shared.add_log(f"ERROR: Sniffer crashed — see console for details.")

    logger.info("DNS sniffer stopped.")
    shared.add_log("DNS sniffer stopped.")
