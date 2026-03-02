"""
main.py — Integration entry point for the Smart Firewall.

Launches three components using threading:
  Thread 1 (daemon)  →  FastAPI server   (api.run_api)
  Thread 2 (daemon)  →  DNS sniffer      (sniffer.run_sniffer)
  Main thread        →  CustomTkinter GUI (gui.run_gui)

When the GUI window is closed the sniffer is signalled to stop
and the process exits cleanly.
"""

import logging
import sys
import threading
import time

import shared
from api import run_api
from sniffer import run_sniffer
from gui import run_gui

# ── Logging setup ────────────────────────────────────────────────────

def _configure_logging() -> None:
    """Set up a human-readable root logger for the console."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  [%(name)s]  %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )


# ── Main ─────────────────────────────────────────────────────────────

def main() -> None:
    _configure_logging()
    logger = logging.getLogger("firewall.main")
    logger.info("=" * 50)
    logger.info("  Smart Firewall — starting up")
    logger.info("=" * 50)

    # ── Thread 1: FastAPI server ─────────────────────────────────────
    api_thread = threading.Thread(
        target=run_api,
        name="APIThread",
        daemon=True,
    )
    api_thread.start()
    logger.info("API thread started.")

    # Give the API a moment to bind its socket before the GUI starts polling
    time.sleep(0.5)

    # ── Thread 2: DNS sniffer ────────────────────────────────────────
    sniffer_thread = threading.Thread(
        target=run_sniffer,
        name="SnifferThread",
        daemon=True,
    )
    sniffer_thread.start()
    logger.info("Sniffer thread started.")

    # ── Main thread: GUI (blocks until the window is closed) ─────────
    logger.info("Launching GUI on main thread…")
    try:
        run_gui()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("GUI closed — shutting down…")
        shared.stop_event.set()

        # Wait briefly for the sniffer to wind down
        sniffer_thread.join(timeout=2)
        logger.info("Bye!")


if __name__ == "__main__":
    main()
