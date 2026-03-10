"""
gui.py — CustomTkinter GUI for the Smart Firewall.

Provides:
  • An entry box to type a domain
  • Block / Unblock buttons
  • A toolbar with Verify, Flush DNS, and Auto-flush toggle
  • A scrollable log area that polls GET /logs every second
"""

import logging
import threading

import customtkinter as ctk
import requests

from wireshark_tab import WiresharkTab

# ── Logging ──────────────────────────────────────────────────────────
logger = logging.getLogger("firewall.gui")

# ── Configuration ────────────────────────────────────────────────────
API_BASE = "http://127.0.0.1:8000"
POLL_INTERVAL_MS = 1000  # 1 second


# ── GUI Application ─────────────────────────────────────────────────

class FirewallGUI(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()

        # ── Window settings ──────────────────────────────────────────
        self.title("🔒 Smart Firewall")
        self.geometry("800x700")
        self.minsize(700, 500)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._build_ui()
        self._init_settings()
        self._start_polling()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Create all widgets."""
        
        # ── Tabview Setup ────────────────────────────────────────────
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tab_firewall = self.tabview.add("Firewall")
        self.tab_pcap = self.tabview.add("Packet Capture")
        
        # Initialize the Wireshark tab
        WiresharkTab(self.tab_pcap)

        # ── Firewall Tab Content ─────────────────────────────────────
        # Title label
        title = ctk.CTkLabel(
            self.tab_firewall,
            text="🔒 Smart Firewall Control Panel",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        title.pack(pady=(10, 8))

        # ── Input frame ──────────────────────────────────────────────
        input_frame = ctk.CTkFrame(self.tab_firewall, fg_color="transparent")
        input_frame.pack(fill="x", padx=24, pady=(4, 8))

        self.domain_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter domain to block (e.g. ads.example.com)",
            height=40,
            font=ctk.CTkFont(size=14),
        )
        self.domain_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.domain_entry.bind("<Return>", lambda _event: self._on_block())

        self.block_btn = ctk.CTkButton(
            input_frame,
            text="🚫  Block",
            width=120,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._on_block,
        )
        self.block_btn.pack(side="right")

        # ── Status label ─────────────────────────────────────────────
        self.status_label = ctk.CTkLabel(
            self.tab_firewall,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#888888",
        )
        self.status_label.pack(pady=(0, 4))

        # ── Blocked-domains header + Unblock button ──────────────────
        blocked_header_frame = ctk.CTkFrame(self.tab_firewall, fg_color="transparent")
        blocked_header_frame.pack(fill="x", padx=24, pady=(4, 0))

        blocked_header = ctk.CTkLabel(
            blocked_header_frame,
            text="Blocked Domains",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        blocked_header.pack(side="left", padx=(2, 0))

        self.unblock_btn = ctk.CTkButton(
            blocked_header_frame,
            text="✅  Unblock",
            width=110,
            height=30,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#444444",
            hover_color="#666666",
            command=self._on_unblock,
        )
        self.unblock_btn.pack(side="right")

        # ── Blocked-domains scrollable list ───────────────────────────
        self.blocked_scroll = ctk.CTkScrollableFrame(self.tab_firewall, height=72)
        self.blocked_scroll.pack(fill="x", padx=24, pady=(2, 6))

        self._selected_domain: str | None = None
        self._domain_labels: dict[str, ctk.CTkLabel] = {}

        # ── DNS Tools toolbar ────────────────────────────────────────
        toolbar = ctk.CTkFrame(self.tab_firewall, fg_color="transparent")
        toolbar.pack(fill="x", padx=24, pady=(2, 6))

        self.verify_btn = ctk.CTkButton(
            toolbar,
            text="🔍  Verify",
            width=100,
            height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#2E5A88",
            hover_color="#3D6E9E",
            command=self._on_verify,
        )
        self.verify_btn.pack(side="left", padx=(0, 8))

        self.flush_btn = ctk.CTkButton(
            toolbar,
            text="🔄  Flush DNS",
            width=120,
            height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#5A4E2E",
            hover_color="#6E6340",
            command=self._on_flush_dns,
        )
        self.flush_btn.pack(side="left", padx=(0, 16))

        self._auto_flush_var = ctk.StringVar(value="on")
        self.auto_flush_switch = ctk.CTkSwitch(
            toolbar,
            text="Auto-flush DNS",
            font=ctk.CTkFont(size=12),
            variable=self._auto_flush_var,
            onvalue="on",
            offvalue="off",
            command=self._on_auto_flush_toggle,
        )
        self.auto_flush_switch.pack(side="left")

        # ── DNS flush indicator ──────────────────────────────────────
        self.dns_indicator = ctk.CTkLabel(
            toolbar,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#888888",
        )
        self.dns_indicator.pack(side="right")

        # ── Log area ─────────────────────────────────────────────────
        log_header = ctk.CTkLabel(
            self.tab_firewall,
            text="Live Logs",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        log_header.pack(fill="x", padx=26, pady=(4, 0))

        self.log_box = ctk.CTkTextbox(
            self.tab_firewall,
            height=200,
            font=ctk.CTkFont(family="Consolas", size=12),
            state="disabled",
            wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, padx=24, pady=(4, 18))

    # ── Settings initialisation ──────────────────────────────────────

    def _init_settings(self) -> None:
        """Fetch current settings from the API on startup."""
        threading.Thread(target=self._fetch_settings, daemon=True).start()

    def _fetch_settings(self) -> None:
        """GET /settings (runs in a worker thread)."""
        try:
            resp = requests.get(f"{API_BASE}/settings", timeout=5)
            data = resp.json()
            enabled = data.get("auto_flush_dns", True)
            self.after(0, self._apply_settings, enabled)
        except requests.RequestException:
            pass  # keep defaults

    def _apply_settings(self, auto_flush: bool) -> None:
        self._auto_flush_var.set("on" if auto_flush else "off")

    # ── Event handlers ───────────────────────────────────────────────

    def _on_block(self) -> None:
        """Send a POST /block request in a background thread."""
        domain = self.domain_entry.get().strip()
        if not domain:
            self._set_status("⚠️ Please enter a domain.", "#FFD700")
            return

        self.block_btn.configure(state="disabled")
        self._set_status(f"Blocking {domain}…", "#AAAAAA")
        threading.Thread(target=self._post_block, args=(domain,), daemon=True).start()

    def _post_block(self, domain: str) -> None:
        """POST to /block (runs in a worker thread)."""
        try:
            resp = requests.post(
                f"{API_BASE}/block",
                json={"domain": domain},
                timeout=15,
            )
            data = resp.json()
            self.after(0, self._block_success, data.get("domain", domain))
        except requests.RequestException as exc:
            logger.error("POST /block failed: %s", exc)
            self.after(0, self._block_error, str(exc))

    def _block_success(self, domain: str) -> None:
        self.domain_entry.delete(0, "end")
        self.block_btn.configure(state="normal")
        self._set_status(f"✅ {domain} blocked!", "#00CC66")

    def _block_error(self, error: str) -> None:
        self.block_btn.configure(state="normal")
        self._set_status(f"❌ Error: {error}", "#FF4444")

    # ── Unblock handlers ─────────────────────────────────────────────

    def _on_unblock(self) -> None:
        """Send a POST /unblock request for the currently selected domain."""
        if not self._selected_domain:
            self._set_status("⚠️ Select a domain to unblock.", "#FFD700")
            return

        domain = self._selected_domain
        self.unblock_btn.configure(state="disabled")
        self._set_status(f"Unblocking {domain}…", "#AAAAAA")
        threading.Thread(
            target=self._post_unblock, args=(domain,), daemon=True
        ).start()

    def _post_unblock(self, domain: str) -> None:
        """POST to /unblock (runs in a worker thread)."""
        try:
            resp = requests.post(
                f"{API_BASE}/unblock",
                json={"domain": domain},
                timeout=15,
            )
            data = resp.json()
            if data.get("status") == "unblocked":
                self.after(0, self._unblock_success, domain)
            else:
                self.after(0, self._unblock_error, f"{domain} not found")
        except requests.RequestException as exc:
            logger.error("POST /unblock failed: %s", exc)
            self.after(0, self._unblock_error, str(exc))

    def _unblock_success(self, domain: str) -> None:
        self._selected_domain = None
        self.unblock_btn.configure(state="normal")
        self._set_status(f"✅ {domain} unblocked!", "#00CC66")

    def _unblock_error(self, error: str) -> None:
        self.unblock_btn.configure(state="normal")
        self._set_status(f"❌ Error: {error}", "#FF4444")

    def _select_domain(self, domain: str) -> None:
        """Highlight the clicked domain and deselect others."""
        self._selected_domain = domain
        for d, lbl in self._domain_labels.items():
            if d == domain:
                lbl.configure(fg_color="#335577", corner_radius=6)
            else:
                lbl.configure(fg_color="transparent", corner_radius=0)

    # ── Verify handler ───────────────────────────────────────────────

    def _on_verify(self) -> None:
        """Verify whether the selected blocked domain is actually blocked."""
        if not self._selected_domain:
            self._set_status("⚠️ Select a domain to verify.", "#FFD700")
            return

        domain = self._selected_domain
        self.verify_btn.configure(state="disabled")
        self._set_status(f"🔍 Verifying {domain}…", "#AAAAAA")
        threading.Thread(
            target=self._post_verify, args=(domain,), daemon=True
        ).start()

    def _post_verify(self, domain: str) -> None:
        """POST to /verify (runs in a worker thread)."""
        try:
            resp = requests.post(
                f"{API_BASE}/verify",
                json={"domain": domain},
                timeout=20,
            )
            data = resp.json()
            self.after(0, self._verify_done, data)
        except requests.RequestException as exc:
            logger.error("POST /verify failed: %s", exc)
            self.after(0, self._verify_done, {
                "status": "error",
                "domain": domain,
                "message": str(exc),
            })

    def _verify_done(self, data: dict) -> None:
        """Update status with verify result on the main thread."""
        self.verify_btn.configure(state="normal")
        status = data.get("status", "unknown")
        domain = data.get("domain", "")
        message = data.get("message", "")

        colour_map = {
            "blocked": "#00CC66",      # green
            "resolved": "#FF4444",     # red
            "unreachable": "#FFD700",  # yellow
        }
        icon_map = {
            "blocked": "🟢",
            "resolved": "🔴",
            "unreachable": "🟡",
        }
        icon = icon_map.get(status, "❓")
        colour = colour_map.get(status, "#AAAAAA")
        self._set_status(f"{icon} {domain}: {status.upper()}", colour)

    # ── Flush DNS handler ────────────────────────────────────────────

    def _on_flush_dns(self) -> None:
        """Manually flush the Windows DNS cache."""
        self.flush_btn.configure(state="disabled")
        self._set_status("🔄 Flushing DNS cache…", "#AAAAAA")
        threading.Thread(target=self._post_flush_dns, daemon=True).start()

    def _post_flush_dns(self) -> None:
        """POST to /flush-dns (runs in a worker thread)."""
        try:
            resp = requests.post(f"{API_BASE}/flush-dns", timeout=15)
            data = resp.json()
            success = data.get("success", False)
            msg = data.get("message", "")
            self.after(0, self._flush_dns_done, success, msg)
        except requests.RequestException as exc:
            logger.error("POST /flush-dns failed: %s", exc)
            self.after(0, self._flush_dns_done, False, str(exc))

    def _flush_dns_done(self, success: bool, message: str) -> None:
        self.flush_btn.configure(state="normal")
        if success:
            self._set_status("✅ DNS cache flushed!", "#00CC66")
            self.dns_indicator.configure(text="Cache cleared ✓", text_color="#00CC66")
            # Fade indicator after 3 seconds
            self.after(3000, lambda: self.dns_indicator.configure(text=""))
        else:
            self._set_status(f"❌ {message}", "#FF4444")

    # ── Auto-flush toggle ────────────────────────────────────────────

    def _on_auto_flush_toggle(self) -> None:
        """Send the new auto-flush setting to the API."""
        enabled = self._auto_flush_var.get() == "on"
        threading.Thread(
            target=self._post_setting, args=(enabled,), daemon=True
        ).start()

    def _post_setting(self, enabled: bool) -> None:
        """POST to /settings (runs in a worker thread)."""
        try:
            requests.post(
                f"{API_BASE}/settings",
                json={"auto_flush_dns": enabled},
                timeout=5,
            )
            state = "enabled" if enabled else "disabled"
            self.after(0, self._set_status, f"Auto-flush DNS {state}", "#AAAAAA")
        except requests.RequestException as exc:
            logger.error("POST /settings failed: %s", exc)

    # ── Polling ──────────────────────────────────────────────────────

    def _start_polling(self) -> None:
        """Schedule the first poll."""
        self.after(POLL_INTERVAL_MS, self._poll_logs)

    def _poll_logs(self) -> None:
        """Fetch logs from the API and schedule the next poll."""
        threading.Thread(target=self._fetch_logs, daemon=True).start()
        self.after(POLL_INTERVAL_MS, self._poll_logs)

    def _fetch_logs(self) -> None:
        """GET /logs (runs in a worker thread)."""
        try:
            resp = requests.get(f"{API_BASE}/logs", timeout=5)
            data = resp.json()
            blocked = data.get("blocked", [])
            logs = data.get("logs", [])
            self.after(0, self._update_ui, blocked, logs)
        except requests.RequestException as exc:
            logger.debug("GET /logs failed: %s", exc)

    def _update_ui(self, blocked: list[str], logs: list[str]) -> None:
        """Update GUI widgets on the main thread."""
        # Rebuild the blocked-domains scrollable list
        current = set(self._domain_labels.keys())
        updated = set(blocked)

        # Remove labels for domains no longer blocked
        for domain in current - updated:
            self._domain_labels[domain].destroy()
            del self._domain_labels[domain]
            if self._selected_domain == domain:
                self._selected_domain = None

        # Add labels for newly blocked domains
        for domain in sorted(updated - current):
            lbl = ctk.CTkLabel(
                self.blocked_scroll,
                text=f"  🚫  {domain}",
                font=ctk.CTkFont(size=12),
                text_color="#FF6B6B",
                anchor="w",
                cursor="hand2",
            )
            lbl.pack(fill="x", pady=1)
            lbl.bind("<Button-1>", lambda _e, d=domain: self._select_domain(d))
            self._domain_labels[domain] = lbl

        # Re-apply selection highlight
        if self._selected_domain in self._domain_labels:
            self._domain_labels[self._selected_domain].configure(
                fg_color="#335577", corner_radius=6
            )

        # Append new log entries
        if logs:
            self.log_box.configure(state="normal")
            for entry in logs:
                self.log_box.insert("end", entry + "\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")

    # ── Utility ──────────────────────────────────────────────────────

    def _set_status(self, text: str, color: str = "#888888") -> None:
        self.status_label.configure(text=text, text_color=color)


# ── Runner ───────────────────────────────────────────────────────────

def run_gui() -> None:
    """Create and run the CustomTkinter application (blocks until closed)."""
    logger.info("Launching Smart Firewall GUI.")
    app = FirewallGUI()
    app.mainloop()
