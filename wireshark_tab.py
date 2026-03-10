"""
wireshark_tab.py — Packet capture tab powered by pyshark.

Provides a self-contained Wireshark-like interface wrapped in a CustomTkinter frame.
Uses a daemon thread to run the capture loop and a thread-safe Queue to pass
packet dictionaries to the main GUI thread, avoiding Tkinter thread violations.
"""

import logging
import queue
import threading
from tkinter import ttk
from typing import Any, Dict

import customtkinter as ctk
import pyshark

logger = logging.getLogger("firewall.wireshark")

# ── Styling Constants ──────────────────────────────────────────────────
# Background colour matching typical dark themes
BG_COLOR = "#1e1e2e"
FG_COLOR = "#cdd6f4"

# Protocol colours
COLORS = {
    "TCP": "#89dceb",
    "UDP": "#a6e3a1",
    "DNS": "#f9e2af",
    "HTTP": "#cba6f7",
    "OTHER": FG_COLOR,
}

MAX_ROWS = 500


class WiresharkTab:
    """A self-contained packet capture tab."""

    def __init__(self, parent_frame: ctk.CTkFrame) -> None:
        self.parent = parent_frame
        
        # State
        self.is_capturing_live = False
        self.capture_thread: threading.Thread | None = None
        self.packet_queue: queue.Queue = queue.Queue()
        self.packet_count = 0
        self.raw_packets: dict[int, str] = {}  # Map row_id to hex payload
        
        # Polling loop variable
        self._poll_id = None
        
        self._build_ui()
        self._configure_treeview_styles()

    def _build_ui(self) -> None:
        """Construct the layout within the parent frame."""
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_rowconfigure(1, weight=1)  # Treeview takes max space
        
        # ── Top Control Bar ──────────────────────────────────────────
        control_frame = ctk.CTkFrame(self.parent, fg_color="transparent")
        control_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        
        # Interface
        ctk.CTkLabel(control_frame, text="Interface:").pack(side="left", padx=(0, 5))
        self.iface_entry = ctk.CTkEntry(control_frame, width=120, placeholder_text="e.g. Wi-Fi")
        self.iface_entry.pack(side="left", padx=(0, 15))
        
        # BPF Filter
        ctk.CTkLabel(control_frame, text="BPF Filter:").pack(side="left", padx=(0, 5))
        self.bpf_entry = ctk.CTkEntry(control_frame, width=180, placeholder_text="e.g. tcp port 80")
        self.bpf_entry.pack(side="left", padx=(0, 15))
        
        # Snapshot Count
        ctk.CTkLabel(control_frame, text="Count:").pack(side="left", padx=(0, 5))
        self.count_entry = ctk.CTkEntry(control_frame, width=50)
        self.count_entry.insert(0, "50")
        self.count_entry.pack(side="left", padx=(0, 15))
        
        # Buttons
        self.btn_live = ctk.CTkButton(
            control_frame, 
            text="▶ Start Live", 
            width=100, 
            fg_color="#00CC66", 
            hover_color="#00994C",
            command=self._toggle_live
        )
        self.btn_live.pack(side="left", padx=(0, 10))
        
        self.btn_snap = ctk.CTkButton(
            control_frame, 
            text="📷 Snapshot", 
            width=100,
            command=self._start_snapshot
        )
        self.btn_snap.pack(side="left", padx=(0, 10))
        
        self.btn_clear = ctk.CTkButton(
            control_frame, 
            text="🗑 Clear", 
            width=80, 
            fg_color="#444444", 
            hover_color="#666666",
            command=self._clear_table
        )
        self.btn_clear.pack(side="right")
        
        # ── Treeview (Packet Table) ──────────────────────────────────
        table_frame = ctk.CTkFrame(self.parent)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        
        columns = ("No", "Src", "SrcPort", "Dst", "DstPort", "Proto", "Len")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        
        # Configure columns
        self.tree.heading("No", text="No.")
        self.tree.column("No", width=50, anchor="center")
        self.tree.heading("Src", text="Source")
        self.tree.column("Src", width=120)
        self.tree.heading("SrcPort", text="SPort")
        self.tree.column("SrcPort", width=60, anchor="center")
        self.tree.heading("Dst", text="Destination")
        self.tree.column("Dst", width=120)
        self.tree.heading("DstPort", text="DPort")
        self.tree.column("DstPort", width=60, anchor="center")
        self.tree.heading("Proto", text="Protocol")
        self.tree.column("Proto", width=70, anchor="center")
        self.tree.heading("Len", text="Length")
        self.tree.column("Len", width=60, anchor="e")
        
        # Scrollbar for tree
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        
        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)
        
        # ── Payload Panel ────────────────────────────────────────────
        self.payload_box = ctk.CTkTextbox(
            self.parent, 
            height=120, 
            font=ctk.CTkFont(family="Consolas", size=12),
            state="disabled",
            wrap="word"
        )
        self.payload_box.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        
        # ── Status Bar ───────────────────────────────────────────────
        self.status_lbl = ctk.CTkLabel(
            self.parent, 
            text="Idle", 
            text_color="#888888", 
            font=ctk.CTkFont(size=12)
        )
        self.status_lbl.grid(row=3, column=0, sticky="w", padx=15, pady=(0, 5))

    def _configure_treeview_styles(self) -> None:
        """Apply dark theme styling to the ttk.Treeview."""
        style = ttk.Style()
        style.theme_use("default")
        
        style.configure(
            "Treeview",
            background=BG_COLOR,
            foreground=FG_COLOR,
            fieldbackground=BG_COLOR,
            borderwidth=0,
            rowheight=24,
            font=("Segoe UI", 10)
        )
        style.map(
            "Treeview",
            background=[("selected", "#335577")],
            foreground=[("selected", "white")]
        )
        style.configure(
            "Treeview.Heading",
            background="#2b2b36",
            foreground="white",
            borderwidth=1,
            font=("Segoe UI", 10, "bold")
        )
        
        # Tag colours
        for name, color in COLORS.items():
            self.tree.tag_configure(name, foreground=color)

    # ── UI Interactions ──────────────────────────────────────────────

    def _clear_table(self) -> None:
        """Clear all rows and payloads."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_count = 0
        self.raw_packets.clear()
        
        self.payload_box.configure(state="normal")
        self.payload_box.delete("1.0", "end")
        self.payload_box.configure(state="disabled")
        
        self.status_lbl.configure(text="Table cleared.")

    def _on_row_select(self, event: Any) -> None:
        """Display payload for the selected packet."""
        selection = self.tree.selection()
        if not selection:
            return
            
        item_id = selection[0]
        # The first value is the packet "No." which we stored as our key
        try:
            values = self.tree.item(item_id, "values")
            pkt_no = int(values[0])
            payload = self.raw_packets.get(pkt_no, "No raw payload available.")
        except Exception:
            payload = "Error retrieving payload."
            
        self.payload_box.configure(state="normal")
        self.payload_box.delete("1.0", "end")
        self.payload_box.insert("end", payload)
        self.payload_box.configure(state="disabled")

    # ── Capture Control ──────────────────────────────────────────────

    def _toggle_live(self) -> None:
        if self.is_capturing_live:
            self._stop_capture()
        else:
            self._start_live_capture()

    def _start_live_capture(self) -> None:
        iface = self.iface_entry.get().strip()
        bpf = self.bpf_entry.get().strip()
        
        self.is_capturing_live = True
        self.btn_live.configure(text="⏹ Stop Live", fg_color="#FF4444", hover_color="#CC0000")
        self.btn_snap.configure(state="disabled")
        self.btn_clear.configure(state="disabled")
        self.iface_entry.configure(state="disabled")
        self.bpf_entry.configure(state="disabled")
        self.status_lbl.configure(text="● Live — 0 packets captured", text_color="#FF4444")
        
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(iface, bpf, 0),  # 0 count = continuous
            daemon=True
        )
        self.capture_thread.start()
        
        # Start draining the queue
        self._poll_id = self.parent.after(100, self._process_queue)

    def _start_snapshot(self) -> None:
        if self.is_capturing_live:
            return
            
        iface = self.iface_entry.get().strip()
        bpf = self.bpf_entry.get().strip()
        try:
            count = int(self.count_entry.get().strip())
        except ValueError:
            count = 50
            
        self.btn_snap.configure(state="disabled")
        self.btn_live.configure(state="disabled")
        self.status_lbl.configure(text=f"Taking snapshot of {count} packets...", text_color="#AAAAAA")
        
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(iface, bpf, count),
            daemon=True
        )
        self.capture_thread.start()
        
        self._poll_id = self.parent.after(100, self._process_queue_snapshot)

    def _stop_capture(self) -> None:
        self.is_capturing_live = False
        self.btn_live.configure(text="▶ Start Live", fg_color="#00CC66", hover_color="#00994C")
        self.btn_snap.configure(state="normal")
        self.btn_clear.configure(state="normal")
        self.iface_entry.configure(state="normal")
        self.bpf_entry.configure(state="normal")
        self.status_lbl.configure(text="Idle", text_color="#888888")
        
        # The worker thread will exit when it sees is_capturing_live = False
        if self._poll_id:
            self.parent.after_cancel(self._poll_id)
            self._poll_id = None

    # ── Background Worker ────────────────────────────────────────────

    def _capture_worker(self, interface: str, bpf_filter: str, count: int) -> None:
        """Daemon thread running pyshark.LiveCapture."""
        import asyncio
        
        # Pyshark requires an asyncio event loop, which daemon threads don't get by default
        asyncio.set_event_loop(asyncio.new_event_loop())
        
        # Use None for default interface if empty
        iface_val = interface if interface else None
        bpf_val = bpf_filter if bpf_filter else None
        
        import os
        custom_tshark = r"C:\wireshark\tshark.exe"
        tshark_exe = custom_tshark if os.path.exists(custom_tshark) else None
        
        try:
            capture = pyshark.LiveCapture(interface=iface_val, bpf_filter=bpf_val, tshark_path=tshark_exe)
            
            # For continuous live capture
            if count == 0:
                for pkt in capture.sniff_continuously():
                    if not self.is_capturing_live:
                        break
                    parsed = self._parse_packet(pkt)
                    self.packet_queue.put(parsed)
            # For snapshot
            else:
                capture.sniff(packet_count=count)
                for pkt in capture:
                    parsed = self._parse_packet(pkt)
                    self.packet_queue.put(parsed)
                    
            # Put a sentinel to signal completion for snapshot mode
            if count > 0:
                self.packet_queue.put(None)
                
        except Exception as exc:
            logger.error("pyshark capture error: %s", exc)
            self.packet_queue.put({"error": str(exc)})
        finally:
            try:
                capture.close()
            except Exception:
                pass

    def _parse_packet(self, pkt: Any) -> Dict[str, Any]:
        """Convert a pyshark packet object to a simple dictionary."""
        try:
            proto = pkt.highest_layer
            length = pkt.length
            
            # Identify protocol logic
            tag = proto
            if hasattr(pkt, 'dns'): tag = "DNS"
            elif hasattr(pkt, 'http'): tag = "HTTP"
            elif hasattr(pkt, 'tcp'): tag = "TCP"
            elif hasattr(pkt, 'udp'): tag = "UDP"
            else: tag = "OTHER"
            
            # IP Layer
            src_ip = ""
            dst_ip = ""
            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
            elif hasattr(pkt, 'ipv6'):
                src_ip = pkt.ipv6.src
                dst_ip = pkt.ipv6.dst
                
            # Transport Layer
            src_port = ""
            dst_port = ""
            if hasattr(pkt, 'tcp'):
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
            elif hasattr(pkt, 'udp'):
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
                
            # Raw Hex dump if available
            raw_hex = "No hex payload dumped."
            # Only some layers expose hex, or we can get the raw frame
            if hasattr(pkt, 'get_raw_packet'):
                try:
                    raw_bytes = pkt.get_raw_packet()
                    # Format as hex dump
                    hex_str = raw_bytes.hex()
                    formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                    # Group into lines of 16 bytes
                    lines = [formatted[i:i+48] for i in range(0, len(formatted), 48)]
                    raw_hex = '\n'.join(f"{i:04x}  {line}" for i, line in enumerate(lines))
                except Exception:
                    pass

            return {
                "type": "packet",
                "src": src_ip,
                "sport": src_port,
                "dst": dst_ip,
                "dport": dst_port,
                "proto": tag,
                "len": length,
                "hex": raw_hex
            }
        except Exception as e:
            logger.debug("Error parsing packet: %s", e)
            return {"type": "packet", "src": "?", "sport": "?", "dst": "?", "dport": "?", "proto": "UNK", "len": "?", "hex": ""}

    # ── Main Thread GUI Updates ──────────────────────────────────────

    def _process_queue(self) -> None:
        """Poll the queue periodically for continuous mode."""
        if not self.is_capturing_live:
            return  # Will stop rescheduling
            
        self._drain_queue()
        
        self.status_lbl.configure(text=f"● Live — {self.packet_count} packets captured")
        self._poll_id = self.parent.after(100, self._process_queue)

    def _process_queue_snapshot(self) -> None:
        """Poll the queue periodically for snapshot mode."""
        done = self._drain_queue(snapshot_mode=True)
        
        if done:
            self.btn_snap.configure(state="normal")
            self.btn_live.configure(state="normal")
            self.status_lbl.configure(text=f"Snapshot complete — {self.packet_count} packets.", text_color="#00CC66")
            self._poll_id = None
        else:
            self._poll_id = self.parent.after(100, self._process_queue_snapshot)

    def _drain_queue(self, snapshot_mode: bool = False) -> bool:
        """Drain available packets and insert to Treeview. Returns True if sentinel seen."""
        updates = 0
        saw_sentinel = False
        
        while True:
            try:
                # Get all available items non-blocking
                item = self.packet_queue.get_nowait()
                
                if item is None:
                    saw_sentinel = True
                    break
                    
                if item.get("error"):
                    self._stop_capture()
                    self.status_lbl.configure(text=f"Error: {item['error']}", text_color="#FF4444")
                    break
                    
                if item.get("type") == "packet":
                    self.packet_count += 1
                    pkt_no = self.packet_count
                    
                    values = (
                        pkt_no,
                        item.get("src", ""),
                        item.get("sport", ""),
                        item.get("dst", ""),
                        item.get("dport", ""),
                        item.get("proto", ""),
                        item.get("len", "")
                    )
                    
                    proto_tag = item.get("proto", "OTHER")
                    if proto_tag not in COLORS:
                        proto_tag = "OTHER"
                        
                    self.tree.insert("", "end", values=values, tags=(proto_tag,))
                    self.raw_packets[pkt_no] = item.get("hex", "")
                    
                    updates += 1
                    
            except queue.Empty:
                break
                
        if updates > 0:
            # Enforce 500 row limit
            children = self.tree.get_children()
            if len(children) > MAX_ROWS:
                # Remove from top
                excess = len(children) - MAX_ROWS
                for i in range(excess):
                    # Clean up payload dict to avoid memory leak
                    try:
                        old_no = int(self.tree.item(children[i], "values")[0])
                        self.raw_packets.pop(old_no, None)
                    except Exception:
                        pass
                    self.tree.delete(children[i])
                    
                # Re-fetch children after deletion
                children = self.tree.get_children()
                
            # Auto-scroll to bottom
            if children:
                self.tree.see(children[-1])
                
        return saw_sentinel
