# Smart Firewall Architecture

This document breaks down the Smart Firewall's architecture, explaining how each component works together to block domains robustly at the network level, even against DoH (DNS-over-HTTPS) and browser caches.

## The Three-Layer Blocking Strategy

When you type a domain (e.g., `google.com`) and click **Block**, the system employs a three-layer defense to ensure it is unreachable across all applications and browsers.

1. **Layer 1: Windows Firewall Outbound Rule (Network Stack Block)**
   - **What it does:** The firewall resolves the domain to its actual IP addresses (both IPv4 and IPv6) using Google's DNS (`8.8.8.8`). Taking these IPs, it creates a hard network-layer block out of your computer using `netsh advfirewall`.
   - **Why it's needed:** Modern browsers like Chrome and Brave use DNS-over-HTTPS (DoH), which bypasses normal DNS queries entirely. By blocking the actual IP addresses at the network interface, it doesn't matter *how* the browser tries to get there—the connection is killed.

2. **Layer 2: Windows Hosts File (DNS Override)**
   - **What it does:** It writes an entry to your `C:\Windows\System32\drivers\etc\hosts` file mapping the blocked domain to `127.0.0.1` (localhost).
   - **Why it's needed:** For standard applications (command-line tools, older browsers, games) that rely on the OS DNS resolver, this instantly blackholes the domain before a network request is even created.

3. **Layer 3: UDP Port-53 Sniffer (Live Traffic Drop)**
   - **What it does:** Using `WinDivert` and `scapy`, a background thread actively watches all UDP network traffic on port 53 (the standard DNS port). If it sees a query for a blocked domain, it silently drops the packet.
   - **Why it's needed:** Acts as a catch-all for any DNS requests that somehow bypass the hosts file but don't use DoH.

---

## File Breakdown and Responsibilities

There are exactly 6 active Python files in the project. Here is what each one does:

### 1. `main.py` (The Orchestrator)
- **Role:** The entry point of the application.
- **What it does:** 
  - Starts the FastAPI background thread (`api.py`).
  - Starts the DNS sniffer background thread (`sniffer.py`).
  - Launches the CustomTkinter GUI on the main thread (`gui.py`).
  - Ensures the program cleanly shuts down when the GUI is closed.

### 2. `shared.py` (The Brain / Memory)
- **Role:** Centralized data storage.
- **What it does:** 
  - Holds the live Python `set()` of currently blocked domains so all threads can access them instantly.
  - Maintains the rolling system log buffer so the GUI can read live activity.
  - Secures data with a `threading.Lock()` so the GUI, API, and Sniffer don't collide when reading/writing at the exact same split-second.
  - Stores the user's `auto_flush_dns` preference.

### 3. `api.py` (The Middleman)
- **Role:** Accepts actions from the GUI and directs the backend logic.
- **What it does:**
  - Runs a local background server on `http://127.0.0.1:8000`.
  - Exposes endpoints like `/block`, `/unblock`, `/verify`, and `/logs`.
  - When the GUI calls `/block`, this file orchestrates the exact order of operations:
    1. Triggers `dns_utils` to lookup the real IPs and add the firewall rule.
    2. Updates the blocked list in `shared.py` (so the sniffer starts dropping packets).
    3. Triggers `dns_utils` to write to the hosts file.
    4. Triggers `dns_utils` to flush the DNS cache.

### 4. `dns_utils.py` (The Heavy Lifter)
- **Role:** Handles all the deep Windows integration and OS-level commands.
- **What it does:** 
  - **Firewall:** Runs `nslookup` against `8.8.8.8` to retrieve true IP addresses, then executes `netsh advfirewall` to add/remove block rules.
  - **Hosts File:** Reads and safely modifies the `C:\Windows\...\hosts` file without destroying existing contents.
  - **DNS Cache:** Executes `ipconfig /flushdns` when requested.
  - **Verification:** Contains the logic to test if a domain is actually dead (blocked) or alive (resolved).

### 5. `sniffer.py` (The Watchguard)
- **Role:** Low-level packet inspection.
- **What it does:**
  - Plugs into the Windows network stack using `pydivert` (WinDivert).
  - Captures every incoming/outgoing packet on UDP port 53.
  - Parses the raw packet using `scapy` to read the DNS request domain name.
  - Checks if the domain is in `shared.py`'s blocked list.
  - If it is blocked, it deletes the packet. If not, it lets it pass through.

### 6. `gui.py` (The Face)
- **Role:** The frontend interface.
- **What it does:**
  - Built using `customtkinter` for a modern dark-mode UI.
  - Provides the input box, the "Block" and "Unblock" buttons.
  - Provides the toolbar for "Verify", "Flush DNS", and the Auto-flush toggle.
  - Runs a background loop that constantly queries the `api.py`'s `/logs` endpoint to populate the live terminal readout at the bottom of the window without freezing the program.

---

## The Block Lifecycle: Step-by-Step

When you type `facebook.com` and hit **Block**, this sequence occurs in less than a second:

1. **GUI Thread:** `gui.py` sends an HTTP POST request to `127.0.0.1:8000/block`.
2. **API Thread:** `api.py` receives the request.
3. **DNS Utils:** `dns_utils.py` uses `nslookup` (via Google DNS over port 53) to get facebook's IP addresses (e.g., `157.240.22.35` and its IPv6 equivalents).
4. **Firewall:** `dns_utils.py` creates a Windows Firewall rule (`SmartFirewall_Block_facebook.com`) blocking all outbound access to those specific IP addresses.
5. **Shared Memory:** `shared.py` adds `"facebook.com"` to the blocking `set()`. 
6. **Sniffer Thread:** `sniffer.py` instantly begins dropping any UDP Port-53 queries for facebook.com.
7. **Hosts File:** `dns_utils.py` appends `127.0.0.1  facebook.com` to the Windows hosts file.
8. **DNS Cache:** `dns_utils.py` runs `ipconfig /flushdns` to wipe your OS's memory of the real IPs.
9. **GUI Thread:** Re-draws the UI to show facebook.com in the blocked list and updates the logs stream!
