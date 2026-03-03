# Smart Firewall

A robust, three-layer DNS and IP-level firewall built in Python. This firewall effectively blocks domains at the network level, defeating modern browser bypass techniques like DNS-over-HTTPS (DoH) and DNS caching.

For a detailed breakdown of how the three-layer blocking mechanism works, please see [System Architecture](System_Architecture.md).

## Features
- **Network-Level Blocking**: Uses Windows Firewall to block actual IP addresses (both IPv4 and IPv6), defeating DoH.
- **Hosts File Redirection**: Overrides local DNS resolution by redirecting domains to `127.0.0.1`.
- **Live DNS Sniffing**: Uses `WinDivert` to actively monitor and drop UDP port 53 DNS queries for blocked domains.
- **Modern GUI**: A clean, dark-mode interface built with `customtkinter`.
- **Domain Verification**: Test if a domain is actively blocked, resolved, or unreachable.
- **Auto-Flush**: Automatically flushes the Windows DNS cache when rules are updated.

---

## 🚀 How to Download and Run Locally

### Prerequisites
- Windows OS (Required for `WinDivert`, the Hosts file, and Windows Firewall rules)
- Python 3.8 or higher installed
- **Administrator Privileges** (Required to modify Firewall rules and sniff packets)

### 1. Clone the Repository
Open your terminal (Command Prompt or PowerShell) and run:
```bash
git clone https://github.com/saiashok0981/simple-firewall-.git
cd simple-firewall-
```

### 2. Install Dependencies
It is highly recommended to use a virtual environment.
```bash
# Create a virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Install required packages
pip install fastapi uvicorn requests customtkinter pydivert scapy pydantic
```

### 3. Run the Application
The application **must** be run as an Administrator to function correctly. 

1. Open a terminal or command prompt **as Administrator**.
2. Navigate to the project folder.
3. Activate your virtual environment if you used one.
4. Run the main file:
```bash
python main.py
```

The graphical interface will appear, and the background API and packet sniffer will start automatically.

---

## 🛠️ How to Contribute or Push Updates to GitHub

If you are modifying the code and want to push your changes back to your GitHub repository:

1. **Check your changes:**
   ```bash
   git status
   ```

2. **Add all modified files:**
   ```bash
   git add .
   ```

3. **Commit your changes with a descriptive message:**
   ```bash
   git commit -m "Describe what you changed here"
   ```

4. **Push the changes to GitHub:**
   ```bash
   git push origin main
   ```
   *(If prompted, log in with your GitHub credentials to authorize the push).*

---

## License
MIT License
