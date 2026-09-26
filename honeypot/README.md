# PHANTOM GRID — Honeypot System

A sci-fi themed honeypot platform with a 3D command center dashboard, live feeds, and real protocol listeners.

---

## Features

- **7 Real Protocol Listeners**: HTTP, FTP, SSH, SNMP, SMB, Telnet, SMTP
- **Legitimate nmap fingerprinting** — each protocol responds realistically
- **Credential capture** — SSH/FTP/Telnet/SMTP log every auth attempt
- **Sci-Fi 3D Dashboard** with radar, live log feed, threat charts
- **Per-protocol banner control** with 35 predefined vulnerable banners
- **Log export** in JSON, CSV, and plain text
- **Web-based authentication** set on first launch

---

## Windows Setup

### Requirements
- Python 3.8+ (download from python.org)
- Administrator rights (for ports below 1024)

### Install & Run

```cmd
# 1. Extract the honeypot folder anywhere
# 2. Open Command Prompt as Administrator
# 3. Navigate to the folder:
cd C:\path\to\honeypot

# 4. Install Python dependencies:
pip install -r requirements.txt

# 5. Run:
python app.py

# OR double-click start_honeypot.bat (as Administrator)
```

### First Run
1. Open browser → `http://localhost:5000/setup`
2. Create your admin username and password
3. You'll be redirected to the login page
4. Log in — the dashboard loads automatically

---

## Protocol Details

| Protocol | Default Port | Nmap Detection | What It Captures |
|----------|-------------|----------------|------------------|
| HTTP     | 80          | Apache/IIS/nginx | GET paths, User-Agent, headers |
| FTP      | 21          | ProFTPD/vsftpd | Username + Password |
| SSH      | 22          | OpenSSH (real handshake) | Username, Password, Pubkey fingerprint |
| SNMP     | 161 (UDP)   | Net-SNMP      | Community strings |
| SMB      | 445         | Windows/Samba  | Connection info, negotiation |
| Telnet   | 23          | Linux/Cisco    | Username + Password (2 attempts) |
| SMTP     | 25          | Sendmail/Postfix | AUTH credentials, MAIL FROM, RCPT TO |

---

## Dashboard Features

### Protocol Control Panel (Left)
- Start/stop each protocol individually or all at once
- Click **◈ BANNER** to change the service banner per-protocol
- Pick from 35 predefined vulnerable banners (Apache CVE-2021-41773, vsftpd backdoor, EternalBlue, etc.)

### Live Feed (Center)
- All connections appear in real-time with severity color coding
- **Filter** by protocol using the buttons at the bottom
- Rotating radar shows live threat activity

### Stats Panel (Right)
- Activity timeline chart (last 60 seconds)
- Protocol breakdown bar chart
- Top attacker IPs
- Recent CRITICAL/HIGH alerts

### Log Export (Top Bar)
- **⬇ JSON** — Full structured JSON with all fields
- **⬇ CSV** — Spreadsheet-compatible
- **⬇ TXT** — Human-readable log file
- **✕ CLEAR** — Clear all in-memory and on-disk logs

---

## Windows Firewall

To allow external connections (for real attack capture), open these ports:

```cmd
# Run as Administrator:
netsh advfirewall firewall add rule name="Honeypot HTTP" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Honeypot FTP" dir=in action=allow protocol=TCP localport=21
netsh advfirewall firewall add rule name="Honeypot SSH" dir=in action=allow protocol=TCP localport=22
netsh advfirewall firewall add rule name="Honeypot SNMP" dir=in action=allow protocol=UDP localport=161
netsh advfirewall firewall add rule name="Honeypot SMB" dir=in action=allow protocol=TCP localport=445
netsh advfirewall firewall add rule name="Honeypot Telnet" dir=in action=allow protocol=TCP localport=23
netsh advfirewall firewall add rule name="Honeypot SMTP" dir=in action=allow protocol=TCP localport=25
```

---

## Using Alternate Ports (Non-Admin)

If you don't want to run as Administrator, edit `config.json` to use high ports:

```json
{
  "ports": {
    "http":   8080,
    "ftp":    2121,
    "ssh":    2222,
    "snmp":   16100,
    "smb":    4445,
    "telnet": 2323,
    "smtp":   2525
  }
}
```

Note: nmap won't auto-detect these as the expected services without `-p` flags or `-sV` version scanning.

---

## nmap Verification

Once running, from another machine:

```bash
# Service version scan
nmap -sV -p 21,22,23,25,80,161,445 <your-ip>

# Full version + script scan  
nmap -sV -sC -p 21,22,23,25,80,161,445 <your-ip>

# SNMP (UDP)
nmap -sU -p 161 <your-ip>
```

---

## Log Files
Logs are saved to `logs/honeypot.log` in NDJSON format. Each line is a JSON event.

---

## Legal Notice
This tool is for authorized security research and network defense only. Deploy only on networks you own or have explicit permission to monitor.
