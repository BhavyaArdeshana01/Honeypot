# 🕸️ PHANTOM GRID v2.0

### Advanced Multi-Protocol Honeypot Security System

> **"Every connection tells a story."**

PHANTOM GRID is a Python-based, multi-protocol honeypot designed for **cybersecurity research, network security education, attack simulation, and security event analysis**.

It emulates multiple network services and records interactions with those services, allowing defenders and security students to observe reconnaissance, service probing, authentication attempts, and other suspicious activity in a controlled environment.

---

## 🎯 Project Overview

Traditional security monitoring often focuses on protecting legitimate services.

A honeypot takes a different approach:

**It creates services that should attract unauthorized interaction and records what happens.**

PHANTOM GRID provides a centralized web dashboard where you can:

- Start and stop individual honeypot services
- Monitor connections in real time
- View security events
- Track activity by protocol
- Monitor attacker/source IP addresses
- Configure service banners
- Export security logs
- Analyze authentication attempts

The project is designed to provide a practical environment for learning concepts related to:

**SOC → Network Security → Threat Detection → Log Analysis → DFIR**

---

# 🚀 Key Features

## 🌐 7 Network Protocol Honeypots

PHANTOM GRID supports:

| Protocol | Default Port | Captured Activity |
|---|---:|---|
| HTTP | 80 | Requests, paths, headers, User-Agent |
| FTP | 21 | Authentication attempts |
| SSH | 22 | Authentication attempts and public-key fingerprints |
| SNMP | 161/UDP | Community strings |
| SMB | 445 | Connection and negotiation information |
| Telnet | 23 | Username and password attempts |
| SMTP | 25 | Authentication, sender and recipient information |

> High-numbered alternate ports can be configured when administrator privileges are not desired.

---

# 🖥️ Security Dashboard

PHANTOM GRID includes a web-based security dashboard designed as a centralized monitoring console.

### Dashboard capabilities

- 📡 Live connection feed
- 📊 Activity statistics
- 🚨 Severity-based security events
- 🌐 Protocol monitoring
- 🎯 Source/attacker IP tracking
- 📈 Activity timeline
- 🔎 Protocol filtering
- ⚙️ Protocol start/stop controls
- 🏷️ Service banner configuration
- 📥 Log export

The dashboard uses **Flask + Flask-SocketIO** for web functionality and real-time event updates.

---

# 🧪 Controlled Attack Simulation

PHANTOM GRID can be used to study how different types of network activity appear from a defender's perspective.

A typical laboratory workflow:

```text
                ┌──────────────────┐
                │   Kali Linux     │
                │                  │
                │ Nmap / Clients   │
                └────────┬─────────┘
                         │
                         │ Network Activity
                         ▼
                ┌──────────────────┐
                │   PHANTOM GRID   │
                │                  │
                │    Honeypot      │
                └────────┬─────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        Security Events        Live Dashboard
              │
              ▼
        ┌──────────────┐
        │ Honeypot Log │
        │    NDJSON    │
        └──────────────┘
