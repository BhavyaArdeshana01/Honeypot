"""
Configuration Manager for PHANTOM GRID Honeypot
"""
import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'config.json')
DEFAULT_CONFIG = {
    "ports": {
        "http":   8080,
        "ftp":    2121,
        "ssh":    2222,
        "snmp":   16100,
        "smb":    4445,
        "telnet": 2323,
        "smtp":   2525,
    },
    "banners": {
        "http":   "Apache/2.4.49 (Unix) OpenSSL/1.1.1l PHP/7.4.23",
        "ftp":    "220 ProFTPD 1.3.5 Server (ProFTPD) [192.168.1.1]",
        "ssh":    "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        "snmp":   "Net-SNMP 5.7.3",
        "smb":    "Windows 7 Professional 7601 Service Pack 1 (Samba 4.5.16)",
        "telnet": "Linux 2.6.32-5-amd64 (Debian GNU/Linux 6.0)",
        "smtp":   "220 mail.corp-internal.net ESMTP Sendmail 8.14.4/8.14.4; Ready",
    },
    "admin_user": "",
    "log_file": "logs/honeypot.log",
    "max_log_entries": 10000,
}

BANNER_PRESETS = {
    "http": [
        {"label": "Apache 2.4.49 (Vulnerable CVE-2021-41773)", "value": "Apache/2.4.49 (Unix) OpenSSL/1.1.1l PHP/7.4.23"},
        {"label": "IIS 6.0 (Vulnerable CVE-2017-7269)",        "value": "Microsoft-IIS/6.0"},
        {"label": "nginx 1.14.0 (Ubuntu)",                     "value": "nginx/1.14.0 (Ubuntu)"},
        {"label": "Apache 2.2.14 (Legacy)",                    "value": "Apache/2.2.14 (Ubuntu) mod_ssl/2.2.14 OpenSSL/0.9.8k"},
        {"label": "Werkzeug/0.16.0 (Debug mode exposed)",      "value": "Werkzeug/0.16.0 Python/3.6.9"},
    ],
    "ftp": [
        {"label": "ProFTPD 1.3.5 (CVE-2015-3306 Mod_Copy)",   "value": "220 ProFTPD 1.3.5 Server (ProFTPD Default) [127.0.0.1]"},
        {"label": "vsftpd 2.3.4 (Backdoor CVE-2011-2523)",    "value": "220 (vsFTPd 2.3.4)"},
        {"label": "FileZilla Server 0.9.60",                   "value": "220-FileZilla Server 0.9.60 beta"},
        {"label": "wu-ftpd 2.6.2 (Legacy vulnerable)",        "value": "220 FTP server (Version wu-2.6.2(1)) ready."},
        {"label": "Pure-FTPd Anonymous",                       "value": "220---------- Welcome to Pure-FTPd [privsep] ----------"},
    ],
    "ssh": [
        {"label": "OpenSSH 7.4 Debian (CVE-2016-6210 enum)",  "value": "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"},
        {"label": "OpenSSH 4.7p1 (Weak crypto, old)",         "value": "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"},
        {"label": "Cisco IOS SSH",                             "value": "SSH-1.99-Cisco-1.25"},
        {"label": "Dropbear SSH 2016.74",                      "value": "SSH-2.0-dropbear_2016.74"},
        {"label": "OpenSSH 5.3 (RHEL 6)",                     "value": "SSH-2.0-OpenSSH_5.3"},
    ],
    "snmp": [
        {"label": "Net-SNMP 5.7.3 (community=public)",        "value": "Net-SNMP 5.7.3"},
        {"label": "Cisco SNMP Agent",                          "value": "Cisco Internetwork Operating System Software IOS 12.4"},
        {"label": "HP Network Node Manager",                   "value": "HP Network Node Manager i v9.0"},
        {"label": "NET-SNMP 5.4.3 (Ubuntu)",                  "value": "NET-SNMP 5.4.3"},
        {"label": "Windows SNMP Service",                      "value": "Hardware: x86 Family 6 - Software: Windows Version 5.1"},
    ],
    "smb": [
        {"label": "Windows 7 SP1 (EternalBlue CVE-2017-0144)","value": "Windows 7 Professional 7601 Service Pack 1"},
        {"label": "Windows XP SP2 (MS08-067 vulnerable)",     "value": "Windows XP Professional 2600 Service Pack 2"},
        {"label": "Samba 3.5.0 (CVE-2017-7494 SambaCry)",    "value": "Samba 3.5.0"},
        {"label": "Windows Server 2003 (Legacy)",              "value": "Windows Server 2003 3790 Service Pack 2"},
        {"label": "Windows 2000 Advanced Server",              "value": "Windows 5.0"},
    ],
    "telnet": [
        {"label": "Linux 2.6 Debian (Telnetd)",                "value": "\r\nDebian GNU/Linux 6.0\r\n"},
        {"label": "Cisco IOS Router",                          "value": "\r\nCisco IOS Software, Version 12.4(24)T4\r\n"},
        {"label": "HP ProCurve Switch",                        "value": "\r\nHP ProCurve Switch 2626\r\n"},
        {"label": "Juniper JunOS",                             "value": "\r\nJuniper Networks, Inc. m20 internet router\r\n"},
        {"label": "BusyBox Telnet (IoT device)",               "value": "\r\nBusyBox v1.19.4 built-in shell\r\n"},
    ],
    "smtp": [
        {"label": "Sendmail 8.14.4 (Legacy corp)",             "value": "220 mail.corp.local ESMTP Sendmail 8.14.4/8.14.4"},
        {"label": "Postfix SMTP (old Ubuntu)",                 "value": "220 ubuntu-server ESMTP Postfix (Ubuntu)"},
        {"label": "Microsoft Exchange 2010",                   "value": "220 EXCH01.corp.local Microsoft ESMTP MAIL Service ready"},
        {"label": "Exim 4.69 (CVE-2010-4344 heap overflow)",  "value": "220 mail.example.com ESMTP Exim 4.69 Mon, 01 Jan 2024"},
        {"label": "qmail 1.03 (Legacy open relay)",            "value": "220 ns1.example.com ESMTP"},
    ],
}

class ConfigManager:
    def __init__(self):
        self._cfg = dict(DEFAULT_CONFIG)
        self._load()

    def _load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    stored = json.load(f)
                # Deep merge
                for k, v in stored.items():
                    if isinstance(v, dict) and isinstance(self._cfg.get(k), dict):
                        self._cfg[k].update(v)
                    else:
                        self._cfg[k] = v
            except Exception:
                pass

    def save(self):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self._cfg, f, indent=2)

    def get(self, key, default=None):
        return self._cfg.get(key, default)

    def set(self, key, value):
        self._cfg[key] = value

    def get_port(self, proto):
        return self._cfg['ports'].get(proto, 0)

    def get_banner(self, proto):
        return self._cfg['banners'].get(proto, '')

    def set_banner(self, proto, banner):
        self._cfg['banners'][proto] = banner
        self.save()

    def get_banner_presets(self):
        return BANNER_PRESETS

    def get_all(self):
        return {
            'ports': self._cfg['ports'],
            'banners': self._cfg['banners'],
        }
