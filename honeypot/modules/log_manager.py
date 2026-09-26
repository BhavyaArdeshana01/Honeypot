"""
Log Manager for PHANTOM GRID Honeypot
Handles storage, retrieval, real-time emit, and export of connection events.
"""
import os
import json
import csv
import io
import threading
from datetime import datetime
from collections import defaultdict, deque

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'honeypot.log')

SEVERITY_MAP = {
    'http':   'MEDIUM',
    'ftp':    'HIGH',
    'ssh':    'CRITICAL',
    'snmp':   'MEDIUM',
    'smb':    'CRITICAL',
    'telnet': 'HIGH',
    'smtp':   'MEDIUM',
}

class LogManager:
    def __init__(self, socketio):
        self._socketio = socketio
        self._lock = threading.Lock()
        self._logs = deque(maxlen=10000)
        self._stats = defaultdict(int)
        self._ip_counter = defaultdict(int)
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    def log(self, proto, ip, port, message, extra=None):
        now = datetime.now()
        entry = {
            'id':        len(self._logs) + 1,
            'timestamp': now.isoformat(),
            'time_fmt':  now.strftime('%H:%M:%S'),
            'protocol':  proto.upper(),
            'proto_key': proto.lower(),
            'ip':        ip,
            'port':      port,
            'message':   message,
            'severity':  SEVERITY_MAP.get(proto.lower(), 'LOW'),
            'extra':     extra or {},
        }
        with self._lock:
            self._logs.appendleft(entry)
            self._stats[proto.lower()] += 1
            self._stats['total'] += 1
            self._ip_counter[ip] += 1

        # Write to file
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass

        # Emit to dashboard
        self._socketio.emit('new_log', entry)
        self._socketio.emit('stats_update', self.get_stats())
        return entry

    def get_logs(self, limit=200, proto=None):
        with self._lock:
            logs = list(self._logs)
        if proto:
            logs = [l for l in logs if l['proto_key'] == proto.lower()]
        return logs[:limit]

    def get_stats(self):
        with self._lock:
            stats = dict(self._stats)
            top_ips = sorted(self._ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            'counts': stats,
            'top_ips': [{'ip': ip, 'count': c} for ip, c in top_ips],
            'total': stats.get('total', 0),
        }

    def clear(self):
        with self._lock:
            self._logs.clear()
            self._stats.clear()
            self._ip_counter.clear()
        try:
            open(LOG_FILE, 'w').close()
        except Exception:
            pass
        self._socketio.emit('logs_cleared', {})

    def export(self, fmt='json'):
        with self._lock:
            logs = list(self._logs)
        if fmt == 'json':
            return json.dumps(logs, indent=2)
        elif fmt == 'csv':
            output = io.StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=['timestamp','protocol','ip','port','severity','message'])
                writer.writeheader()
                for l in logs:
                    writer.writerow({k: l.get(k,'') for k in ['timestamp','protocol','ip','port','severity','message']})
            return output.getvalue()
        else:
            lines = []
            for l in logs:
                lines.append(f"[{l['timestamp']}] [{l['severity']}] {l['protocol']} | {l['ip']}:{l['port']} | {l['message']}")
            return '\n'.join(lines)
