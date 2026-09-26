"""
Protocol Manager for PHANTOM GRID Honeypot
Manages lifecycle of all protocol honeypot listeners.
"""
import threading
from modules.protocols.http_honeypot   import HTTPHoneypot
from modules.protocols.ftp_honeypot    import FTPHoneypot
from modules.protocols.ssh_honeypot    import SSHHoneypot
from modules.protocols.snmp_honeypot   import SNMPHoneypot
from modules.protocols.smb_honeypot    import SMBHoneypot
from modules.protocols.telnet_honeypot import TelnetHoneypot
from modules.protocols.smtp_honeypot   import SMTPHoneypot

PROTOCOL_CLASSES = {
    'http':   HTTPHoneypot,
    'ftp':    FTPHoneypot,
    'ssh':    SSHHoneypot,
    'snmp':   SNMPHoneypot,
    'smb':    SMBHoneypot,
    'telnet': TelnetHoneypot,
    'smtp':   SMTPHoneypot,
}

class ProtocolManager:
    def __init__(self, log_mgr, config_mgr):
        self._log_mgr    = log_mgr
        self._config_mgr = config_mgr
        self._instances  = {}
        self._threads    = {}
        self._status     = {p: 'stopped' for p in PROTOCOL_CLASSES}
        self._lock       = threading.Lock()

    def _make_instance(self, proto):
        cls    = PROTOCOL_CLASSES[proto]
        port   = self._config_mgr.get_port(proto)
        banner = self._config_mgr.get_banner(proto)
        return cls(port=port, banner=banner, log_mgr=self._log_mgr)

    def start_all(self):
        for proto in PROTOCOL_CLASSES:
            self.toggle(proto, 'start')

    def toggle(self, proto, action):
        if proto not in PROTOCOL_CLASSES:
            return {'ok': False, 'error': 'Unknown protocol'}
        with self._lock:
            if action == 'start':
                if self._status[proto] == 'running':
                    return {'ok': True, 'status': 'already running'}
                try:
                    inst = self._make_instance(proto)
                    t = threading.Thread(target=inst.run, daemon=True, name=f'hp-{proto}')
                    t.start()
                    self._instances[proto] = inst
                    self._threads[proto]   = t
                    self._status[proto]    = 'running'
                    self._log_mgr._socketio.emit('protocol_status', {'proto': proto, 'status': 'running'})
                    return {'ok': True, 'status': 'running'}
                except Exception as e:
                    self._status[proto] = 'error'
                    return {'ok': False, 'error': str(e)}
            elif action == 'stop':
                if self._status[proto] == 'stopped':
                    return {'ok': True, 'status': 'already stopped'}
                inst = self._instances.get(proto)
                if inst:
                    try:
                        inst.stop()
                    except Exception:
                        pass
                self._status[proto] = 'stopped'
                self._log_mgr._socketio.emit('protocol_status', {'proto': proto, 'status': 'stopped'})
                return {'ok': True, 'status': 'stopped'}
        return {'ok': False, 'error': 'Unknown action'}

    def reload_banner(self, proto):
        inst = self._instances.get(proto)
        if inst:
            banner = self._config_mgr.get_banner(proto)
            inst.banner = banner
        return {'ok': True}

    def get_status(self):
        with self._lock:
            return {
                'protocols': {
                    proto: {
                        'status': self._status[proto],
                        'port':   self._config_mgr.get_port(proto),
                        'banner': self._config_mgr.get_banner(proto),
                    }
                    for proto in PROTOCOL_CLASSES
                }
            }
