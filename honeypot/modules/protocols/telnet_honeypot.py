"""Telnet Honeypot - fake login shell that captures credentials."""
import time
from modules.protocols.base import BaseHoneypot

# Telnet option negotiation bytes
IAC  = b'\xff'
WILL = b'\xfb'
WONT = b'\xfc'
DO   = b'\xfd'
DONT = b'\xfe'
ECHO = b'\x01'
SGA  = b'\x03'

NEGOTIATE = IAC + WILL + ECHO + IAC + WILL + SGA + IAC + DO + SGA

FAKE_SHELL_CMDS = {
    'ls':     'bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var',
    'pwd':    '/root',
    'whoami': 'root',
    'id':     'uid=0(root) gid=0(root) groups=0(root)',
    'uname -a': 'Linux debian-srv 2.6.32-5-amd64 #1 SMP Tue Jun 14 09:43:10 UTC 2011 x86_64 GNU/Linux',
    'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\nwww-data:x:33:33::/var/www:/bin/sh',
}


class TelnetHoneypot(BaseHoneypot):
    def __init__(self, port, banner, log_mgr):
        super().__init__(port, banner, log_mgr, 'telnet')

    def _recv_clean(self, conn):
        """Receive and strip telnet IAC sequences."""
        data = self._safe_recv(conn, 1024, timeout=30)
        if not data:
            return ''
        # Strip IAC sequences
        result = b''
        i = 0
        while i < len(data):
            if data[i:i+1] == b'\xff' and i + 2 < len(data):
                i += 3  # Skip IAC + cmd + option
            else:
                result += data[i:i+1]
                i += 1
        return result.decode(errors='replace').strip('\r\n').strip()

    def _handle(self, conn, addr):
        ip, src_port = addr[0], addr[1]
        self.log_mgr.log('telnet', ip, src_port, 'New Telnet connection')
        username = ''
        try:
            # Send telnet negotiation + banner
            self._safe_send(conn, NEGOTIATE)
            time.sleep(0.1)
            self._safe_send(conn, f'\r\n{self.banner}\r\n\r\n')
            self._safe_send(conn, 'login: ')
            username = self._recv_clean(conn)
            if not username:
                return
            self.log_mgr.log('telnet', ip, src_port, f'USERNAME: {username}')
            self._safe_send(conn, 'Password: ')
            # Don't echo password
            self._safe_send(conn, IAC + WILL + ECHO)
            password = self._recv_clean(conn)
            self._safe_send(conn, '\r\n')
            self.log_mgr.log('telnet', ip, src_port,
                f'LOGIN ATTEMPT — user: {username} | pass: {password}',
                extra={'username': username, 'password': password})
            time.sleep(1)
            self._safe_send(conn, 'Login incorrect\r\n\r\n')
            # Send second attempt
            self._safe_send(conn, 'login: ')
            u2 = self._recv_clean(conn)
            if u2:
                self._safe_send(conn, 'Password: ')
                p2 = self._recv_clean(conn)
                self._safe_send(conn, '\r\n')
                self.log_mgr.log('telnet', ip, src_port,
                    f'2ND LOGIN ATTEMPT — user: {u2} | pass: {p2}',
                    extra={'username': u2, 'password': p2, 'attempt': 2})
            self._safe_send(conn, 'Login incorrect\r\n')
        except Exception as e:
            self.log_mgr.log('telnet', ip, src_port, f'Telnet error: {e}')
        finally:
            self._close(conn)
