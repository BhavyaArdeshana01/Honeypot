"""SSH Honeypot using Paramiko - performs real SSH key exchange, captures credentials."""
import threading
import socket
import paramiko
import os

HOST_KEY_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'ssh_host_key')

def _get_host_key():
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    return key

HOST_KEY = _get_host_key()


class SSHHoneypotInterface(paramiko.ServerInterface):
    def __init__(self, log_mgr, ip, port):
        self.log_mgr    = log_mgr
        self.ip         = ip
        self.port       = port
        self.event      = threading.Event()
        self._username  = ''

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.log_mgr.log('ssh', self.ip, self.port,
            f'AUTH ATTEMPT — user: {username} | pass: {password}',
            extra={'username': username, 'password': password})
        # Always reject - but after logging
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        fp = key.get_fingerprint().hex()
        self.log_mgr.log('ssh', self.ip, self.port,
            f'PUBKEY ATTEMPT — user: {username} | fingerprint: {fp}',
            extra={'username': username, 'key_fingerprint': fp, 'key_type': key.get_name()})
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode(errors='replace')
        self.log_mgr.log('ssh', self.ip, self.port,
            f'EXEC REQUEST: {cmd}',
            extra={'command': cmd})
        return True


class SSHHoneypot:
    def __init__(self, port, banner, log_mgr):
        self.port       = port
        self.banner     = banner
        self.log_mgr    = log_mgr
        self._running   = False
        self._sock      = None

    def run(self):
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('0.0.0.0', self.port))
        self._sock.listen(50)
        self._sock.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        self.log_mgr.log('ssh', ip, port, f'New SSH connection')
        transport = None
        try:
            transport = paramiko.Transport(conn)
            transport.local_version = self.banner
            transport.add_server_key(HOST_KEY)
            server = SSHHoneypotInterface(self.log_mgr, ip, port)
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan:
                chan.send(b'\r\nAccess denied.\r\n')
                chan.close()
        except Exception as e:
            if 'Error reading SSH protocol banner' not in str(e):
                self.log_mgr.log('ssh', ip, port, f'SSH error: {str(e)[:100]}')
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
