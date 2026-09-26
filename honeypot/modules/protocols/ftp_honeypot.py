"""FTP Honeypot - Full fake FTP server that captures credentials."""
from modules.protocols.base import BaseHoneypot

FAKE_FILES = [
    'drwxr-xr-x   2 root root 4096 Jan 01 12:00 .',
    'drwxr-xr-x  18 root root 4096 Jan 01 12:00 ..',
    '-rw-r--r--   1 root root  512 Jan 01 12:00 backup.tar.gz',
    '-rw-------   1 root root 1024 Jan 01 12:00 passwords.txt',
    '-rw-r--r--   1 root root 2048 Jan 01 12:00 config.db',
    'drwxr-xr-x   2 root root 4096 Jan 01 12:00 private',
]

class FTPHoneypot(BaseHoneypot):
    def __init__(self, port, banner, log_mgr):
        super().__init__(port, banner, log_mgr, 'ftp')

    def _handle(self, conn, addr):
        ip, src_port = addr[0], addr[1]
        username = ''
        try:
            self._safe_send(conn, f'{self.banner}\r\n')
            self.log_mgr.log('ftp', ip, src_port, f'New FTP connection')

            while True:
                data = self._safe_recv(conn, 1024, timeout=30)
                if not data:
                    break
                cmd_line = data.decode(errors='replace').strip()
                if not cmd_line:
                    continue
                parts = cmd_line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ''

                if cmd == 'USER':
                    username = arg
                    self.log_mgr.log('ftp', ip, src_port, f'USER: {username}')
                    self._safe_send(conn, f'331 Password required for {username}\r\n')

                elif cmd == 'PASS':
                    password = arg
                    self.log_mgr.log('ftp', ip, src_port,
                        f'LOGIN ATTEMPT — user: {username} | pass: {password}',
                        extra={'username': username, 'password': password})
                    # Always fail after logging
                    self._safe_send(conn, '530 Login incorrect.\r\n')

                elif cmd == 'QUIT':
                    self._safe_send(conn, '221 Goodbye.\r\n')
                    break

                elif cmd == 'SYST':
                    self._safe_send(conn, '215 UNIX Type: L8\r\n')

                elif cmd == 'FEAT':
                    self._safe_send(conn, '211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n')

                elif cmd in ('LIST', 'NLST'):
                    self._safe_send(conn, '150 Opening ASCII mode data connection for file list\r\n')
                    self._safe_send(conn, '425 Can\'t open data connection.\r\n')

                else:
                    self._safe_send(conn, f'502 Command not implemented: {cmd}\r\n')
        except Exception as e:
            self.log_mgr.log('ftp', ip, src_port, f'Error: {e}')
        finally:
            self._close(conn)
