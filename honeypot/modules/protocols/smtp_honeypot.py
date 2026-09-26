"""SMTP Honeypot - fake mail server capturing relay attempts and credentials."""
import base64
from modules.protocols.base import BaseHoneypot


class SMTPHoneypot(BaseHoneypot):
    def __init__(self, port, banner, log_mgr):
        super().__init__(port, banner, log_mgr, 'smtp')

    def _handle(self, conn, addr):
        ip, src_port = addr[0], addr[1]
        self.log_mgr.log('smtp', ip, src_port, 'New SMTP connection')
        mail_from = ''
        rcpt_to   = []
        body_lines = []
        in_data   = False
        try:
            self._safe_send(conn, f'{self.banner}\r\n')
            while True:
                data = self._safe_recv(conn, 4096, timeout=30)
                if not data:
                    break
                lines = data.decode(errors='replace').split('\r\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if in_data:
                        if line == '.':
                            in_data = False
                            full_body = '\n'.join(body_lines)
                            self.log_mgr.log('smtp', ip, src_port,
                                f'EMAIL CAPTURED | from: {mail_from} | to: {",".join(rcpt_to)} | size: {len(full_body)}b',
                                extra={'from': mail_from, 'to': rcpt_to, 'body_preview': full_body[:200]})
                            self._safe_send(conn, '250 2.0.0 Ok: queued\r\n')
                            mail_from, rcpt_to, body_lines = '', [], []
                        else:
                            body_lines.append(line)
                        continue
                    upper = line.upper()
                    if upper.startswith('EHLO') or upper.startswith('HELO'):
                        domain = line.split(' ', 1)[1] if ' ' in line else 'unknown'
                        self.log_mgr.log('smtp', ip, src_port, f'EHLO from: {domain}')
                        self._safe_send(conn,
                            '250-mail.corp-internal.net Hello\r\n'
                            '250-SIZE 10240000\r\n'
                            '250-AUTH LOGIN PLAIN\r\n'
                            '250-STARTTLS\r\n'
                            '250 HELP\r\n')
                    elif upper.startswith('AUTH'):
                        parts = line.split()
                        method = parts[1] if len(parts) > 1 else ''
                        if method == 'LOGIN':
                            self._safe_send(conn, '334 VXNlcm5hbWU6\r\n')  # "Username:"
                            u_data = self._safe_recv(conn, 256, timeout=10)
                            u_dec = base64.b64decode(u_data.strip()).decode(errors='replace') if u_data else ''
                            self._safe_send(conn, '334 UGFzc3dvcmQ6\r\n')  # "Password:"
                            p_data = self._safe_recv(conn, 256, timeout=10)
                            p_dec = base64.b64decode(p_data.strip()).decode(errors='replace') if p_data else ''
                            self.log_mgr.log('smtp', ip, src_port,
                                f'AUTH LOGIN — user: {u_dec} | pass: {p_dec}',
                                extra={'username': u_dec, 'password': p_dec, 'method': 'LOGIN'})
                            self._safe_send(conn, '535 5.7.8 Authentication credentials invalid\r\n')
                        elif method == 'PLAIN':
                            creds_b64 = parts[2] if len(parts) > 2 else ''
                            try:
                                decoded = base64.b64decode(creds_b64).decode(errors='replace')
                                parts2 = decoded.split('\x00')
                                u_dec = parts2[1] if len(parts2) > 1 else decoded
                                p_dec = parts2[2] if len(parts2) > 2 else ''
                            except Exception:
                                u_dec, p_dec = creds_b64, ''
                            self.log_mgr.log('smtp', ip, src_port,
                                f'AUTH PLAIN — user: {u_dec} | pass: {p_dec}',
                                extra={'username': u_dec, 'password': p_dec, 'method': 'PLAIN'})
                            self._safe_send(conn, '535 5.7.8 Authentication credentials invalid\r\n')
                        else:
                            self._safe_send(conn, '504 Unrecognized authentication type\r\n')
                    elif upper.startswith('MAIL FROM'):
                        mail_from = line[10:].strip('<>').strip() if len(line) > 10 else ''
                        self.log_mgr.log('smtp', ip, src_port, f'MAIL FROM: {mail_from}')
                        self._safe_send(conn, '250 2.1.0 Ok\r\n')
                    elif upper.startswith('RCPT TO'):
                        rcpt = line[8:].strip('<>').strip() if len(line) > 8 else ''
                        rcpt_to.append(rcpt)
                        self.log_mgr.log('smtp', ip, src_port, f'RCPT TO: {rcpt}')
                        self._safe_send(conn, '250 2.1.5 Ok\r\n')
                    elif upper == 'DATA':
                        in_data = True
                        self._safe_send(conn, '354 End data with <CR><LF>.<CR><LF>\r\n')
                    elif upper == 'QUIT':
                        self._safe_send(conn, '221 2.0.0 Bye\r\n')
                        return
                    elif upper == 'NOOP':
                        self._safe_send(conn, '250 2.0.0 Ok\r\n')
                    elif upper == 'RSET':
                        mail_from, rcpt_to, body_lines = '', [], []
                        self._safe_send(conn, '250 2.0.0 Ok\r\n')
                    elif upper == 'VRFY' or upper.startswith('VRFY'):
                        self._safe_send(conn, '252 Cannot VRFY user\r\n')
                    else:
                        self._safe_send(conn, '500 5.5.2 Syntax error\r\n')
        except Exception as e:
            self.log_mgr.log('smtp', ip, src_port, f'SMTP error: {e}')
        finally:
            self._close(conn)
