"""HTTP Honeypot - mimics Apache/IIS/nginx with fake responses."""
from modules.protocols.base import BaseHoneypot

FAKE_PAGES = {
    '/':        ('<html><head><title>Apache2 Ubuntu Default Page</title></head><body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></body></html>', 200, 'OK'),
    '/admin':   ('<html><body><h2>401 Unauthorized</h2></body></html>', 401, 'Unauthorized'),
    '/phpmyadmin': ('<html><body><h2>phpMyAdmin 4.8.1</h2><form method=post><input name=pma_username><input name=pma_password type=password><input type=submit value=Go></form></body></html>', 200, 'OK'),
    '/wp-admin': ('<html><body><h2>WordPress Login</h2><form method=post><input name=log placeholder=Username><input name=pwd type=password placeholder=Password><input type=submit value="Log In"></form></body></html>', 200, 'OK'),
    '/.env':    ('APP_KEY=base64:SomeRandomBase64Key\nDB_HOST=127.0.0.1\nDB_DATABASE=laravel\nDB_USERNAME=root\nDB_PASSWORD=secret\n', 200, 'OK'),
    '/config':  ('{"debug":true,"database":"mysql://root:password@localhost/app","secret":"jwt_secret_key"}', 200, 'OK'),
}

class HTTPHoneypot(BaseHoneypot):
    def __init__(self, port, banner, log_mgr):
        super().__init__(port, banner, log_mgr, 'http')

    def _handle(self, conn, addr):
        ip, port = addr[0], addr[1]
        try:
            data = self._safe_recv(conn, 8192)
            if not data:
                return
            lines = data.decode(errors='replace').split('\r\n')
            request_line = lines[0] if lines else ''
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    headers[k.lower()] = v

            method, path, *_ = (request_line.split(' ') + ['/', 'HTTP/1.1'])[:3]
            path = path.split('?')[0]

            user_agent = headers.get('user-agent', '')
            self.log_mgr.log('http', ip, port,
                f'{method} {path} | UA: {user_agent[:80]}',
                extra={'method': method, 'path': path, 'user_agent': user_agent, 'headers': dict(list(headers.items())[:10])})

            body, code, status = FAKE_PAGES.get(path, ('<html><body><h1>404 Not Found</h1></body></html>', 404, 'Not Found'))
            response = (
                f'HTTP/1.1 {code} {status}\r\n'
                f'Server: {self.banner}\r\n'
                f'Content-Type: text/html\r\n'
                f'Content-Length: {len(body)}\r\n'
                f'Connection: close\r\n'
                f'X-Powered-By: PHP/7.4.23\r\n'
                f'\r\n'
                f'{body}'
            )
            self._safe_send(conn, response)
        except Exception as e:
            self.log_mgr.log('http', ip, port, f'Handler error: {e}')
        finally:
            self._close(conn)
