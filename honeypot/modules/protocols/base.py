"""Base class for all protocol honeypot listeners."""
import socket
import threading


class BaseHoneypot:
    def __init__(self, port, banner, log_mgr, proto_name):
        self.port       = port
        self.banner     = banner
        self.log_mgr    = log_mgr
        self.proto_name = proto_name
        self._running   = False
        self._server_sock = None

    def run(self):
        self._running = True
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(('0.0.0.0', self.port))
            self._server_sock.listen(50)
            self._server_sock.settimeout(1.0)
            while self._running:
                try:
                    conn, addr = self._server_sock.accept()
                    t = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as e:
            self.log_mgr.log(self.proto_name, '0.0.0.0', self.port, f'Listener error: {e}')
        finally:
            self._running = False

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def _handle(self, conn, addr):
        raise NotImplementedError

    def _safe_recv(self, conn, size=4096, timeout=10):
        conn.settimeout(timeout)
        try:
            return conn.recv(size)
        except Exception:
            return b''

    def _safe_send(self, conn, data):
        try:
            if isinstance(data, str):
                data = data.encode()
            conn.sendall(data)
        except Exception:
            pass

    def _close(self, conn):
        try:
            conn.close()
        except Exception:
            pass
