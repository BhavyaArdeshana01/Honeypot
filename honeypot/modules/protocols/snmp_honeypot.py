"""SNMP Honeypot - UDP-based, responds to SNMP v1/v2c GET requests."""
import socket
import threading
import struct

# Minimal SNMP response builder (without pysnmp complexity)
# Returns a fake sysDescr for OID 1.3.6.1.2.1.1.1.0

def _parse_community(data):
    """Extract community string from SNMP packet (simple parser)."""
    try:
        if len(data) < 10:
            return None
        # Skip version + sequence header, find community string
        idx = 2  # skip SEQUENCE tag + length
        if data[idx] == 0x02:  # INTEGER (version)
            idx += 2 + data[idx+1]
        if idx < len(data) and data[idx] == 0x04:  # OCTET STRING (community)
            length = data[idx+1]
            return data[idx+2:idx+2+length].decode(errors='replace')
    except Exception:
        pass
    return None

def _make_error_response(request_data):
    """Return None - just log without responding for unhandled packets."""
    return None


class SNMPHoneypot:
    def __init__(self, port, banner, log_mgr):
        self.port     = port
        self.banner   = banner
        self.log_mgr  = log_mgr
        self._running = False
        self._sock    = None

    def run(self):
        self._running = True
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('0.0.0.0', self.port))
            self._sock.settimeout(1.0)
            while self._running:
                try:
                    data, addr = self._sock.recvfrom(4096)
                    ip, src_port = addr[0], addr[1]
                    community = _parse_community(data) or 'unknown'
                    self.log_mgr.log('snmp', ip, src_port,
                        f'SNMP request | community: "{community}" | bytes: {len(data)}',
                        extra={'community': community, 'raw_len': len(data)})
                    # Send a minimal SNMP response to appear legitimate
                    # sysDescr response
                    desc = self.banner.encode()
                    oid_encoded = b'\x2b\x06\x01\x02\x01\x01\x01\x00'  # 1.3.6.1.2.1.1.1.0
                    varbind = (b'\x30' + bytes([len(oid_encoded)+4+len(desc)]) +
                               b'\x06' + bytes([len(oid_encoded)]) + oid_encoded +
                               b'\x04' + bytes([len(desc)]) + desc)
                    varbind_list = b'\x30' + bytes([len(varbind)]) + varbind
                    # version=1(v2c=1), community
                    comm = community.encode()
                    version = b'\x02\x01\x01'
                    comm_field = b'\x04' + bytes([len(comm)]) + comm
                    # GetResponse PDU type = 0xa2
                    pdu_inner = (b'\x02\x04\x00\x00\x00\x01'  # request-id
                                 b'\x02\x01\x00'               # error-status=0
                                 b'\x02\x01\x00' +             # error-index=0
                                 varbind_list)
                    pdu = b'\xa2' + bytes([len(pdu_inner)]) + pdu_inner
                    msg_inner = version + comm_field + pdu
                    msg = b'\x30' + bytes([len(msg_inner)]) + msg_inner
                    self._sock.sendto(msg, addr)
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception as e:
            self.log_mgr.log('snmp', '0.0.0.0', self.port, f'SNMP listener error: {e}')
        finally:
            self._running = False

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
