"""SMB Honeypot - Responds to SMB negotiation to appear as Windows share."""
import struct
from modules.protocols.base import BaseHoneypot

# SMB1 Negotiate Response (minimal, enough for nmap to identify)
def _build_smb_neg_response(banner):
    """Build a minimal SMB Negotiate Protocol Response."""
    # NetBIOS session header (4 bytes) + SMB header (32 bytes) + params
    smb_header = (
        b'\xff\x53\x4d\x42'  # Magic: \xffSMB
        b'\x72'              # Command: Negotiate Protocol (0x72)
        b'\x00\x00\x00\x00' # Status: success
        b'\x88'              # Flags: response
        b'\x01\xc0'         # Flags2
        b'\x00\x00'         # PID high
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Security features
        b'\x00\x00'         # Reserved
        b'\x00\x00'         # TID
        b'\xff\xfe'         # PID
        b'\x00\x00'         # UID
        b'\x00\x00'         # MID
    )
    # Word count + parameters (simplified)
    params = (
        b'\x11'             # WordCount = 17
        b'\x00\x00'         # DialectIndex: NTLM 0.12
        b'\x03'             # SecurityMode: user-level, challenges
        b'\x01\x00'         # MaxMpxCount
        b'\x01\x00'         # MaxNumberVcs
        b'\x00\x00\x10\x00' # MaxBufferSize: 65535
        b'\x00\x00\x01\x00' # MaxRawSize
        b'\x00\x00\x00\x00' # SessionKey
        b'\x01\x00\x00\x00' # Capabilities
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # SystemTime
        b'\x00\x00'         # ServerTimeZone
        b'\x08'             # ChallengeLength
    )
    challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    # ByteCount + native OS + native LAN manager
    native_os = banner.encode('utf-16-le') + b'\x00\x00'
    native_lan = b'Windows\x00'.encode('utf-16-le')
    byte_count = struct.pack('<H', 2 + len(challenge) + len(native_os) + len(native_lan))
    payload = params + byte_count + b'\x00\x00' + challenge + native_os + native_lan
    # NetBIOS session message header
    netbios = struct.pack('>I', len(smb_header) + len(payload))
    return netbios + smb_header + payload


class SMBHoneypot(BaseHoneypot):
    def __init__(self, port, banner, log_mgr):
        super().__init__(port, banner, log_mgr, 'smb')

    def _handle(self, conn, addr):
        ip, src_port = addr[0], addr[1]
        try:
            data = self._safe_recv(conn, 4096, timeout=10)
            if not data:
                return
            info = ''
            # Try to extract NetBIOS/SMB info
            if len(data) > 8 and data[4:8] == b'\xffSMB':
                cmd = data[8]
                info = f'SMB1 cmd=0x{cmd:02x}'
            elif len(data) > 8 and data[4:8] == b'\xfeSMB':
                info = 'SMB2/3 negotiation'
            else:
                info = f'Raw bytes: {data[:20].hex()}'
            self.log_mgr.log('smb', ip, src_port,
                f'SMB connection | {info}',
                extra={'smb_info': info, 'raw_hex': data[:32].hex()})
            # Send negotiate response to look legitimate
            resp = _build_smb_neg_response(self.banner)
            self._safe_send(conn, resp)
            # Wait briefly then close
            self._safe_recv(conn, 1024, timeout=2)
        except Exception as e:
            self.log_mgr.log('smb', ip, src_port, f'SMB error: {e}')
        finally:
            self._close(conn)
