"""A minimal RFC 6455 codec and echo upstream for the WebSocket proxy tests."""
import base64
import hashlib
import os
import socket
import struct

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_for(key):
    return base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()


def frame(opcode, payload, mask):
    hdr = bytes([0x80 | opcode])
    n = len(payload)
    mbit = 0x80 if mask else 0
    if n < 126:
        hdr += bytes([mbit | n])
    elif n < 65536:
        hdr += bytes([mbit | 126]) + struct.pack("!H", n)
    else:
        hdr += bytes([mbit | 127]) + struct.pack("!Q", n)
    if not mask:
        return hdr + payload
    k = os.urandom(4)
    return hdr + k + bytes(b ^ k[i % 4] for i, b in enumerate(payload))


def _recvn(s, n, buf):
    while len(buf[0]) < n:
        d = s.recv(65536)
        if not d:
            raise EOFError
        buf[0] += d
    out, buf[0] = buf[0][:n], buf[0][n:]
    return out


def read_frame(s, buf):
    """(opcode, payload); buf is a one-element list holding bytes read ahead."""
    b0, b1 = _recvn(s, 2, buf)
    op = b0 & 0x0F
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack("!H", _recvn(s, 2, buf))[0]
    elif n == 127:
        n = struct.unpack("!Q", _recvn(s, 8, buf))[0]
    k = _recvn(s, 4, buf) if b1 & 0x80 else None
    p = _recvn(s, n, buf)
    if k:
        p = bytes(b ^ k[i % 4] for i, b in enumerate(p))
    return op, p


def echo_handler(req, c):
    """Answers a WebSocket upgrade with 101 and echoes frames; a ping gets a pong, close ends."""
    key = req.get("sec-websocket-key")
    if req.get("upgrade") is None or key is None:
        from upstream_util import ok
        return ok("not an upgrade", status=400)
    c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Accept: {accept_for(key)}\r\n\r\n").encode())
    buf = [b""]
    try:
        while True:
            op, p = read_frame(c, buf)
            if op == 0x9:
                c.sendall(frame(0xA, p, False))
            elif op == 0x8:
                c.sendall(frame(0x8, p, False))
                break
            else:
                c.sendall(frame(op, p, False))
    except (EOFError, OSError):
        pass
    req.close = True
    return None


def ws_connect(port, path="/", key=None, version="13", extra=""):
    """Opens a WebSocket over HTTP/1.1; (socket, status, response head, read-ahead buffer)."""
    key = key if key is not None else base64.b64encode(os.urandom(16)).decode()
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: {version}\r\n{extra}\r\n").encode())
    data = b""
    while b"\r\n\r\n" not in data:
        d = s.recv(65536)
        if not d:
            break
        data += d
    head, _, rest = data.partition(b"\r\n\r\n")
    st = int(head.split(b" ", 2)[1]) if head else 0
    return s, st, head, [rest]
