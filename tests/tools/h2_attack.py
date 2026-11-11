"""A hand-written HTTP/2 client for tests that need control over the wire: it sends exactly the
frames it is told to, as fast as it is told to, and decodes the answers. No third-party HTTP/2
library is installed in the dev image, and none is wanted here: an attack tool has to be able
to break the protocol on purpose, which a library will not let it do.

HPACK: the encoder writes literals (never relying on the server's table), the decoder is a
complete one (static and dynamic tables, Huffman), so it can read whatever the server sends.
The Huffman code is the RFC 7541 Appendix B one, rebuilt from the code lengths in
scripts/gen-huffman.py, which is also what generates the server's table."""
import importlib.util
import os
import socket
import ssl
import struct
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, \
    CONTINUATION = range(10)
PRIORITY_UPDATE = 0x10
END_STREAM, END_HEADERS, PADDED, PRIORITY_FLAG = 0x1, 0x4, 0x8, 0x20
ACK = 0x1

NO_ERROR, PROTOCOL_ERROR, INTERNAL_ERROR, FLOW_CONTROL_ERROR, SETTINGS_TIMEOUT, STREAM_CLOSED, \
    FRAME_SIZE_ERROR, REFUSED_STREAM, CANCEL, COMPRESSION_ERROR, CONNECT_ERROR, \
    ENHANCE_YOUR_CALM = range(12)

S_HEADER_TABLE_SIZE, S_ENABLE_PUSH, S_MAX_CONCURRENT_STREAMS, S_INITIAL_WINDOW_SIZE, \
    S_MAX_FRAME_SIZE, S_MAX_HEADER_LIST_SIZE = 1, 2, 3, 4, 5, 6


def _load_lengths():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "gen-huffman.py")
    spec = importlib.util.spec_from_file_location("gen_huffman", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.LENGTHS


def _huffman_codes():
    lengths = _load_lengths()
    order = sorted(range(257), key=lambda s: (lengths[s], s))
    code, prev, table = 0, lengths[order[0]], {}
    for sym in order:
        code <<= lengths[sym] - prev
        prev = lengths[sym]
        table[(lengths[sym], code)] = sym
        code += 1
    return table


_HUFF = _huffman_codes()

STATIC = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""),
    ("content-length", ""), ("content-location", ""), ("content-range", ""), ("content-type", ""),
    ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""),
    ("host", ""), ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""),
    ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""),
    ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
]


def huffman_decode(data):
    out, code, length = bytearray(), 0, 0
    for byte in data:
        for i in range(7, -1, -1):
            code = (code << 1) | ((byte >> i) & 1)
            length += 1
            sym = _HUFF.get((length, code))
            if sym is not None:
                if sym == 256:
                    raise ValueError("EOS in a string")
                out.append(sym)
                code, length = 0, 0
            elif length > 30:
                raise ValueError("bad Huffman code")
    if length > 7 or code != (1 << length) - 1:
        raise ValueError("bad Huffman padding")
    return bytes(out)


def int_encode(value, prefix, first=0):
    mx = (1 << prefix) - 1
    if value < mx:
        return bytes([first | value])
    out = bytearray([first | mx])
    value -= mx
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def int_decode(buf, pos, prefix):
    mx = (1 << prefix) - 1
    v = buf[pos] & mx
    pos += 1
    if v < mx:
        return v, pos
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        v += (b & 127) << shift
        shift += 7
        if not b & 128:
            return v, pos


def _str_encode(s):
    b = s.encode() if isinstance(s, str) else s
    return int_encode(len(b), 7) + b


class Hpack:
    """Decoder with the dynamic table the peer's encoder fills; encode() writes literals only."""

    def __init__(self, max_size=4096):
        self.table, self.size, self.max = [], 0, max_size

    def _add(self, name, value):
        self.table.insert(0, (name, value))
        self.size += len(name) + len(value) + 32
        while self.size > self.max and self.table:
            n, v = self.table.pop()
            self.size -= len(n) + len(v) + 32

    def _index(self, i):
        if i == 0:
            raise ValueError("index 0")
        if i <= len(STATIC):
            return STATIC[i - 1]
        return self.table[i - len(STATIC) - 1]

    def _string(self, buf, pos):
        huff = buf[pos] & 0x80
        n, pos = int_decode(buf, pos, 7)
        raw = bytes(buf[pos:pos + n])
        if len(raw) != n:
            raise ValueError("truncated string")
        pos += n
        return (huffman_decode(raw) if huff else raw).decode("latin-1"), pos

    def decode(self, buf):
        out, pos = [], 0
        while pos < len(buf):
            b = buf[pos]
            if b & 0x80:
                i, pos = int_decode(buf, pos, 7)
                out.append(self._index(i))
            elif b & 0x40:
                i, pos = int_decode(buf, pos, 6)
                if i:
                    name = self._index(i)[0]
                else:
                    name, pos = self._string(buf, pos)
                value, pos = self._string(buf, pos)
                self._add(name, value)
                out.append((name, value))
            elif b & 0x20:
                self.max, pos = int_decode(buf, pos, 5)
                while self.size > self.max and self.table:
                    n, v = self.table.pop()
                    self.size -= len(n) + len(v) + 32
            else:
                i, pos = int_decode(buf, pos, 4)
                if i:
                    name = self._index(i)[0]
                else:
                    name, pos = self._string(buf, pos)
                value, pos = self._string(buf, pos)
                out.append((name, value))
        return out


def encode_block(headers, index=False, never=()):
    """A header block of literals. index=True asks the server's decoder to add every field to its
    dynamic table (RFC 7541 6.2.1), which is how the table-churn test fills it."""
    out = bytearray()
    for name, value in headers:
        full = {(":method", "GET"): 2, (":scheme", "https"): 7, (":path", "/"): 4}.get((name, value))
        if full and not index:
            out += int_encode(full, 7, 0x80)
            continue
        idx = next((i + 1 for i, (n, _) in enumerate(STATIC) if n == name), 0)
        if index:
            out += int_encode(idx, 6, 0x40)
        else:
            out += int_encode(idx, 4, 0x10 if name in never else 0x00)
        if not idx:
            out += _str_encode(name)
        out += _str_encode(value)
    return bytes(out)


def pack(ftype, flags, sid, payload=b""):
    n = len(payload)
    return struct.pack(">BHBBI", n >> 16, n & 0xFFFF, ftype, flags, sid) + payload


def settings_frame(items=(), ack=False):
    return pack(SETTINGS, ACK if ack else 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in items))


def window_update(sid, inc):
    return pack(WINDOW_UPDATE, 0, sid, struct.pack(">I", inc))


def rst(sid, code):
    return pack(RST_STREAM, 0, sid, struct.pack(">I", code))


def ping(data=b"12345678", ack=False):
    return pack(PING, ACK if ack else 0, 0, data)


def request_headers(path="/", method="GET", authority="localhost", scheme="https", extra=()):
    return [(":method", method), (":scheme", scheme), (":authority", authority),
            (":path", path)] + list(extra)


def headers_frame(sid, headers, end_stream=True, end_headers=True, index=False):
    flags = (END_STREAM if end_stream else 0) | (END_HEADERS if end_headers else 0)
    return pack(HEADERS, flags, sid, encode_block(headers, index=index))


class Stream:
    def __init__(self):
        self.headers, self.trailers, self.body = [], [], bytearray()
        self.ended, self.reset = False, None

    @property
    def status(self):
        for n, v in self.headers:
            if n == ":status":
                return int(v)
        return None

    def header(self, name):
        for n, v in self.headers:
            if n == name:
                return v
        return None


class H2:
    """One HTTP/2 connection. pump() reads one frame and records what it says; until() pumps till a
    condition holds or the time runs out."""

    def __init__(self, port, tls=True, host="localhost", timeout=10, handshake=True, settings=(),
                 auto_wu=True):
        s = socket.create_connection(("127.0.0.1", port), timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            s = ctx.wrap_socket(s, server_hostname=host)
            assert s.selected_alpn_protocol() == "h2", "the server did not choose h2"
        self.sock = s
        self.sock.settimeout(timeout)
        self.buf = b""
        self.dec = Hpack()
        self.streams = {}
        self.auto_wu = auto_wu
        self.goaway = None
        self.server_settings = {}
        self.settings_acks = 0
        self.pings = []
        self.pending = {}  # sid -> header block fragments being assembled
        self.eof = False
        self.frames_seen = 0
        self.conn_window_seen = 0
        if handshake:
            self.handshake(settings)

    # ---- sending ----
    def send(self, data):
        try:
            self.sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            self.eof = True

    def handshake(self, settings=()):
        self.send(PREFACE + settings_frame(settings))
        self.until(lambda: self.server_settings, 5)

    # ---- reading ----
    def _fill(self, n, timeout):
        deadline = time.monotonic() + timeout
        while len(self.buf) < n:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(1 << 16)
            except (socket.timeout, TimeoutError):
                return False
            except (ConnectionResetError, ssl.SSLError, OSError):
                self.eof = True
                return False
            if not chunk:
                self.eof = True
                return False
            self.buf += chunk
        return True

    def read_frame(self, timeout=1.0):
        if not self._fill(9, timeout):
            return None
        n = int.from_bytes(self.buf[:3], "big")
        if not self._fill(9 + n, timeout):
            return None
        ftype, flags = self.buf[3], self.buf[4]
        sid = struct.unpack(">I", self.buf[5:9])[0] & 0x7FFFFFFF
        payload = self.buf[9:9 + n]
        self.buf = self.buf[9 + n:]
        self.frames_seen += 1
        return ftype, flags, sid, payload

    def stream(self, sid):
        return self.streams.setdefault(sid, Stream())

    def pump(self, timeout=1.0):
        fr = self.read_frame(timeout)
        if fr is None:
            return None
        ftype, flags, sid, p = fr
        if ftype == SETTINGS:
            if flags & ACK:
                self.settings_acks += 1
            else:
                for i in range(0, len(p), 6):
                    k, v = struct.unpack(">HI", p[i:i + 6])
                    self.server_settings[k] = v
                if not self.server_settings:
                    self.server_settings[0] = 0
                self.send(settings_frame(ack=True))
        elif ftype == PING:
            if flags & ACK:
                self.pings.append(p)
            else:
                self.send(ping(p, ack=True))
        elif ftype == GOAWAY:
            self.goaway = (struct.unpack(">I", p[:4])[0] & 0x7FFFFFFF, struct.unpack(">I", p[4:8])[0])
        elif ftype == RST_STREAM:
            self.stream(sid).reset = struct.unpack(">I", p)[0]
        elif ftype in (HEADERS, CONTINUATION):
            if ftype == HEADERS:
                if flags & PADDED:
                    pad = p[0]
                    p = p[1:len(p) - pad]
                if flags & PRIORITY_FLAG:
                    p = p[5:]
                self.pending[sid] = [bytearray(), bool(flags & END_STREAM)]
            self.pending[sid][0] += p
            if flags & END_HEADERS:
                block, end = self.pending.pop(sid)
                fields = self.dec.decode(bytes(block))
                st = self.stream(sid)
                (st.trailers if st.headers else st.headers).extend(fields)
                if end:
                    st.ended = True
        elif ftype == DATA:
            body = p
            if flags & PADDED:
                body = p[1:len(p) - p[0]]
            st = self.stream(sid)
            st.body += body
            if flags & END_STREAM:
                st.ended = True
            if self.auto_wu and len(p):
                self.conn_window_seen += len(p)
                if not st.ended:
                    self.send(window_update(sid, len(p)))
                self.send(window_update(0, len(p)))
        return fr

    def until(self, cond, timeout=5.0):
        deadline = time.monotonic() + timeout
        while not cond():
            left = deadline - time.monotonic()
            if left <= 0 or self.eof:
                return cond()
            self.pump(min(left, 0.5))
        return True

    def response(self, sid, timeout=10.0):
        self.until(lambda: self.stream(sid).ended or self.stream(sid).reset is not None, timeout)
        return self.stream(sid)

    def drain(self, seconds=0.3):
        """Reads whatever arrives for a while."""
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self.eof:
            self.pump(min(0.1, end - time.monotonic()))

    def closed(self, timeout=3.0):
        """True when the server closes the connection (reading frames until it does)."""
        deadline = time.monotonic() + timeout
        while not self.eof and time.monotonic() < deadline:
            self.pump(0.2)
        return self.eof

    def get(self, sid, path="/", extra=(), end_stream=True):
        self.send(headers_frame(sid, request_headers(path, extra=extra), end_stream))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
