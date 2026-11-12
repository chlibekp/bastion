"""A scriptable HTTP/1.1 upstream for proxy tests, on raw sockets so a test controls every byte.

Each accepted connection runs in a thread: requests are read (head, then a Content-Length or
chunked body), recorded, and answered by `handler(req, conn)`. A handler returns the response
bytes, or None after it wrote (or deliberately did not write) on conn itself. The default answers
200 with the request path as the body, keeping the connection open."""
import socket
import threading
import time


class Request:
    def __init__(self, head, body, conn_id):
        self.raw_head = head
        self.body = body
        self.conn_id = conn_id
        lines = head.decode("latin-1").split("\r\n")
        self.method, self.target, self.version = lines[0].split(" ")
        self.headers = []
        for line in lines[1:]:
            if line:
                k, v = line.split(":", 1)
                self.headers.append((k.strip().lower(), v.strip()))

    def get(self, name):
        vals = [v for k, v in self.headers if k == name.lower()]
        return vals[0] if vals else None

    def all(self, name):
        return [v for k, v in self.headers if k == name.lower()]


def ok(body=b"", status=200, headers=()):
    if isinstance(body, str):
        body = body.encode()
    h = "".join(f"{k}: {v}\r\n" for k, v in headers)
    return (f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\n{h}\r\n").encode() + body


def default_handler(req, conn):
    return ok(req.target)


class Upstream:
    def __init__(self, handler=default_handler, host="127.0.0.1", port=0, tls=None):
        """tls: an ssl.SSLContext (server side) to speak TLS; then sni, peer_certs and
        resumed record each handshake's SNI, client certificate and session reuse."""
        self.handler = handler
        self.tls = tls
        self.sni = []
        self.peer_certs = []
        self.resumed = []
        self.tls_failures = 0
        if tls is not None:
            tls.sni_callback = lambda sock, name, ctx: self.sni.append(name) and None
        self.requests = []
        self.connections = 0
        self.closed = 0  # connections that saw EOF from the proxy
        self.partial = []  # body bytes seen so far by the request being read (streaming tests)
        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind((host, port))
        self.lsock.listen(128)
        self.port = self.lsock.getsockname()[1]
        self.url = f"http://{host}:{self.port}"
        self._stop = False
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.lsock.close()
        except OSError:
            pass

    def _accept(self):
        while not self._stop:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
                cid = self.connections
            threading.Thread(target=self._serve, args=(c, cid), daemon=True).start()

    @staticmethod
    def _read_until(c, buf, marker):
        while marker not in buf:
            d = c.recv(65536)
            if not d:
                return None
            buf += d
        return buf

    def _read_body(self, c, rest, head):
        h = head.lower()
        if b"\r\ncontent-length:" in h:
            n = int(h.split(b"\r\ncontent-length:")[1].split(b"\r\n")[0])
            while len(rest) < n:
                d = c.recv(65536)
                if not d:
                    return None, b""
                rest += d
                self.partial.append(len(rest))
            return rest[:n], rest[n:]
        if b"\r\ntransfer-encoding: chunked" in h:
            body = b""
            while True:
                rest = self._read_until(c, rest, b"\r\n")
                if rest is None:
                    return None, b""
                line, rest = rest.split(b"\r\n", 1)
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    rest = self._read_until(c, rest, b"\r\n")
                    return body, rest.split(b"\r\n", 1)[1]
                while len(rest) < size + 2:
                    d = c.recv(65536)
                    if not d:
                        return None, b""
                    rest += d
                body += rest[:size]
                self.partial.append(len(body))
                rest = rest[size + 2:]
        return b"", rest

    def _serve(self, c, cid):
        buf = b""
        if self.tls is not None:
            try:
                c.settimeout(10)
                c = self.tls.wrap_socket(c, server_side=True)
                c.settimeout(None)
            except OSError:
                self.tls_failures += 1
                c.close()
                return
            self.peer_certs.append(c.getpeercert(binary_form=True))
            self.resumed.append(c.session_reused)
        try:
            while True:
                buf = self._read_until(c, buf, b"\r\n\r\n")
                if buf is None:
                    with self._lock:
                        self.closed += 1
                    return
                head, rest = buf.split(b"\r\n\r\n", 1)
                body, buf = self._read_body(c, rest, head)
                if body is None:
                    return
                req = Request(head, body, cid)
                self.requests.append(req)
                out = self.handler(req, c)
                if out is None:
                    if getattr(req, "close", False):
                        c.close()
                        return
                    continue
                c.sendall(out)
        except OSError:
            return
        finally:
            try:
                c.close()
            except OSError:
                pass


def wait_until(pred, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


def http(port, raw, timeout=5, read_all=True):
    """Sends raw on a new connection; returns everything read until close or timeout."""
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.sendall(raw)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
            if not read_all:
                break
    except socket.timeout:
        pass
    s.close()
    return out


def get(port, path="/", host="localhost", extra=""):
    return http(port, f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n".encode())
