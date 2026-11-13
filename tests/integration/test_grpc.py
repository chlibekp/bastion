"""HTTP/2 upstreams and gRPC through the proxy (Phase 9, Task 8): a real gRPC server and client
(grpcio) on both ends of bastion, plus a raw HTTP/2 upstream (the h2 library) for connection
behaviour the gRPC server does not let a test control: multiplexing, GOAWAY and
SETTINGS_MAX_CONCURRENT_STREAMS."""
import socket
import struct
import threading
import time
from concurrent import futures

import pytest

grpc = pytest.importorskip("grpc")
h2conn = pytest.importorskip("h2.connection")
import h2.config  # noqa: E402
import h2.events  # noqa: E402
import h2.settings  # noqa: E402

from upstream_util import get, wait_until  # noqa: E402

SVC = "/test.Echo/"


def ident(x):
    return x


def make_server(state):
    def unary(req, ctx):
        if req == b"fail":
            ctx.set_trailing_metadata((("x-trail", "yes"),))
            ctx.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad thing")
        return b"echo:" + req

    def server_stream(req, ctx):
        for i in range(5):
            yield b"%s-%d" % (req, i)

    def client_stream(it, ctx):
        return b"|".join(it)

    def bidi(it, ctx):
        for m in it:
            yield m

    def slow(req, ctx):
        ctx.add_callback(lambda: state.__setitem__("cancelled", True))
        deadline = time.monotonic() + 10
        while ctx.is_active() and time.monotonic() < deadline:
            time.sleep(0.02)
        return b"late"

    h = {
        "Unary": grpc.unary_unary_rpc_method_handler(unary, ident, ident),
        "ServerStream": grpc.unary_stream_rpc_method_handler(server_stream, ident, ident),
        "ClientStream": grpc.stream_unary_rpc_method_handler(client_stream, ident, ident),
        "Bidi": grpc.stream_stream_rpc_method_handler(bidi, ident, ident),
        "Slow": grpc.unary_unary_rpc_method_handler(slow, ident, ident),
    }
    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=16),
                      options=[("grpc.max_receive_message_length", 64 << 20),
                               ("grpc.max_send_message_length", 64 << 20)])
    srv.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("test.Echo", h),))
    port = srv.add_insecure_port("127.0.0.1:0")
    srv.start()
    return srv, port


def conf(up_port, extra=""):
    return (f"workers 1;\nupstream g {{ server 127.0.0.1:{up_port}; protocol http2; {extra} }}\n"
            f"server {{ listen 127.0.0.1:@HTTP_PORT@ h2c; client_max_body_size 0;\n"
            f"location / {{ proxy g; }} }}\n")


@pytest.fixture
def grpc_env(bastion):
    state = {}
    srv, port = make_server(state)
    b = bastion(conf(port))
    ch = grpc.insecure_channel(f"127.0.0.1:{b.ports['http']}",
                               options=[("grpc.max_receive_message_length", 64 << 20),
                                        ("grpc.max_send_message_length", 64 << 20)])
    yield ch, state, b
    ch.close()
    srv.stop(0)


def call(ch, kind, name):
    f = {"uu": ch.unary_unary, "us": ch.unary_stream, "su": ch.stream_unary,
         "ss": ch.stream_stream}[kind]
    return f(SVC + name, request_serializer=ident, response_deserializer=ident)


def test_unary(grpc_env):
    ch, _, _ = grpc_env
    assert call(ch, "uu", "Unary")(b"hi", timeout=10) == b"echo:hi"


def test_server_stream(grpc_env):
    ch, _, _ = grpc_env
    got = list(call(ch, "us", "ServerStream")(b"x", timeout=10))
    assert got == [b"x-0", b"x-1", b"x-2", b"x-3", b"x-4"]


def test_client_stream(grpc_env):
    ch, _, _ = grpc_env
    assert call(ch, "su", "ClientStream")(iter([b"a", b"b", b"c"]), timeout=10) == b"a|b|c"


def test_bidi(grpc_env):
    ch, _, _ = grpc_env
    msgs = [b"m%d" % i for i in range(20)]
    assert list(call(ch, "ss", "Bidi")(iter(msgs), timeout=10)) == msgs


def test_trailers_forwarded(grpc_env):
    ch, _, _ = grpc_env
    with pytest.raises(grpc.RpcError) as ei:
        call(ch, "uu", "Unary")(b"fail", timeout=10)
    e = ei.value
    assert e.code() == grpc.StatusCode.INVALID_ARGUMENT  # grpc-status 3 crossed the proxy
    assert e.details() == "bad thing"  # and grpc-message
    assert ("x-trail", "yes") in tuple(e.trailing_metadata())


def test_upstream_down_grpc(bastion):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()  # nothing listens there
    b = bastion(conf(dead, "retry attempts=0;"))
    with grpc.insecure_channel(f"127.0.0.1:{b.ports['http']}") as ch:
        with pytest.raises(grpc.RpcError) as ei:
            call(ch, "uu", "Unary")(b"hi", timeout=10)
    assert ei.value.code() == grpc.StatusCode.UNAVAILABLE
    assert ei.value.details() == "upstream unavailable"  # bastion's grpc-status 14, not a 502


def test_deadline_cancel(grpc_env):
    ch, state, _ = grpc_env
    with pytest.raises(grpc.RpcError) as ei:
        call(ch, "uu", "Slow")(b"x", timeout=0.5)
    assert ei.value.code() == grpc.StatusCode.DEADLINE_EXCEEDED
    # the client's RST_STREAM became an upstream RST_STREAM: the server saw the RPC end
    assert wait_until(lambda: state.get("cancelled"), 5)


def test_flow_control_bidirectional(grpc_env):
    ch, _, _ = grpc_env
    big = [bytes([i]) * (1 << 20) for i in range(8)]  # 8 MiB each way, beyond every window
    got = list(call(ch, "ss", "Bidi")(iter(big), timeout=60))
    assert got == big


# ---- a raw HTTP/2 upstream ----

class H2Upstream:
    def __init__(self, max_streams=None, delay=0.0, goaway_first=False):
        self.max_streams, self.delay, self.goaway_first = max_streams, delay, goaway_first
        self.lock = threading.Lock()
        self.conns = 0
        self.max_conc = 0
        self.errors = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.sock.close()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.conns += 1
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        conn = h2conn.H2Connection(config=cfg)
        if self.max_streams is not None:
            conn.local_settings = h2.settings.Settings(
                client=False,
                initial_values={h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: self.max_streams})
        wl = threading.Lock()
        active = set()
        st = {"goaway": False}
        with wl:
            conn.initiate_connection()
            c.sendall(conn.data_to_send())

        def respond(sid):
            with wl:
                try:
                    conn.send_headers(sid, [(":status", "200"), ("content-type", "text/plain")])
                    conn.send_data(sid, b"ok", end_stream=True)
                    c.sendall(conn.data_to_send())
                except Exception as e:  # the stream was reset meanwhile
                    self.errors.append(repr(e))
                active.discard(sid)
            if st["goaway"]:
                time.sleep(0.3)
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        try:
            while True:
                data = c.recv(65536)
                if not data:
                    break
                with wl:
                    for ev in conn.receive_data(data):
                        if isinstance(ev, h2.events.RequestReceived):
                            active.add(ev.stream_id)
                            with self.lock:
                                self.max_conc = max(self.max_conc, len(active))
                            if self.goaway_first and not st["goaway"]:
                                st["goaway"] = True  # GOAWAY now, then answer the stream it names
                                c.sendall(struct.pack(">I", 8)[1:] + b"\x07\x00" +
                                          struct.pack(">III", 0, ev.stream_id, 0))
                            threading.Timer(self.delay, respond, (ev.stream_id,)).start()
                        elif isinstance(ev, h2.events.DataReceived):
                            conn.acknowledge_received_data(ev.flow_controlled_length,
                                                           ev.stream_id)
                        elif isinstance(ev, h2.events.StreamReset):
                            active.discard(ev.stream_id)
                    c.sendall(conn.data_to_send())
        except Exception as e:
            self.errors.append(repr(e))
        finally:
            c.close()


def parallel_gets(port, n):
    out = [None] * n

    def one(i):
        out[i] = get(port, f"/r{i}")

    ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(20)
    return out


def test_multiplexing(bastion):
    u = H2Upstream(delay=0.5)
    try:
        b = bastion(conf(u.port))
        res = parallel_gets(b.ports["http"], 20)
        assert all(r is not None and r.startswith(b"HTTP/1.1 200") for r in res), res
        assert u.max_conc > 1  # streams were in flight together on one connection
        assert u.conns <= 2, u.conns
        assert not u.errors, u.errors
    finally:
        u.close()


def test_upstream_settings_limit(bastion):
    u = H2Upstream(max_streams=2, delay=0.3)
    try:
        b = bastion(conf(u.port))
        res = parallel_gets(b.ports["http"], 6)
        assert all(r is not None and r.startswith(b"HTTP/1.1 200") for r in res), res
        assert u.max_conc <= 2, u.max_conc  # never more than the peer allowed
        assert not u.errors, u.errors
    finally:
        u.close()


def test_upstream_goaway(bastion):
    u = H2Upstream(delay=0.5, goaway_first=True)
    try:
        b = bastion(conf(u.port))
        first = {}
        t = threading.Thread(target=lambda: first.setdefault("r", get(b.ports["http"], "/a")))
        t.start()
        assert wait_until(lambda: u.conns == 1, 5)
        time.sleep(0.2)  # the GOAWAY is there: the next request needs a new connection
        second = get(b.ports["http"], "/b")
        t.join(10)
        assert first["r"].startswith(b"HTTP/1.1 200"), first  # the in-flight stream drained
        assert second.startswith(b"HTTP/1.1 200"), second
        assert u.conns == 2, u.conns
    finally:
        u.close()
