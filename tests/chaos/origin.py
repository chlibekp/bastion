"""A disposable HTTP/1.1 origin for the chaos tests, run as its own process so a test can SIGKILL
it mid-response and start it again on the same port: `python3 origin.py PORT`.

GET <path> answers 200 with body(path), the same function the tests use to check bytes, and
`Cache-Control: public, max-age=60`. It prints "ready" once listening."""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def body(path):
    unit = f"origin {path};".encode()
    return (unit * (65536 // len(unit) + 1))[:65536]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        b = body(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "public, max-age=60")
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
    print("ready", flush=True)
    srv.serve_forever()
