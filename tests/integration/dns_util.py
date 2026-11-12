"""A tiny authoritative DNS server for tests: answers A queries from a table it can change at
run time, NOERROR with no records for anything else. It can also go silent (a resolver that is
down). Only what the helper's stub resolver asks is implemented."""
import socket
import struct
import threading


class FakeDNS:
    def __init__(self, records=None, ttl=1):
        self.records = dict(records or {})  # name -> [ipv4 text]
        self.ttl = ttl
        self.silent = False
        self.queries = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def close(self):
        self._stop = True
        self.thread.join(2)
        self.sock.close()

    def _run(self):
        while not self._stop:
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 12:
                continue
            qid, _flags, qd = struct.unpack("!HHH", data[:6])
            off, labels = 12, []
            while off < len(data) and data[off] != 0:
                n = data[off]
                labels.append(data[off + 1:off + 1 + n].decode())
                off += 1 + n
            qname = ".".join(labels).lower()
            qtype = struct.unpack("!H", data[off + 1:off + 3])[0]
            question = data[12:off + 5]
            self.queries.append((qname, qtype))
            if self.silent:
                continue
            answers = b""
            count = 0
            if qtype == 1:
                for ip in self.records.get(qname, []):
                    answers += struct.pack("!HHHIH", 0xC00C, 1, 1, self.ttl, 4) + socket.inet_aton(ip)
                    count += 1
            rcode = 0 if qname in self.records else 3
            head = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, count, 0, 0)
            self.sock.sendto(head + question + answers, peer)
