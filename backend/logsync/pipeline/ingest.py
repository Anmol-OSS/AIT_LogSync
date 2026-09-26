"""Syslog ingest: UDP, TCP and TCP+TLS (RFC 5425) listeners.

TCP framing follows RFC 6587: octet counting ("123 <34>...") when a frame
starts with a digit, otherwise newline-delimited. Each message gets an event
id and receive time here and is published unchanged - raw bytes are never
decoded or re-encoded before they are archived.

Backpressure: TCP readers block when the bus is full, so senders slow down
(the lossless path). UDP cannot push back; overflow is counted, not hidden.
"""
import logging
import os
import socket
import socketserver
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone

from ..core.processor import RawEvent

log = logging.getLogger("logsync.ingest")
MAX_MESSAGE = 64 * 1024


def _tz(offset: str) -> timezone:
    sign = -1 if offset.startswith("-") else 1
    hh, mm = offset.lstrip("+-").split(":")
    return timezone(sign * timedelta(hours=int(hh), minutes=int(mm)))


class Stamper:
    """Event ids are unique across restarts and ingest replicas (uuid4)."""

    def __init__(self, tz: str = "+05:30"):
        self.tz = _tz(tz)

    def make(self, raw: bytes, host: str) -> RawEvent:
        return RawEvent("ev-" + uuid.uuid4().hex[:20],
                        datetime.now(self.tz).isoformat(timespec="milliseconds"), host, raw)


def split_frames(buf: bytearray) -> list[bytes]:
    """Consume complete RFC 6587 frames from buf (in place); return them."""
    out = []
    while buf:
        if buf[:1].isdigit():
            sp = buf.find(b" ")
            if 0 < sp <= 6 and buf[:sp].isdigit():
                n = int(buf[:sp])
                if len(buf) < sp + 1 + n:
                    break
                out.append(bytes(buf[sp + 1:sp + 1 + n]))
                del buf[:sp + 1 + n]
                continue
        nl = buf.find(b"\n")
        if nl < 0:
            if len(buf) > MAX_MESSAGE:  # no delimiter in sight: cut, never buffer forever
                out.append(bytes(buf[:MAX_MESSAGE]))
                del buf[:MAX_MESSAGE]
                continue
            break
        out.append(bytes(buf[:nl].rstrip(b"\r")))
        del buf[:nl + 1]
    return [m for m in out if m]


class SyslogServer:
    def __init__(self, bus, host: str = "0.0.0.0", port: int = 5514, tls_port: int | None = None,
                 tz: str = "+05:30", certfile: str | None = None, keyfile: str | None = None):
        self.bus, self.host, self.port = bus, host, port
        self.stamper = Stamper(tz)
        self.received = 0
        self._servers: list[socketserver.BaseServer] = []
        self._tls = None
        certfile = certfile or os.environ.get("LOGSYNC_TLS_CERT")
        keyfile = keyfile or os.environ.get("LOGSYNC_TLS_KEY")
        if certfile and keyfile:
            self._tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._tls.load_cert_chain(certfile, keyfile)
            self.tls_port = tls_port or 6514
        else:
            self.tls_port = None

    def _emit(self, raw: bytes, peer: str, block: bool) -> None:
        self.received += 1
        self.bus.publish(self.stamper.make(raw, peer), block=block)

    def start(self) -> "SyslogServer":
        outer = self

        class UDPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request[0].rstrip(b"\r\n")
                if data:
                    outer._emit(data, self.client_address[0], block=False)

        class TCPHandler(socketserver.StreamRequestHandler):
            def handle(self):
                buf = bytearray()
                while True:
                    try:
                        chunk = self.request.recv(65536)
                    except (ConnectionError, OSError, ssl.SSLError):
                        break
                    if not chunk:
                        break
                    buf += chunk
                    for msg in split_frames(buf):
                        outer._emit(msg, self.client_address[0], block=True)
                if buf.strip():
                    outer._emit(bytes(buf).rstrip(b"\r\n"), self.client_address[0], block=True)

        class TLSServer(socketserver.ThreadingTCPServer):
            def get_request(self):
                sock, addr = super().get_request()
                return outer._tls.wrap_socket(sock, server_side=True), addr

        for cls in (socketserver.ThreadingUDPServer, socketserver.ThreadingTCPServer):
            cls.allow_reuse_address = True
            cls.daemon_threads = True
        self._servers = [socketserver.ThreadingUDPServer((self.host, self.port), UDPHandler),
                         socketserver.ThreadingTCPServer((self.host, self.port), TCPHandler)]
        if self._tls:
            TLSServer.allow_reuse_address = True
            TLSServer.daemon_threads = True
            self._servers.append(TLSServer((self.host, self.tls_port), TCPHandler))
        for s in self._servers:
            threading.Thread(target=s.serve_forever, daemon=True, name="ingest-%s" % type(s).__name__).start()
        log.info("syslog ingest on udp/tcp %s:%d%s", self.host, self.port,
                 " and tls :%d" % self.tls_port if self.tls_port else "")
        return self

    def stop(self) -> None:
        for s in self._servers:
            s.shutdown()
            s.server_close()


def send_lines(lines: list[bytes], host: str, port: int, proto: str = "tcp") -> None:
    """Small client used by the replayer and tests."""
    if proto == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for ln in lines:
                s.sendto(ln, (host, port))
    else:
        with socket.create_connection((host, port)) as s:
            s.sendall(b"".join(b"%d %s" % (len(ln), ln) for ln in lines))
