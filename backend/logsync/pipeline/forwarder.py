"""SIEM forwarder: push normalized events to a SIEM over syslog (PS requirement g).

    LOGSYNC_FORWARD=udp://siem.local:514     (or tcp://...)
    LOGSYNC_FORWARD_FORMAT=json | cef

json: RFC 5424 message whose body is the UES event plus its evidence pointers
      (raw hash, archive ref, parser digest) - any SIEM with a JSON parser.
cef:  ArcSight CEF with the common fields, for SIEMs that expect CEF.
"""
import json
import socket
import threading
from urllib.parse import urlparse


def _cef_escape(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


def to_json_line(event: dict) -> bytes:
    body = {"event_id": event["event_id"], "ues": event["ues"],
            "evidence": {"raw_sha256": event["raw"]["sha256"], "archive_ref": event["raw"]["archive_ref"],
                         "parser": "%s@%s" % (event["parser"]["pack_id"], event["parser"]["version"]),
                         "parser_digest": event["parser"]["digest"],
                         "leaf_index": event["merkle"]["leaf_index"]}}
    return ("<134>1 %s logsync ulpf - ues - %s" % (event["received_at"], json.dumps(body, separators=(",", ":")))).encode()


def to_cef_line(event: dict) -> bytes:
    u = event["ues"] or {}
    src, dst = u.get("src_endpoint", {}), u.get("dst_endpoint", {})
    ext = {"rt": u.get("time"), "src": src.get("ip"), "spt": src.get("port"), "dst": dst.get("ip"),
           "dpt": dst.get("port"), "proto": u.get("connection_info", {}).get("protocol_name"),
           "act": u.get("disposition"), "deviceExternalId": event["source"]["host"],
           "cs1Label": "raw_sha256", "cs1": event["raw"]["sha256"],
           "cs2Label": "archive_ref", "cs2": event["raw"]["archive_ref"]}
    extension = " ".join("%s=%s" % (k, _cef_escape(v)) for k, v in ext.items() if v is not None)
    product = u.get("metadata", {}).get("product", {})
    return ("CEF:0|AIT_LogSync|ULPF|0.1|%s|%s|%s|%s" % (
        u.get("class_uid", 0), product.get("name", event["source"]["family"]).replace("|", "\\|"),
        u.get("severity_id", 0), extension)).encode()


class SyslogForwarder:
    def __init__(self, url: str, fmt: str = "json"):
        u = urlparse(url)
        self.proto, self.addr = u.scheme, (u.hostname, u.port or 514)
        self.encode = to_cef_line if fmt == "cef" else to_json_line
        self.sent = self.errors = 0
        self._lock = threading.Lock()
        self._sock = None

    def _socket(self):
        if self._sock is None:
            if self.proto == "tcp":
                self._sock = socket.create_connection(self.addr, timeout=5)
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    def send(self, event: dict) -> None:
        line = self.encode(event)
        with self._lock:
            try:
                s = self._socket()
                if self.proto == "tcp":
                    s.sendall(b"%d %s" % (len(line), line))
                else:
                    s.sendto(line, self.addr)
                self.sent += 1
            except OSError:
                self.errors += 1
                self._sock = None   # reconnect next time; the event stays in the lake and index
