"""Data-lake sink: normalized events as Parquet (Apache Arrow columnar format).

Files land in  data/lake/ues/date=YYYY-MM-DD/part-<n>.parquet  - the Hive-style
layout Spark, Trino, DuckDB and Iceberg import tooling read directly. Typed
columns are what make the output AI/ML-ready (PS requirement h).
"""
import json
import threading
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("time", pa.string()),
    ("received_at", pa.string()),
    ("source", pa.string()),
    ("status", pa.string()),
    ("class_uid", pa.int32()),
    ("src_ip", pa.string()),
    ("src_port", pa.int32()),
    ("dst_ip", pa.string()),
    ("dst_port", pa.int32()),
    ("protocol", pa.string()),
    ("disposition", pa.string()),
    ("severity_id", pa.int32()),
    ("vendor", pa.string()),
    ("product", pa.string()),
    ("event_code", pa.string()),
    ("raw_sha256", pa.string()),
    ("archive_ref", pa.string()),
    ("leaf_index", pa.int64()),
    ("pack", pa.string()),
    ("unmapped", pa.string()),     # JSON
    ("provenance", pa.string()),   # JSON
])


def _get(d: dict | None, path: str):
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return None
        d = d[part]
    return d


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def to_row(event: dict) -> dict:
    u = event.get("ues")
    return {
        "event_id": event["event_id"], "time": _get(u, "time"), "received_at": event["received_at"],
        "source": event["source"]["name"], "status": event["status"],
        "class_uid": _int(_get(u, "class_uid")),
        "src_ip": _get(u, "src_endpoint.ip"), "src_port": _int(_get(u, "src_endpoint.port")),
        "dst_ip": _get(u, "dst_endpoint.ip"), "dst_port": _int(_get(u, "dst_endpoint.port")),
        "protocol": _get(u, "connection_info.protocol_name"), "disposition": _get(u, "disposition"),
        "severity_id": _int(_get(u, "severity_id")),
        "vendor": _get(u, "metadata.product.vendor_name"), "product": _get(u, "metadata.product.name"),
        "event_code": _get(u, "metadata.event_code"),
        "raw_sha256": event["raw"]["sha256"], "archive_ref": event["raw"]["archive_ref"],
        "leaf_index": event["merkle"]["leaf_index"],
        "pack": "%s@%s" % (event["parser"]["pack_id"], event["parser"]["version"]),
        "unmapped": json.dumps(_get(u, "unmapped") or {}),
        "provenance": json.dumps(event["provenance"]),
    }


class LakeWriter:
    def __init__(self, directory: Path, flush_rows: int = 5000, flush_seconds: float = 5.0):
        self.dir = Path(directory) / "ues"
        self.flush_rows, self.flush_seconds = flush_rows, flush_seconds
        self._rows: list[dict] = []
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self._n = 0

    def add(self, event: dict) -> None:
        with self._lock:
            self._rows.append(to_row(event))
            due = len(self._rows) >= self.flush_rows or time.monotonic() - self._last >= self.flush_seconds
        if due:
            self.flush()

    def flush(self) -> Path | None:
        with self._lock:
            rows, self._rows = self._rows, []
            self._last = time.monotonic()
            if not rows:
                return None
            self._n += 1
            date = (rows[0]["received_at"] or "unknown")[:10]
            path = self.dir / ("date=%s" % date) / ("part-%d-%05d.parquet" % (int(time.time()), self._n))
        path.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMA), path, compression="zstd")
        return path
