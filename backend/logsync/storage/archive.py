"""Immutable raw archive: every original byte, stored before parsing.

Content-addressed: an object is identified by the SHA-256 of its bytes and
stored once, however many events reference it. Objects are appended to a
segment file; a full segment is sealed with gzip-6 (the codec slide 4 measured
fitting the burst budget) and its uncompressed file removed.

    ref = "seg-000001:<offset>:<length>"
"""
import gzip
import hashlib
from collections import OrderedDict
from pathlib import Path

from .db import Database


class Archive:
    def __init__(self, directory: Path, db: Database, segment_max_bytes: int = 4 * 1024 * 1024):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = db
        self.segment_max = segment_max_bytes
        self._cache: OrderedDict[str, bytes] = OrderedDict()  # sealed segments, decompressed
        existing = sorted(self.dir.glob("seg-*.log"))
        self._active = existing[-1].stem if existing else self._next_segment_name()

    def _next_segment_name(self) -> str:
        nums = [int(p.name[4:10]) for p in self.dir.glob("seg-*")]
        return "seg-%06d" % (max(nums, default=0) + 1)

    def _path(self, seg: str, sealed: bool) -> Path:
        return self.dir / (seg + (".log.gz" if sealed else ".log"))

    # ---------------------------------------------------------------- write
    def put(self, data: bytes) -> tuple[str, str]:
        """Store bytes; returns (sha256 hex, ref). Identical bytes are stored once."""
        sha = hashlib.sha256(data).hexdigest()
        conn = self.db.connect()
        row = conn.execute("SELECT ref FROM objects WHERE sha256 = ?", (sha,)).fetchone()
        if row:
            return sha, row["ref"]
        path = self._path(self._active, sealed=False)
        with open(path, "ab") as f:
            offset = f.tell()
            f.write(data)
        ref = "%s:%d:%d" % (self._active, offset, len(data))
        conn.execute("INSERT INTO objects (sha256, ref, length) VALUES (?, ?, ?)", (sha, ref, len(data)))
        if offset + len(data) >= self.segment_max:
            self.seal_active()
        return sha, ref

    def seal_active(self) -> None:
        path = self._path(self._active, sealed=False)
        if path.exists() and path.stat().st_size:
            self._path(self._active, sealed=True).write_bytes(gzip.compress(path.read_bytes(), 6))
            path.unlink()
        self._active = self._next_segment_name()

    # ---------------------------------------------------------------- read
    def _segment_bytes(self, seg: str) -> bytes:
        plain = self._path(seg, sealed=False)
        if plain.exists():
            return plain.read_bytes()
        if seg in self._cache:
            self._cache.move_to_end(seg)
            return self._cache[seg]
        data = gzip.decompress(self._path(seg, sealed=True).read_bytes())
        self._cache[seg] = data
        if len(self._cache) > 8:
            self._cache.popitem(last=False)
        return data

    def get(self, ref: str) -> bytes:
        seg, offset, length = ref.split(":")
        offset, length = int(offset), int(length)
        return self._segment_bytes(seg)[offset:offset + length]

    def ref_for(self, sha256: str) -> str | None:
        row = self.db.connect().execute("SELECT ref FROM objects WHERE sha256 = ?", (sha256,)).fetchone()
        return row["ref"] if row else None

    # ---------------------------------------------------------------- demo only
    def overwrite_byte(self, ref: str, index: int, value: int) -> int:
        """Change one archived byte in place and return the old value.
        Exists only for the tamper demo - it is what an attacker would do."""
        seg, offset, _ = ref.split(":")
        pos = int(offset) + index
        plain = self._path(seg, sealed=False)
        if plain.exists():
            with open(plain, "r+b") as f:
                f.seek(pos)
                old = f.read(1)[0]
                f.seek(pos)
                f.write(bytes([value]))
            return old
        data = bytearray(gzip.decompress(self._path(seg, sealed=True).read_bytes()))
        old = data[pos]
        data[pos] = value
        self._path(seg, sealed=True).write_bytes(gzip.compress(bytes(data), 6))
        self._cache.pop(seg, None)
        return old
