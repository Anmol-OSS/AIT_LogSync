"""Evidence store: raw archive + Merkle log + signed, timestamped tree heads.

record() is called for every event BEFORE parsing (write-first). The Merkle
leaf binds the event id and receive time to the exact raw bytes, so neither
the bytes nor their metadata can change without breaking the inclusion proof.
"""
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from ..config import Settings
from .archive import Archive
from .db import Database
from .keys import Signer
from .merkle import MerkleLog, leaf_hash, verify_inclusion
from .timestamp import LocalTSA


def leaf_input(event_id: str, received_at: str, raw: bytes) -> bytes:
    return b"logsync-leaf-v1\n" + event_id.encode() + b"\n" + received_at.encode() + b"\n" + raw


@dataclass
class TreeHead:
    tree_size: int
    root: str
    timestamp: str
    signature: str
    rfc3161: bytes | None

    def message(self) -> bytes:
        return sth_message(self.tree_size, self.root, self.timestamp)


def sth_message(tree_size: int, root: str, timestamp: str) -> bytes:
    return json.dumps({"tree_size": tree_size, "root": root, "timestamp": timestamp},
                      sort_keys=True, separators=(",", ":")).encode()


class EvidenceStore:
    def __init__(self, settings: Settings, db: Database):
        settings.ensure_dirs()
        self.settings = settings
        self.db = db
        self.archive = Archive(settings.data_dir / "archive", db, settings.segment_max_bytes)
        self.log = MerkleLog(settings.data_dir / "merkle" / "leaves.bin")
        self.signer = Signer(settings.data_dir / "keys" / "log_ed25519.pem")
        self.tsa = LocalTSA(settings.data_dir / "tsa", enabled=settings.tsa == "openssl")
        self._last_seal = time.monotonic()

    # ---------------------------------------------------------------- write path
    def record(self, event_id: str, received_at: str, raw: bytes) -> tuple[str, str, int]:
        """Archive raw bytes and append the event's leaf. Returns (sha256, ref, leaf_index)."""
        return self.record_many([(event_id, received_at, raw)])[0]

    def record_many(self, items: list[tuple[str, str, bytes]]) -> list[tuple[str, str, int]]:
        """Batch version: archive every raw line, then append all leaves with one fsync."""
        stored = self.archive.put_many([raw for _, _, raw in items])
        indexes = self.log.append_many([leaf_hash(leaf_input(e, t, raw)) for e, t, raw in items])
        return [(sha, ref, idx) for (sha, ref), idx in zip(stored, indexes)]

    def maybe_seal(self, force: bool = False) -> TreeHead | None:
        """Sign a new tree head if enough leaves or time have accumulated."""
        latest = self.latest_head()
        last_size = latest.tree_size if latest else 0
        size = self.log.size
        if size == last_size:
            return None
        due = (size - last_size >= self.settings.sth_every_leaves
               or time.monotonic() - self._last_seal >= self.settings.sth_every_seconds)
        if not (force or due):
            return None
        return self.seal()

    def seal(self) -> TreeHead:
        size = self.log.size
        root = self.log.root(size).hex()
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        msg = sth_message(size, root, ts)
        head = TreeHead(size, root, ts, self.signer.sign(msg), self.tsa.stamp(msg))
        self.db.connect().execute(
            "INSERT OR REPLACE INTO tree_heads (tree_size, root, timestamp, signature, rfc3161) VALUES (?,?,?,?,?)",
            (head.tree_size, head.root, head.timestamp, head.signature, head.rfc3161))
        self._last_seal = time.monotonic()
        return head

    # ---------------------------------------------------------------- read path
    def latest_head(self) -> TreeHead | None:
        row = self.db.connect().execute(
            "SELECT * FROM tree_heads ORDER BY tree_size DESC LIMIT 1").fetchone()
        return TreeHead(row["tree_size"], row["root"], row["timestamp"], row["signature"],
                        row["rfc3161"]) if row else None

    def proof(self, leaf_index: int) -> tuple[TreeHead, list[bytes]] | None:
        """Inclusion proof of a leaf against the latest signed head; None until sealed."""
        self.log.refresh()
        head = self.latest_head()
        if head is None or leaf_index >= head.tree_size:
            return None
        return head, self.log.inclusion_proof(leaf_index, head.tree_size)

    def check_inclusion(self, event_id: str, received_at: str, raw: bytes, leaf_index: int) -> tuple[bool, str]:
        """Recompute the leaf from archived bytes and verify it reaches a validly signed root."""
        p = self.proof(leaf_index)
        if p is None:
            return False, "leaf %d not yet covered by a signed tree head" % leaf_index
        head, path = p
        if not self.signer.verify(head.message(), head.signature):
            return False, "tree head signature invalid"
        if self.log.root(head.tree_size).hex() != head.root:
            return False, "log contents do not match signed root"
        lh = leaf_hash(leaf_input(event_id, received_at, raw))
        if not verify_inclusion(lh, leaf_index, head.tree_size, path, bytes.fromhex(head.root)):
            return False, "recomputed leaf hash does not reach signed root"
        stamp = ""
        if head.rfc3161:
            stamp = ", RFC 3161 timestamp valid" if self.tsa.verify(head.message(), head.rfc3161) \
                else ", RFC 3161 timestamp INVALID"
        return True, "leaf %d proven in signed tree of %d (%d-hash path)%s" % (
            leaf_index, head.tree_size, len(path), stamp)
