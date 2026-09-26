"""Process one raw event end to end: archive first, then identify, parse, gate, store.

This is the work a pipeline worker does per message; ingest transport (Kafka
or in-process queue) is handled in logsync.pipeline.
"""
import json
import threading
import time
from dataclasses import dataclass

from ..config import Settings
from ..storage.db import Database
from ..storage.evidence import EvidenceStore
from ..storage.keys import Signer
from ..storage.lake import LakeWriter
from .engine import Engine, make_engine
from .event import build_event
from .registry import Registry


@dataclass
class RawEvent:
    event_id: str
    received_at: str
    source_host: str
    raw: bytes


class Processor:
    def __init__(self, settings: Settings, engine: Engine | None = None, forwarder=None):
        self.settings = settings
        self.db = Database(settings.db_path)
        self.evidence = EvidenceStore(settings, self.db)
        self.registry = Registry(settings.data_dir / "packs",
                                 Signer(settings.data_dir / "keys" / "pack_ed25519.pem"))
        self.registry.bootstrap(settings.packs_dir)
        self.engine = engine or make_engine(settings.parser_engine)
        self.lake = LakeWriter(settings.data_dir / "lake")
        self.forwarder = forwarder
        self._lock = threading.Lock()  # one writer: archive, Merkle log and index stay in step

    def seen(self, event_id: str) -> bool:
        return self.db.connect().execute("SELECT 1 FROM events WHERE event_id = ?", (event_id,)).fetchone() is not None

    def process(self, ev: RawEvent) -> dict | None:
        """Returns the stored event, or None if this event id was already processed
        (at-least-once delivery from Kafka can redeliver)."""
        with self._lock:
            if self.seen(ev.event_id):
                return None
            sha, ref, leaf = self.evidence.record(ev.event_id, ev.received_at, ev.raw)   # write first
            pack = self.registry.identify(ev.raw)
            tok = self.engine.tokenize(pack.spec, ev.raw) if pack else None
            event = build_event(event_id=ev.event_id, received_at=ev.received_at, source_host=ev.source_host,
                                raw=ev.raw, sha256=sha, archive_ref=ref, leaf_index=leaf, pack=pack, tok=tok,
                                default_tz=self.settings.default_tz)
            self._store(event)
            self.evidence.maybe_seal()
        if event["status"] == "accepted":
            self.lake.add(event)
            if self.forwarder:
                self.forwarder.send(event)
        return event

    def _store(self, event: dict) -> None:
        pack = None if event["parser"]["pack_id"] == "none" else \
            "%s@%s" % (event["parser"]["pack_id"], event["parser"]["version"])
        self.db.connect().execute(
            "INSERT INTO events (event_id, received_at, created, source_name, source_host, status, pack, "
            "sha256, leaf_index, doc) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (event["event_id"], event["received_at"], time.time(), event["source"]["name"],
             event["source"]["host"], event["status"], pack, event["raw"]["sha256"],
             event["merkle"]["leaf_index"], json.dumps(event, separators=(",", ":"))))

    def reprocess(self, event_ids: list[str]) -> int:
        """Re-parse already-archived events (e.g. dead-lettered lines after a new pack
        is approved). Raw bytes and Merkle leaves are untouched - only the normalized
        record is rebuilt, from the archived bytes."""
        done = 0
        conn = self.db.connect()
        for eid in event_ids:
            row = conn.execute("SELECT doc FROM events WHERE event_id = ?", (eid,)).fetchone()
            if not row:
                continue
            old = json.loads(row["doc"])
            raw = self.evidence.archive.get(old["raw"]["archive_ref"])
            pack = self.registry.identify(raw)
            if pack is None:
                continue
            event = build_event(event_id=eid, received_at=old["received_at"], source_host=old["source"]["host"],
                                raw=raw, sha256=old["raw"]["sha256"].removeprefix("sha256:"),
                                archive_ref=old["raw"]["archive_ref"], leaf_index=old["merkle"]["leaf_index"],
                                pack=pack, tok=self.engine.tokenize(pack.spec, raw),
                                default_tz=self.settings.default_tz)
            conn.execute("UPDATE events SET status=?, source_name=?, pack=?, doc=? WHERE event_id=?",
                         (event["status"], event["source"]["name"], "%s@%s" % (pack.id, pack.version),
                          json.dumps(event, separators=(",", ":")), eid))
            if event["status"] == "accepted":
                self.lake.add(event)
            done += 1
        return done

    def flush(self) -> None:
        self.evidence.maybe_seal(force=True)
        self.lake.flush()
