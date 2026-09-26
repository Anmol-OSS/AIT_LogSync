"""Process raw events end to end: archive first, then identify, parse, gate, store.

This is the work a pipeline worker does per batch of messages; the transport
(Kafka or an in-process queue) lives in logsync.pipeline.
"""
import json
import threading
import time
from collections import defaultdict
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


def pack_signer(settings: Settings) -> Signer:
    return Signer(settings.data_dir / "keys" / "pack_ed25519.pem")


class Processor:
    def __init__(self, settings: Settings, engine: Engine | None = None, forwarder=None, on_event=None):
        self.settings = settings
        settings.ensure_dirs()
        self.db = Database(settings.db_path)
        self.evidence = EvidenceStore(settings, self.db)
        self.registry = Registry(settings.data_dir / "packs", pack_signer(settings))
        self.registry.bootstrap(settings.packs_dir)
        self.engine = engine or make_engine(settings.parser_engine)
        self.lake = LakeWriter(settings.data_dir / "lake")
        self.forwarder = forwarder
        self.on_event = on_event          # callback(event) - e.g. publish dead letters to Kafka
        self._lock = threading.Lock()     # one writer: archive, Merkle log and index stay in step

    def process(self, ev: RawEvent) -> dict | None:
        """Process one event; None if its id was already processed."""
        out = self.process_batch([ev])
        return out[0] if out else None

    def process_batch(self, batch: list[RawEvent]) -> list[dict]:
        """Returns the stored events. Events whose id was already processed are
        skipped (Kafka delivers at least once, so redelivery must be harmless)."""
        with self._lock:
            conn = self.db.connect()
            conn.execute("BEGIN IMMEDIATE")
            try:
                fresh, ids = [], set()
                for ev in batch:
                    if ev.event_id in ids or conn.execute(
                            "SELECT 1 FROM events WHERE event_id = ?", (ev.event_id,)).fetchone():
                        continue
                    ids.add(ev.event_id)
                    fresh.append(ev)
                # 1. write first: raw bytes archived and sealed into the log before any parsing
                recorded = self.evidence.record_many([(e.event_id, e.received_at, e.raw) for e in fresh])
                # 2. identify, then tokenize per pack in one sandbox call
                packs = [self.registry.identify(e.raw) for e in fresh]
                groups: dict[str, list[int]] = defaultdict(list)
                for i, p in enumerate(packs):
                    if p is not None:
                        groups[p.ref].append(i)
                toks: list = [None] * len(fresh)
                for idxs in groups.values():
                    spec = packs[idxs[0]].spec
                    for i, tok in zip(idxs, self.engine.tokenize_many(spec, [fresh[i].raw for i in idxs])):
                        toks[i] = tok
                # 3. normalize + round-trip gate, 4. index
                events = []
                for ev, (sha, ref, leaf), pack, tok in zip(fresh, recorded, packs, toks):
                    events.append(build_event(
                        event_id=ev.event_id, received_at=ev.received_at, source_host=ev.source_host,
                        raw=ev.raw, sha256=sha, archive_ref=ref, leaf_index=leaf, pack=pack, tok=tok,
                        default_tz=self.settings.default_tz))
                self._store(conn, events)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            self.evidence.maybe_seal()
        for event in events:
            if event["status"] == "accepted":
                self.lake.add(event)
                if self.forwarder:
                    self.forwarder.send(event)
            if self.on_event:
                self.on_event(event)
        return events

    def _store(self, conn, events: list[dict]) -> None:
        now = time.time()
        conn.executemany(
            "INSERT INTO events (event_id, received_at, created, source_name, source_host, status, pack, "
            "sha256, leaf_index, doc) VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(e["event_id"], e["received_at"], now, e["source"]["name"], e["source"]["host"], e["status"],
              None if e["parser"]["pack_id"] == "none" else "%s@%s" % (e["parser"]["pack_id"], e["parser"]["version"]),
              e["raw"]["sha256"], e["merkle"]["leaf_index"], json.dumps(e, separators=(",", ":")))
             for e in events])

    def reprocess(self, event_ids: list[str]) -> int:
        """Re-parse already-archived events (e.g. dead-lettered lines after a new pack
        is approved). Raw bytes and Merkle leaves are untouched - only the normalized
        record is rebuilt, from the archived bytes."""
        done = 0
        with self._lock:
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
                             (event["status"], event["source"]["name"], pack.ref,
                              json.dumps(event, separators=(",", ":")), eid))
                if event["status"] == "accepted":
                    self.lake.add(event)
                done += 1
        return done

    def tick(self) -> None:
        """Periodic housekeeping: hot-reload packs, seal a tree head if due, flush the lake."""
        self.registry.reload_if_changed()
        with self._lock:
            self.evidence.maybe_seal()
        self.lake.flush_if_due()

    def flush(self) -> None:
        with self._lock:
            self.evidence.maybe_seal(force=True)
        self.lake.flush()
