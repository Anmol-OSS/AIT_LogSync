"""The real API service: reads the evidence store and event index the pipeline writes.

Runs in the same process as the worker (`logsync serve`) or as its own service
next to Kafka workers (`logsync api`), sharing the data directory.
"""
import json
import threading
import time

from ..config import Settings
from ..core.engine import make_engine
from ..core.processor import pack_signer
from ..core.registry import Registry
from ..core.verify import verify_event
from ..storage.db import Database
from ..storage.evidence import EvidenceStore
from . import models as m
from .service import NotFound


class LiveService:
    def __init__(self, settings: Settings, publish=None, synth=None, engine=None):
        settings.ensure_dirs()
        self.settings = settings
        self.db = Database(settings.db_path)
        self.evidence = EvidenceStore(settings, self.db)
        self.registry = Registry(settings.data_dir / "packs", pack_signer(settings))
        self.registry.reload()
        self.engine = engine or make_engine(settings.parser_engine)
        self.publish = publish          # callable(RawEvent) - HTTP ingest goes through the same bus
        self.synth = synth              # parser synthesis loop (M5d)
        self._stamper = None
        self._stamp_cache: dict[int, str] = {}   # tree size -> RFC 3161 time (avoid re-parsing tokens)
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- helpers
    def _doc(self, event_id: str) -> dict:
        row = self.db.connect().execute("SELECT doc FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if not row:
            raise NotFound(event_id)
        return json.loads(row["doc"])

    def _with_merkle(self, doc: dict, prove: bool) -> dict:
        idx = doc["merkle"]["leaf_index"]
        head = self.evidence.latest_head()
        merkle = {"leaf_index": idx, "tree_size": head.tree_size if head else 0,
                  "root": head.root if head else "", "inclusion_proof": [], "status": "pending"}
        if head and idx < head.tree_size:
            merkle["status"] = "sealed"
            if prove:
                p = self.evidence.proof(idx)
                if p:
                    merkle["inclusion_proof"] = [h.hex() for h in p[1]]
        doc["merkle"] = merkle
        return doc

    # ---------------------------------------------------------------- dashboard
    def dashboard(self) -> m.DashboardSummary:
        c = self.db.connect()
        counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM events GROUP BY status")}
        total = sum(counts.values())
        accepted, blocked, unparsed = counts.get("accepted", 0), counts.get("blocked", 0), counts.get("unparsed", 0)
        identified = accepted + blocked
        now = time.time()
        recent = c.execute("SELECT COUNT(*) n FROM events WHERE created >= ?", (now - 10,)).fetchone()["n"]
        # blocked by the round-trip gate specifically (vs. a failed transform)
        rt_blocked = 0
        for r in c.execute("SELECT doc FROM events WHERE status = 'blocked' ORDER BY seq DESC LIMIT 2000"):
            reason = json.loads(r["doc"])["roundtrip"].get("reason") or ""
            rt_blocked += "transform" not in reason
        packs = {p.source_name: p for p in self.registry.active()}
        sources = []
        for r in c.execute("SELECT source_name, COUNT(*) n, SUM(status='accepted') ok, "
                           "MAX(pack) pack, MAX(seq) last FROM events GROUP BY source_name ORDER BY n DESC"):
            p = packs.get(r["source_name"])
            if r["source_name"] == "unknown":
                fam, fmt, pack = "Unknown", "?", None
            else:
                last = json.loads(c.execute("SELECT doc FROM events WHERE seq = ?", (r["last"],)).fetchone()["doc"])
                fam, fmt, pack = last["source"]["family"], last["source"]["format"], p.ref if p else r["pack"]
            sources.append(m.SourceStats(name=r["source_name"], family=fam, format=fmt, pack=pack,
                                         events=r["n"], parse_rate=(r["ok"] or 0) / r["n"]))
        drift = []
        for r in c.execute("SELECT source_host, COUNT(*) n FROM events WHERE status='unparsed' "
                           "GROUP BY source_host ORDER BY n DESC LIMIT 5"):
            drift.append(m.DriftSignal(source="unknown", signal="unrecognised format",
                                       detail="%d lines from %s match no pack fingerprint - candidate for a new pack"
                                              % (r["n"], r["source_host"])))
        for r in c.execute("SELECT pack, COUNT(*) n FROM events WHERE status='blocked' AND pack IS NOT NULL "
                           "GROUP BY pack ORDER BY n DESC LIMIT 5"):
            drift.append(m.DriftSignal(source=r["pack"], signal="blocked by gate",
                                       detail="%d events from %s had bytes or values the pack could not explain "
                                              "- possible firmware format change" % (r["n"], r["pack"])))
        # events per second, by status, for the last 60 seconds
        start = int(now) - 59
        buckets = {t: {"accepted": 0, "blocked": 0, "unparsed": 0} for t in range(start, int(now) + 1)}
        for r in c.execute("SELECT CAST(created AS INTEGER) t, status, COUNT(*) n FROM events "
                           "WHERE created >= ? GROUP BY t, status", (start,)):
            if r["t"] in buckets and r["status"] in buckets[r["t"]]:
                buckets[r["t"]][r["status"]] = r["n"]
        timeline = [m.TimelinePoint(t=t, **v) for t, v in buckets.items()]

        head = self.evidence.latest_head()
        tree_head = None
        if head:
            if head.tree_size not in self._stamp_cache and head.rfc3161:
                self._stamp_cache = {head.tree_size: self.evidence.tsa.describe(head.rfc3161)}
            tree_head = m.TreeHeadInfo(tree_size=head.tree_size, root=head.root, signed_at=head.timestamp,
                                       signature=head.signature[:32] + "…",
                                       rfc3161_time=self._stamp_cache.get(head.tree_size))
        return m.DashboardSummary(
            timeline=timeline, tree_head=tree_head,
            window="since start · events/sec over the last 10 s",
            totals=m.Totals(received=total, archived=total, normalized=accepted, blocked=blocked,
                            dead_letter=unparsed, eps=recent / 10.0,
                            parse_success_rate=accepted / identified if identified else 1.0,
                            roundtrip_pass_rate=1 - rt_blocked / identified if identified else 1.0),
            sources=sources, drift=drift)

    # ---------------------------------------------------------------- events
    def list_events(self, limit=50, source=None, status=None):
        sql, args = "SELECT doc FROM events", []
        where = []
        if source:
            where.append("source_name = ?")
            args.append(source)
        if status:
            where.append("status = ?")
            args.append(status)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        return [self._with_merkle(json.loads(r["doc"]), prove=False)
                for r in self.db.connect().execute(sql, args)]

    def get_event(self, event_id):
        return self._with_merkle(self._doc(event_id), prove=True)

    def verify(self, event_id):
        doc = self._doc(event_id)
        self.registry.reload_if_changed()
        with self._lock:
            return verify_event(doc, self.evidence, self.registry, self.engine, self.settings.default_tz)

    # ---------------------------------------------------------------- tamper demo
    def tamper(self, event_id):
        """Flip one archived byte - inside the source IP if the event has one - the
        way an attacker editing evidence at rest would."""
        doc = self._doc(event_id)
        sha = doc["raw"]["sha256"].removeprefix("sha256:")
        ref = self.evidence.archive.ref_for(sha) or doc["raw"]["archive_ref"]
        c = self.db.connect()
        if c.execute("SELECT 1 FROM demo_tamper WHERE sha256 = ?", (sha,)).fetchone():
            self.restore(event_id)
        ip = next((p for p in doc["provenance"] if p["field"] == "src_endpoint.ip"), None)
        pos = ip["bytes"][1] - 1 if ip else len(doc["raw"]["text"].encode()) // 2
        original = doc["raw"]["text"].encode()[pos]
        new = ord("9") if original != ord("9") else ord("8")
        old = self.evidence.archive.overwrite_byte(ref, pos, new)
        c.execute("INSERT OR REPLACE INTO demo_tamper (sha256, byte_index, original) VALUES (?,?,?)", (sha, pos, old))
        tampered = self.evidence.archive.get(ref)
        return m.TamperResult(event_id=event_id, tampered_byte=pos, tampered_raw=tampered.decode("utf-8", "replace"))

    def restore(self, event_id):
        doc = self._doc(event_id)
        sha = doc["raw"]["sha256"].removeprefix("sha256:")
        c = self.db.connect()
        row = c.execute("SELECT byte_index, original FROM demo_tamper WHERE sha256 = ?", (sha,)).fetchone()
        if row:
            ref = self.evidence.archive.ref_for(sha) or doc["raw"]["archive_ref"]
            self.evidence.archive.overwrite_byte(ref, row["byte_index"], row["original"])
            c.execute("DELETE FROM demo_tamper WHERE sha256 = ?", (sha,))

    # ---------------------------------------------------------------- packs
    def list_packs(self):
        self.registry.reload_if_changed()
        return [m.PackInfo(pack_id=p.id, version=p.version, vendor=p.vendor, product=p.product,
                           format=p.format, digest=p.digest, signed=self.registry.is_signed(p))
                for p in self.registry.active()]

    def draft_pack(self, sample):
        if not self.synth:
            raise NotFound("parser synthesis is not enabled")
        return self.synth.draft(sample)

    def approve_pack(self, req):
        if not self.synth:
            raise NotFound("parser synthesis is not enabled")
        return self.synth.approve(req)

    # ---------------------------------------------------------------- ingest
    def ingest(self, req):
        if not self.publish:
            raise NotFound("no ingest bus configured")
        from ..pipeline.ingest import Stamper
        if self._stamper is None:
            self._stamper = Stamper(self.settings.default_tz)
        ids = []
        for line in req.lines:
            raw = line.rstrip("\r\n").encode("utf-8")
            if raw:
                ev = self._stamper.make(raw, req.source_host)
                self.publish(ev)
                ids.append(ev.event_id)
        return m.IngestResult(accepted=len(ids), event_ids=ids)
