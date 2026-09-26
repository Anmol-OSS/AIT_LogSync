"""What the API needs from the rest of the system.

Routes only talk to a ``Service``. M3 ships ``FixtureService`` (the M2 mock
JSON); later milestones plug in the real pipeline-backed implementation
without touching the routes.
"""
import json
from pathlib import Path
from typing import Protocol

from . import models as m

REPO = Path(__file__).resolve().parents[3]
MOCK_DIR = REPO / "frontend" / "src" / "mock"


class NotFound(Exception):
    pass


class Service(Protocol):
    def dashboard(self) -> m.DashboardSummary: ...
    def list_events(self, limit: int, source: str | None, status: str | None) -> list[m.ProofCarryingEvent]: ...
    def get_event(self, event_id: str) -> m.ProofCarryingEvent: ...
    def verify(self, event_id: str) -> m.VerifyReport: ...
    def tamper(self, event_id: str) -> m.TamperResult: ...
    def restore(self, event_id: str) -> None: ...
    def list_packs(self) -> list[m.PackInfo]: ...
    def draft_pack(self, sample: list[str]) -> m.PackDraft: ...
    def approve_pack(self, req: m.ApproveRequest) -> m.ApproveResult: ...
    def ingest(self, req: m.IngestRequest) -> m.IngestResult: ...


class FixtureService:
    """Serves the frontend mock JSON, validated through the response models."""

    def __init__(self, mock_dir: Path = MOCK_DIR):
        load = lambda name: json.loads((mock_dir / name).read_text(encoding="utf-8"))
        self._events = [m.ProofCarryingEvent.model_validate(e) for e in load("events.json")]
        self._reports = {k: {kind: m.VerifyReport.model_validate(r) for kind, r in v.items()}
                         for k, v in load("verify.json").items()}
        self._dashboard = m.DashboardSummary.model_validate(load("dashboard.json"))
        self._draft = m.PackDraft.model_validate(load("pack_draft.json"))
        self._tampered: set[str] = set()

    def dashboard(self):
        return self._dashboard

    def list_events(self, limit=100, source=None, status=None):
        out = [e for e in self._events
               if (source is None or e.source.name == source) and (status is None or e.status == status)]
        return out[:limit]

    def get_event(self, event_id):
        for e in self._events:
            if e.event_id == event_id:
                return e
        raise NotFound(event_id)

    def verify(self, event_id):
        self.get_event(event_id)
        if event_id not in self._reports:
            raise NotFound(event_id)
        return self._reports[event_id]["tampered" if event_id in self._tampered else "clean"]

    def tamper(self, event_id):
        report = self._reports.get(event_id)
        if not report:
            raise NotFound(event_id)
        self._tampered.add(event_id)
        t = report["tampered"]
        return m.TamperResult(event_id=event_id, tampered_byte=t.tampered_byte, tampered_raw=t.tampered_raw)

    def restore(self, event_id):
        self._tampered.discard(event_id)

    def list_packs(self):
        return [m.PackInfo(pack_id=e.parser.pack_id, version=e.parser.version, vendor=e.source.family,
                           product=e.source.family, format=e.source.format, digest=e.parser.digest, signed=True)
                for e in self._events if e.status == "accepted"]

    def draft_pack(self, sample):
        return self._draft

    def approve_pack(self, req):
        mapped = sum(1 for f in req.fields if f.mapped_to != "(ignore)")
        return m.ApproveResult(pack_id="juniper-srx-rt-flow", version="0.1.0", draft_id=req.draft_id,
                               mapped_fields=mapped, signature="ed25519:FIXTURE",
                               status="signed → hot-loaded → source live")

    def ingest(self, req):
        return m.IngestResult(accepted=0, event_ids=[])
