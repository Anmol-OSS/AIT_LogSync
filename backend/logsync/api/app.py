"""FastAPI application: REST API for the UI, SIEM integrations and auditors.

Started by `logsync serve` or `logsync api` (interactive docs at /docs).
"""
import os
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__
from . import models as m
from .service import NotFound, Service


def create_app(service: Service, static_dir: Path | None = None) -> FastAPI:
    svc = service
    app = FastAPI(title="LogSync ULPF", version=__version__,
                  description="Universal Log Pre-processing Framework - proof-carrying telemetry API")
    api = APIRouter(prefix="/api")
    demo_enabled = os.environ.get("LOGSYNC_DEMO", "1") == "1"

    def found(fn, *args):
        try:
            return fn(*args)
        except NotFound as e:
            raise HTTPException(404, f"not found: {e}")
        except ValueError as e:          # e.g. a pack rejected by the validation gate
            raise HTTPException(422, str(e))

    @api.get("/health")
    def health():
        return {"status": "ok", "version": __version__, "service": type(svc).__name__}

    @api.get("/dashboard", response_model=m.DashboardSummary)
    def dashboard():
        return svc.dashboard()

    @api.get("/events", response_model=list[m.ProofCarryingEvent])
    def list_events(limit: int = 50, source: str | None = None, status: str | None = None):
        return svc.list_events(min(max(limit, 1), 500), source, status)

    @api.get("/events/{event_id}", response_model=m.ProofCarryingEvent)
    def get_event(event_id: str):
        return found(svc.get_event, event_id)

    @api.post("/events/{event_id}/verify", response_model=m.VerifyReport)
    def verify(event_id: str):
        return found(svc.verify, event_id)

    @api.post("/demo/tamper/{event_id}", response_model=m.TamperResult)
    def tamper(event_id: str):
        if not demo_enabled:
            raise HTTPException(403, "demo endpoints disabled (LOGSYNC_DEMO=0)")
        return found(svc.tamper, event_id)

    @api.post("/demo/restore/{event_id}")
    def restore(event_id: str):
        if not demo_enabled:
            raise HTTPException(403, "demo endpoints disabled (LOGSYNC_DEMO=0)")
        found(svc.restore, event_id)
        return {"restored": event_id}

    @api.get("/packs", response_model=list[m.PackInfo])
    def list_packs():
        return svc.list_packs()

    @api.post("/packs/draft", response_model=m.PackDraft)
    def draft_pack(req: m.DraftRequest):
        lines = [ln for ln in req.sample if ln.strip()]
        if not lines:
            raise HTTPException(422, "sample must contain at least one non-empty line")
        return found(svc.draft_pack, lines)

    @api.post("/packs/approve", response_model=m.ApproveResult)
    def approve_pack(req: m.ApproveRequest):
        return found(svc.approve_pack, req)

    @api.post("/ingest", response_model=m.IngestResult)
    def ingest(req: m.IngestRequest):
        return svc.ingest(req)

    app.include_router(api)

    # In the container the built UI is served from the same origin (no CORS, no CDN).
    if static_dir and (static_dir / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=static_dir / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            return FileResponse(static_dir / "index.html")

    return app

