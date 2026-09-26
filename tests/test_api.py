"""API contract tests against the fixture service (M3).

The frontend mock JSON is the contract; FixtureService validates it through
the Pydantic models with extra="forbid", so any drift between
frontend/src/types.ts and backend models fails here.
"""
import pytest
from fastapi.testclient import TestClient

from logsync.api.app import create_app
from logsync.api.service import FixtureService


@pytest.fixture
def client():
    return TestClient(create_app(FixtureService()))


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_dashboard_shape(client):
    d = client.get("/api/dashboard").json()
    assert set(d) == {"window", "totals", "sources", "drift"}
    assert d["totals"]["received"] >= d["totals"]["normalized"]


def test_list_and_filter_events(client):
    all_events = client.get("/api/events").json()
    assert len(all_events) == 6
    blocked = client.get("/api/events", params={"status": "blocked"}).json()
    assert [e["status"] for e in blocked] == ["blocked"]
    assert len(client.get("/api/events", params={"limit": 2}).json()) == 2


def test_get_event_and_404(client):
    e = client.get("/api/events/evt_fortigate_0001").json()
    assert e["raw"]["text"].startswith("<189>date=")
    assert client.get("/api/events/nope").status_code == 404


def test_verify_then_tamper_then_restore(client):
    eid = "evt_panos_0003"
    assert client.post(f"/api/events/{eid}/verify").json()["overall"] == "verified"
    t = client.post(f"/api/demo/tamper/{eid}").json()
    assert t["tampered_raw"] != client.get(f"/api/events/{eid}").json()["raw"]["text"]
    assert client.post(f"/api/events/{eid}/verify").json()["overall"] == "failed"
    client.post(f"/api/demo/restore/{eid}")
    assert client.post(f"/api/events/{eid}/verify").json()["overall"] == "verified"


def test_draft_and_approve(client):
    assert client.post("/api/packs/draft", json={"sample": ["", "  "]}).status_code == 422
    d = client.post("/api/packs/draft", json={"sample": ["<14>Sep 25 09:14:02 srx-edge01 RT_FLOW: x"]}).json()
    fields = [{"name": f["name"], "mapped_to": f["mapped_to"]} for f in d["fields"]]
    fields[0]["mapped_to"] = "(ignore)"
    r = client.post("/api/packs/approve", json={"draft_id": d["draft_id"], "fields": fields}).json()
    assert r["mapped_fields"] == len(fields) - 1


def test_demo_endpoints_can_be_disabled(monkeypatch):
    monkeypatch.setenv("LOGSYNC_DEMO", "0")
    c = TestClient(create_app(FixtureService()))
    assert c.post("/api/demo/tamper/evt_panos_0003").status_code == 403
