"""REST API contract, against the live service over a real evidence store.

Responses go through the Pydantic response models (extra="forbid"), so any
drift between backend output and the contract in frontend/src/types.ts fails.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from logsync.api.app import create_app
from logsync.api.live import LiveService
from logsync.config import Settings
from logsync.core.processor import Processor, RawEvent
from logsync.generators import SOURCES, generate_lines

REPO = Path(__file__).resolve().parents[1]
TS = "2026-09-25T09:00:00+05:30"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    s = Settings(data_dir=tmp_path_factory.mktemp("api") / "data", packs_dir=REPO / "packs")
    p = Processor(s)
    batch = [RawEvent("%s-%d" % (n, i), TS, "10.0.0.1", ln.encode())
             for n in SOURCES for i, ln in enumerate(generate_lines(n, 10, seed=21))]
    batch.append(RawEvent("broken-0", TS, "10.0.0.2", generate_lines("fortigate", 1)[0].encode() + b" X-DBG:9f"))
    p.process_batch(batch)
    p.flush()
    return TestClient(create_app(LiveService(s)))


def test_health(client):
    assert client.get("/api/health").json()["service"] == "LiveService"


def test_dashboard(client):
    d = client.get("/api/dashboard").json()
    t = d["totals"]
    assert t["received"] == t["archived"] == 10 * len(SOURCES) + 1
    assert (t["normalized"], t["blocked"], t["dead_letter"]) == (60, 1, 10)
    assert any(x["signal"] == "blocked by gate" for x in d["drift"])


def test_list_filter_and_get(client):
    assert len(client.get("/api/events", params={"limit": 5}).json()) == 5
    blocked = client.get("/api/events", params={"status": "blocked"}).json()
    assert [e["event_id"] for e in blocked] == ["broken-0"]
    assert blocked[0]["roundtrip"]["unexplained"]
    e = client.get("/api/events/panos-3").json()
    assert e["merkle"]["status"] == "sealed" and e["merkle"]["inclusion_proof"]
    assert client.get("/api/events/nope").status_code == 404


def test_verify_tamper_restore(client):
    assert client.post("/api/events/suricata-2/verify").json()["overall"] == "verified"
    t = client.post("/api/demo/tamper/suricata-2").json()
    r = client.post("/api/events/suricata-2/verify").json()
    assert r["overall"] == "failed" and r["tampered_raw"] == t["tampered_raw"]
    client.post("/api/demo/restore/suricata-2")
    assert client.post("/api/events/suricata-2/verify").json()["overall"] == "verified"


def test_blocked_event_verifies_as_consistently_blocked(client):
    r = client.post("/api/events/broken-0/verify").json()
    assert r["overall"] == "verified"


def test_packs_listed_and_signed(client):
    packs = client.get("/api/packs").json()
    assert len(packs) == 6 and all(p["signed"] for p in packs)


def test_synthesis_disabled_is_a_clear_error(client):
    assert client.post("/api/packs/draft", json={"sample": ["x"]}).status_code == 404
    assert client.post("/api/packs/draft", json={"sample": [" "]}).status_code == 422


def test_demo_endpoints_can_be_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("LOGSYNC_DEMO", "0")
    locked = TestClient(create_app(LiveService(Settings(data_dir=tmp_path / "data"))))
    assert locked.post("/api/demo/tamper/x").status_code == 403
