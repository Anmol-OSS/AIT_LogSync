"""Streaming pipeline (M5c): framing, end-to-end over real sockets, live API, SIEM forwarder, Kafka."""
import json
import os
import socket
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from logsync.api.app import create_app
from logsync.api.live import LiveService
from logsync.config import Settings
from logsync.core.processor import Processor
from logsync.generators import SOURCES, generate_lines
from logsync.pipeline.bus import MemoryBus
from logsync.pipeline.forwarder import SyslogForwarder
from logsync.pipeline.ingest import SyslogServer, send_lines, split_frames
from logsync.pipeline.worker import Worker

REPO = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(cond, timeout=30.0):
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise TimeoutError
        time.sleep(0.05)


# ---------------------------------------------------------------- framing
def test_rfc6587_octet_counting_and_newlines():
    buf = bytearray(b"5 hello11 <1>a b c de\nline two\r\npartial")
    assert split_frames(buf) == [b"hello", b"<1>a b c de", b"line two"]
    assert bytes(buf) == b"partial"
    buf = bytearray(b"13 <1>incomple")
    assert split_frames(buf) == [] and bytes(buf) == b"13 <1>incomple"
    buf += b"te"
    assert split_frames(buf) == [b"<1>incomplete"]


# ---------------------------------------------------------------- end to end
@pytest.fixture
def stack(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", packs_dir=REPO / "packs", sth_every_leaves=100,
                        sth_every_seconds=0.2, parser_engine="wasm")
    siem = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    siem.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)  # UDP drops silently when full
    siem.bind(("127.0.0.1", 0))
    siem.settimeout(2)
    fwd = SyslogForwarder("udp://127.0.0.1:%d" % siem.getsockname()[1])
    bus = MemoryBus()
    proc = Processor(settings, forwarder=fwd)
    worker = Worker(proc, bus).start()
    port = free_port()
    ingest = SyslogServer(bus, "127.0.0.1", port, tz=settings.default_tz).start()
    service = LiveService(settings, publish=bus.publish)
    yield {"port": port, "proc": proc, "service": service, "siem": siem, "fwd": fwd, "bus": bus, "worker": worker}
    ingest.stop()
    worker.stop()
    siem.close()


def count(proc):
    return proc.db.connect().execute("SELECT COUNT(*) n FROM events").fetchone()["n"]


def test_end_to_end_tcp_syslog_to_verified_events(stack):
    proc, svc = stack["proc"], stack["service"]
    per = 40
    lines = [ln.encode() for name in SOURCES for ln in generate_lines(name, per, seed=99)]
    send_lines(lines, "127.0.0.1", stack["port"], "tcp")
    total = per * len(SOURCES)
    wait_until(lambda: count(proc) == total)
    wait_until(lambda: (svc.evidence.latest_head() or type("h", (), {"tree_size": 0})).tree_size >= total)

    d = svc.dashboard()
    assert d.totals.received == d.totals.archived == total
    assert d.totals.normalized == per * 6 and d.totals.dead_letter == per and d.totals.blocked == 0
    assert {s.name for s in d.sources} == set(SOURCES) - {"juniper_srx"} | {"unknown"}
    assert any("match no pack" in x.detail for x in d.drift)

    # every accepted event was forwarded to the SIEM
    got = 0
    while True:
        try:
            msg = stack["siem"].recv(65536)
        except socket.timeout:
            break
        body = json.loads(msg.split(b" - ues - ", 1)[1])
        assert body["evidence"]["raw_sha256"].startswith("sha256:")
        got += 1
    assert got == per * 6 == stack["fwd"].sent

    ev = svc.list_events(limit=500, source="panos", status="accepted")[0]
    full = svc.get_event(ev["event_id"])
    assert full["merkle"]["status"] == "sealed" and full["merkle"]["inclusion_proof"]
    assert svc.verify(ev["event_id"])["overall"] == "verified"
    t = svc.tamper(ev["event_id"])
    r = svc.verify(ev["event_id"])
    assert r["overall"] == "failed" and r["tampered_byte"] == t.tampered_byte
    svc.restore(ev["event_id"])
    assert svc.verify(ev["event_id"])["overall"] == "verified"

    unknown = svc.list_events(limit=1, status="unparsed")[0]
    assert svc.verify(unknown["event_id"])["overall"] == "verified"    # raw archived and sealed anyway


def test_udp_ingest_and_http_ingest_share_the_pipeline(stack):
    proc = stack["proc"]
    send_lines([ln.encode() for ln in generate_lines("fortigate", 20)], "127.0.0.1", stack["port"], "udp")
    client = TestClient(create_app(stack["service"]))
    r = client.post("/api/ingest", json={"lines": generate_lines("suricata", 5), "source_host": "test"}).json()
    assert r["accepted"] == 5
    wait_until(lambda: count(proc) == 25)
    e = client.get("/api/events/%s" % r["event_ids"][0]).json()
    assert e["source"]["name"] == "suricata" and e["source"]["host"] == "test"


def test_duplicate_delivery_is_idempotent(stack):
    proc, bus = stack["proc"], stack["bus"]
    from logsync.core.processor import RawEvent
    ev = RawEvent("dup-1", "2026-09-25T09:00:00+05:30", "h", generate_lines("panos", 1)[0].encode())
    bus.publish(ev)
    bus.publish(ev)
    wait_until(lambda: count(proc) == 1)
    time.sleep(0.3)
    assert count(proc) == 1


# ---------------------------------------------------------------- Kafka (needs a broker)
@pytest.mark.skipif(not os.environ.get("LOGSYNC_TEST_KAFKA"), reason="set LOGSYNC_TEST_KAFKA=host:port")
def test_kafka_bus_roundtrip(tmp_path):
    from logsync.pipeline.bus import KafkaBus, wait_for_kafka
    from logsync.pipeline.ingest import Stamper
    boot = os.environ["LOGSYNC_TEST_KAFKA"]
    wait_for_kafka(boot)
    settings = Settings(data_dir=tmp_path / "data", packs_dir=REPO / "packs", parser_engine="wasm")
    producer = KafkaBus(boot)
    consumer = KafkaBus(boot, group="test-%d" % time.time_ns(), consume=True)
    worker = Worker(Processor(settings), consumer)
    stamper = Stamper()
    sent = [stamper.make(ln.encode(), "kafka-test") for ln in generate_lines("checkpoint_leef", 30, seed=5)]
    for ev in sent:
        producer.publish(ev)
    producer.flush()
    ids = {e.event_id for e in sent}
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        worker.run_once(timeout=1)
        rows = worker.processor.db.connect().execute("SELECT event_id, status FROM events").fetchall()
        if ids <= {r["event_id"] for r in rows}:
            break
    got = {r["event_id"]: r["status"] for r in rows if r["event_id"] in ids}
    assert len(got) == 30 and set(got.values()) == {"accepted"}
    producer.close()
    consumer.close()
