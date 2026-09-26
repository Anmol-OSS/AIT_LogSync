"""Archive, signed tree heads, RFC 3161, tamper detection, Parquet lake (M4)."""
import pyarrow.parquet as pq
import pytest

from logsync.config import Settings
from logsync.storage.archive import Archive
from logsync.storage.db import Database
from logsync.storage.evidence import EvidenceStore
from logsync.storage.keys import Signer
from logsync.storage.lake import LakeWriter


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path / "data", sth_every_leaves=5, sth_every_seconds=3600)


@pytest.fixture
def db(settings):
    return Database(settings.db_path)


def test_archive_roundtrip_dedup_and_seal(tmp_path, db):
    a = Archive(tmp_path / "arc", db, segment_max_bytes=100)
    lines = [b"<134>line number %d with some padding" % i for i in range(10)]
    stored = [a.put(ln) for ln in lines]
    assert a.put(lines[3]) == stored[3]                    # identical bytes stored once
    assert list((tmp_path / "arc").glob("*.log.gz"))       # small segment size forced sealing
    for ln, (sha, ref) in zip(lines, stored):
        assert a.get(ref) == ln                            # readable from sealed and active segments
        assert a.ref_for(sha) == ref


def test_overwrite_byte_in_sealed_segment(tmp_path, db):
    a = Archive(tmp_path / "arc", db, segment_max_bytes=10)
    _, ref = a.put(b"src=10.2.1.7")
    old = a.overwrite_byte(ref, 11, ord("9"))
    assert old == ord("7") and a.get(ref) == b"src=10.2.1.9"


def test_signer_roundtrip_and_reload(tmp_path):
    s = Signer(tmp_path / "k.pem")
    sig = s.sign(b"tree head")
    assert s.verify(b"tree head", sig) and not s.verify(b"tree head!", sig)
    assert Signer(tmp_path / "k.pem").verify(b"tree head", sig)   # same key after restart


def test_evidence_record_seal_prove_and_detect_tamper(settings, db):
    ev = EvidenceStore(settings, db)
    events = [("evt-%d" % i, "2026-09-25T09:00:%02d+05:30" % i, b"raw line %d" % i) for i in range(12)]
    recorded = [ev.record(*e) for e in events]
    assert ev.proof(3) is None                              # not sealed yet
    head = ev.seal()
    assert head.tree_size == 12

    eid, ts, raw = events[3]
    ok, detail = ev.check_inclusion(eid, ts, raw, recorded[3][2])
    assert ok, detail

    ok, _ = ev.check_inclusion(eid, ts, raw + b"x", recorded[3][2])        # altered bytes
    assert not ok
    ok, _ = ev.check_inclusion(eid, "2026-09-25T10:00:00+05:30", raw, recorded[3][2])  # altered metadata
    assert not ok

    # the archive itself is tampered: reading back gives different bytes, proof fails
    sha, ref, idx = recorded[3]
    ev.archive.overwrite_byte(ref, 0, ord("R"))
    ok, _ = ev.check_inclusion(eid, ts, ev.archive.get(ref), idx)
    assert not ok


def test_maybe_seal_cadence(settings, db):
    ev = EvidenceStore(settings, db)
    for i in range(4):
        ev.record("e%d" % i, "t", b"x%d" % i)
    assert ev.maybe_seal() is None                          # 4 < 5 leaves, time not due
    ev.record("e4", "t", b"x4")
    assert ev.maybe_seal().tree_size == 5
    assert ev.maybe_seal(force=True) is None                # nothing new to seal


def test_rfc3161_timestamp_on_tree_head(settings, db):
    ev = EvidenceStore(settings, db)
    if not ev.tsa.available:
        pytest.skip("openssl not installed")
    ev.record("e0", "t", b"x")
    head = ev.seal()
    assert head.rfc3161
    assert ev.tsa.verify(head.message(), head.rfc3161)
    assert not ev.tsa.verify(head.message() + b"x", head.rfc3161)
    assert ev.tsa.describe(head.rfc3161).endswith("GMT")


def test_lake_writes_typed_parquet(tmp_path):
    w = LakeWriter(tmp_path, flush_rows=1000)
    event = {
        "event_id": "e1", "received_at": "2026-09-25T09:00:00+05:30", "status": "accepted",
        "source": {"name": "fortigate"}, "raw": {"sha256": "sha256:ab", "archive_ref": "seg-000001:0:10"},
        "merkle": {"leaf_index": 0}, "parser": {"pack_id": "fortigate", "version": "1.0.0"},
        "provenance": [],
        "ues": {"class_uid": 4001, "time": "2026-09-25T09:00:00+05:30",
                "src_endpoint": {"ip": "10.2.1.7", "port": 4521}, "dst_endpoint": {"ip": "8.8.8.8", "port": 53},
                "unmapped": {"policyid": "3"}},
    }
    w.add(event)
    path = w.flush()
    t = pq.read_table(path)
    assert t.num_rows == 1
    assert t.column("src_port").type == "int32"
    assert t.to_pylist()[0]["src_ip"] == "10.2.1.7"
