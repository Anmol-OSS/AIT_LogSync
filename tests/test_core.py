"""Parser core (M5a): grok, transforms, tokenizer, packs, round-trip gate, registry, verification."""
import json
from pathlib import Path

import pytest

from logsync.config import Settings
from logsync.core import grok, transforms
from logsync.core.engine import PythonEngine
from logsync.core.event import build_event
from logsync.core.pack import PackError, load_pack
from logsync.core.processor import Processor, RawEvent
from logsync.core.registry import Registry
from logsync.core.tokenize import tokenize
from logsync.core.verify import verify_event
from logsync.generators import SOURCES
from logsync.storage.keys import Signer

REPO = Path(__file__).resolve().parents[1]
PACKS = sorted((load_pack(p.read_text(encoding="utf-8")) for p in (REPO / "packs").glob("*.yaml")),
               key=lambda p: (p.priority, p.id))
TS = "2026-09-25T09:00:00+05:30"


def sample(name):
    return (REPO / "samples" / ("%s.log" % name)).read_bytes().splitlines()


def identify(raw):
    return next((p for p in PACKS if p.fingerprint.search(raw[:1024])), None)


def process(raw, i=0):
    pack = identify(raw)
    tok = tokenize(pack.spec, raw) if pack else None
    return build_event(event_id="e%d" % i, received_at=TS, source_host="h", raw=raw, sha256="00",
                       archive_ref="r", leaf_index=i, pack=pack, tok=tok)


# ---------------------------------------------------------------- grok
def test_grok_expansion():
    assert grok.expand("%{INT:port}") == r"(?P<port>[+-]?\d+)"
    assert grok.expand("%{WORD} x").startswith("(?:")
    with pytest.raises(grok.GrokError):
        grok.expand("%{NOPE:x}")
    with pytest.raises(grok.GrokError):
        grok.expand("%{INT:a} %{INT:a}")


# ---------------------------------------------------------------- transforms
@pytest.mark.parametrize("steps,text,expected", [
    (["ip"], " 10.2.1.7 ", "10.2.1.7"),
    (["int"], "443", 443),
    ([{"lookup": {"allow": "Allowed", "*": "Other"}}], "zzz", "Other"),
    (["rfc3164", "tz"], "Sep  5 09:00:00", "2026-09-05T09:00:00+05:30"),
    (["iso8601", "tz"], "2026-09-25T09:00:06.555385+0530", "2026-09-25T09:00:06.555385+05:30"),
    (["epoch_ns", "tz"], "1790307000000000000", "2026-09-25T09:00:00+05:30"),
    (["epoch_ms", {"tz": "+00:00"}], "1790307000000", "2026-09-25T03:30:00+00:00"),
    (["cef_unescape"], r"policy match\=yes", "policy match=yes"),
    (["csv_unquote"], 'say ""hi""', 'say "hi"'),
    (["json_string"], r"a\"bé", 'a"bé'),
    (["iana_proto"], "17", "udp"),
])
def test_transforms(steps, text, expected):
    assert transforms.apply(steps, text, transforms.Context(TS)) == expected


def test_transform_failures_raise():
    ctx = transforms.Context(TS)
    for steps, text in ((["ip"], "10.2.1"), (["int"], "x"), ([{"lookup": {"a": 1}}], "b")):
        with pytest.raises(transforms.TransformError):
            transforms.apply(steps, text, ctx)


# ---------------------------------------------------------------- tokenizer formats
def spans(data, tok):
    return {f[0]: data[f[1]:f[2]].decode() for f in tok.fields}


def test_kv_quoted_bare_and_trailing_garbage():
    data = b'a=1 b="x y" c=3 junk'
    tok = tokenize({"format": "kv"}, data)
    assert spans(data, tok) == {"a": "1", "b": "x y", "c": "3"}
    assert tok.unexplained == [[16, 20]]
    assert tokenize({"format": "kv"}, b'a="open').unexplained == [[0, 7]]


def test_csv_quotes_and_names():
    data = b'1,"a, ""b""",,x'
    tok = tokenize({"format": "csv", "columns": ["one", "two"]}, data)
    assert [f[0] for f in tok.fields] == ["one", "two", "col2", "col3"]
    assert spans(data, tok)["two"] == 'a, ""b""' and tok.fields[1][3] == 2
    assert tok.unexplained == []


def test_cef_header_escapes_and_spaced_values():
    data = rb"CEF:0|Ven\|dor|P|1|100|Name|5|src=1.2.3.4 cs1=Allow Web msg=a\=b end=1"
    tok = tokenize({"format": "cef"}, data)
    s = spans(data, tok)
    assert s["cef.vendor"] == r"Ven\|dor" and s["cs1"] == "Allow Web" and s["msg"] == r"a\=b"
    assert tok.unexplained == []
    assert not tokenize({"format": "cef"}, b"CEF:0|only|two").ok


def test_leef_tabs():
    data = b"LEEF:1.0|V|P|1|Accept|src=1.2.3.4\tbad\tdst=5.6.7.8"
    tok = tokenize({"format": "leef", "delimiter": "\t"}, data)
    assert spans(data, tok)["dst"] == "5.6.7.8"
    assert tok.unexplained == [[data.index(b"bad"), data.index(b"bad") + 3]]


def test_json_nested_arrays_escapes():
    data = b'{"a":{"b":"x\\"y","c":[1,true]},"d":null} trailing'
    tok = tokenize({"format": "json"}, data)
    s = spans(data, tok)
    assert s == {"a.b": 'x\\"y', "a.c.0": "1", "a.c.1": "true", "d": "null"}
    assert tok.unexplained == [[data.index(b"trailing") - 1 + 1, len(data)]]
    assert not tokenize({"format": "json"}, b'{"a": "unterminated').ok


def test_regex_prefers_full_match_then_reports_leftover():
    spec = {"format": "regex", "patterns": [r"(?P<a>\d+)", r"(?P<a>\d+) (?P<b>\w+)"]}
    assert tokenize(spec, b"12 ab").unexplained == []
    assert tokenize(spec, b"12 ab !").unexplained == [[5, 7]]
    assert not tokenize(spec, b"xx").ok


# ---------------------------------------------------------------- packs on the corpus
@pytest.mark.parametrize("name", [n for n, s in SOURCES.items() if s.has_pack])
def test_every_sample_line_is_accepted_with_exact_provenance(name):
    for i, raw in enumerate(sample(name)):
        ev = process(raw, i)
        assert ev["status"] == "accepted", (i, ev["roundtrip"])
        assert ev["roundtrip"]["unexplained"] == []
        assert ev["ues"]["class_uid"] == 4001
        for p in ev["provenance"]:
            s, e = p["bytes"]
            assert raw[s:e].decode() == p["raw"]                    # bytes point at the source text


def test_core_fields_are_mapped_for_every_family():
    for name, src in SOURCES.items():
        if not src.has_pack:
            continue
        ev = process(sample(name)[0])
        u = ev["ues"]
        assert u["src_endpoint"]["ip"] and u["dst_endpoint"]["ip"], name
        assert isinstance(u["dst_endpoint"]["port"], int), name
        assert u["time"].startswith("2026-09-25T"), name


def test_unknown_device_is_unparsed():
    ev = process(sample("juniper_srx")[0])
    assert ev["status"] == "unparsed" and ev["parser"]["pack_id"] == "none"


@pytest.mark.parametrize("name,mutate,reason", [
    ("fortigate", lambda b: b + b" X-DBG:9f", "not explained"),
    ("suricata", lambda b: b[:-5], "structure did not match"),
    ("checkpoint_cef", lambda b: b.replace(b"|Log|", b"~Log~"), "structure did not match"),
    ("panos", lambda b: b.replace(b"192.168.4.11", b"192.168.4.311"), "declared transform failed"),
    ("cisco_asa", lambda b: b + b" trailing", "not explained"),
])
def test_damaged_lines_are_blocked_never_half_normalized(name, mutate, reason):
    ev = process(mutate(sample(name)[0]))
    assert ev["status"] == "blocked"
    assert ev["ues"] is None and ev["provenance"] == []
    assert reason in ev["roundtrip"]["reason"]


def test_pack_validation():
    with pytest.raises(PackError):
        load_pack("id: x\nversion: 1\nformat: nope\nfingerprint: a\n")
    with pytest.raises(PackError):
        load_pack("id: x\nversion: 1\nformat: kv\nfingerprint: a\nmap: {a: {from: b, transforms: [nope]}}\n")


# ---------------------------------------------------------------- registry
def test_registry_signs_verifies_and_hot_reloads(tmp_path):
    reg = Registry(tmp_path / "packs", Signer(tmp_path / "k.pem"))
    assert reg.bootstrap(REPO / "packs") == 6
    assert len(reg.active()) == 6
    fg = reg.get("fortigate", "1.3.0")
    assert reg.is_signed(fg)

    newer = fg.text.replace("version: 1.3.0", "version: 1.4.0")
    reg.add(newer)
    assert [p.version for p in reg.active() if p.id == "fortigate"] == ["1.4.0"]
    assert reg.get("fortigate", "1.3.0") is not None          # old version kept for verification
    with pytest.raises(PackError):
        reg.add(newer)                                        # versions are immutable

    path = tmp_path / "packs" / "fortigate@1.4.0.yaml"
    path.write_bytes(path.read_bytes().replace(b"accept: Allowed", b"accept: Blocked"))
    assert reg.reload_if_changed()
    assert "fortigate@1.4.0.yaml" in reg.rejected             # tampered pack refused
    assert [p.version for p in reg.active() if p.id == "fortigate"] == ["1.3.0"]


# ---------------------------------------------------------------- processor + verification
@pytest.fixture
def proc(tmp_path):
    s = Settings(data_dir=tmp_path / "data", packs_dir=REPO / "packs", sth_every_leaves=1000,
                 sth_every_seconds=3600, parser_engine="python")
    return Processor(s, engine=PythonEngine())


def test_process_verify_tamper(proc):
    lines = [(n, raw) for n in ("fortigate", "panos", "juniper_srx") for raw in sample(n)[:5]]
    stored = [proc.process(RawEvent("evt-%d" % i, TS, "10.0.0.%d" % i, raw)) for i, (_, raw) in enumerate(lines)]
    assert proc.process(RawEvent("evt-0", TS, "x", lines[0][1])) is None       # duplicate delivery ignored
    proc.flush()
    assert [e["status"] for e in stored].count("unparsed") == 5

    def verify(ev):
        doc = json.loads(proc.db.connect().execute("SELECT doc FROM events WHERE event_id=?",
                                                   (ev["event_id"],)).fetchone()["doc"])
        return verify_event(doc, proc.evidence, proc.registry, proc.engine)

    good = stored[0]
    r = verify(good)
    assert r["overall"] == "verified", r
    assert verify(stored[12])["overall"] == "verified"                          # unparsed: archive + Merkle hold

    ip = next(p for p in good["provenance"] if p["field"] == "src_endpoint.ip")
    pos = ip["bytes"][1] - 1
    ref = good["raw"]["archive_ref"]
    old = proc.evidence.archive.overwrite_byte(ref, pos, ord("9") if good["raw"]["text"][pos] != "9" else ord("8"))
    r = verify(good)
    status = {c["name"]: c["status"] for c in r["checks"]}
    assert r["overall"] == "failed" and r["tampered"] and r["tampered_byte"] == pos
    assert status == {"archive_integrity": "fail", "parser_integrity": "pass", "provenance_integrity": "fail",
                      "roundtrip_integrity": "pass", "merkle_integrity": "fail"}

    proc.evidence.archive.overwrite_byte(ref, pos, old)
    assert verify(good)["overall"] == "verified"
