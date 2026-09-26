"""Checks that the synthetic sample logs are deterministic and well-formed.

These are not parser tests (parsers arrive in M5a); they only make sure every
source emits the structure its real vendor format has.
"""
import csv
import json
import re
from pathlib import Path

import pytest

from logsync.generators import SOURCES, generate_lines
from logsync.generators.__main__ import main as cli_main

REPO = Path(__file__).resolve().parents[1]
N = 300
# Most devices send a full RFC 3164 header (<PRI>timestamp host). FortiGate
# sends only <PRI> and puts date/time inside its key=value body - real devices
# are inconsistent, and the parser must cope with both.
SYSLOG_HEADER = re.compile(r"^<(\d{1,3})>(?:[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \S+ )?")
PRI_ONLY_SOURCES = {"fortigate"}
IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def body(line: str) -> str:
    """Message after the syslog header."""
    return SYSLOG_HEADER.sub("", line, count=1)


@pytest.mark.parametrize("name", SOURCES)
def test_same_seed_same_bytes(name):
    assert generate_lines(name, N, seed=7) == generate_lines(name, N, seed=7)


@pytest.mark.parametrize("name", SOURCES)
def test_different_seed_different_lines(name):
    assert generate_lines(name, N, seed=7) != generate_lines(name, N, seed=8)


@pytest.mark.parametrize("name", SOURCES)
def test_every_line_has_a_valid_syslog_header(name):
    for line in generate_lines(name, N):
        m = SYSLOG_HEADER.match(line)
        assert m, line
        assert 0 <= int(m.group(1)) <= 191          # PRI range from RFC 3164
        has_timestamp_host = m.end() > len("<%s>" % m.group(1))
        assert has_timestamp_host == (name not in PRI_ONLY_SOURCES), line
        assert "\n" not in line and "\r" not in line
        line.encode("ascii")                         # plain ASCII for now


def test_cisco_asa_structure():
    pat = re.compile(r"%ASA-[0-7]-(106100|106023|302013): ")
    ids = set()
    for line in generate_lines("cisco_asa", N):
        m = pat.search(line)
        assert m, line
        ids.add(m.group(1))
        assert re.search(IPV4, line)
    assert ids == {"106100", "106023", "302013"}     # all three message types appear


def test_fortigate_is_key_value():
    kv = re.compile(r'(\w+)=("[^"]*"|\S+)')
    for line in generate_lines("fortigate", N):
        fields = dict(kv.findall(body(line)))
        for key in ("date", "time", "srcip", "dstip", "srcport", "dstport", "action", "proto"):
            assert key in fields, (key, line)
        assert re.fullmatch(IPV4, fields["srcip"])


def test_panos_csv_has_fixed_columns():
    for line in generate_lines("panos", N):
        row = next(csv.reader([body(line)]))
        assert len(row) == 40, line
        assert row[3] == "TRAFFIC"
        assert re.fullmatch(IPV4, row[7]) and re.fullmatch(IPV4, row[8])
        assert row[30] in {"allow", "deny", "drop"}


def test_checkpoint_cef_header_and_extension():
    for line in generate_lines("checkpoint_cef", N):
        msg = body(line)
        assert msg.startswith("CEF:0|Check Point|")
        parts = msg.split("|", 7)
        assert len(parts) == 8                       # 7 header fields + extension
        ext = parts[7]
        for key in ("act=", "src=", "dst=", "spt=", "dpt=", "cs1=", "msg="):
            assert key in ext, (key, line)
        assert "\\=" in ext                          # escaped '=' inside a value


def test_checkpoint_leef_is_tab_delimited():
    for line in generate_lines("checkpoint_leef", N):
        msg = body(line)
        assert msg.startswith("LEEF:1.0|Check Point|")
        attrs = dict(a.split("=", 1) for a in msg.split("|", 5)[5].split("\t"))
        for key in ("src", "dst", "srcPort", "dstPort", "action", "devTime"):
            assert key in attrs, (key, line)


def test_suricata_body_is_eve_json():
    types = set()
    for line in generate_lines("suricata", N):
        assert " suricata[2211]: {" in line
        event = json.loads(line.split(": ", 1)[1])
        types.add(event["event_type"])
        for key in ("timestamp", "src_ip", "dest_ip", "proto"):
            assert key in event
    assert types == {"alert", "flow", "dns"}


def test_cli_writes_lf_only_files(tmp_path):
    assert cli_main(["--out", str(tmp_path), "--count", "25"]) == 0
    for name in SOURCES:
        data = (tmp_path / ("%s.log" % name)).read_bytes()
        assert b"\r" not in data
        assert data.count(b"\n") == 25
        assert data.decode() == "\n".join(generate_lines(name, 25)) + "\n"


def test_committed_samples_match_generator():
    """samples/ must be exactly what `python -m logsync.generators` produces."""
    for name in SOURCES:
        path = REPO / "samples" / ("%s.log" % name)
        assert path.exists(), "run: python -m logsync.generators"
        assert path.read_bytes() == ("\n".join(generate_lines(name, 200)) + "\n").encode()
