"""WASM runtime (M5b): differential test against the Python reference, sandbox limits."""
import random
from pathlib import Path

import pytest

from logsync.core.pack import load_pack
from logsync.core.tokenize import tokenize
from logsync.core.wasm_host import WasmEngine
from logsync.generators import SOURCES

REPO = Path(__file__).resolve().parents[1]
PACKS = {p.source_name: p for p in (load_pack(f.read_text(encoding="utf-8")) for f in (REPO / "packs").glob("*.yaml"))}


@pytest.fixture(scope="module")
def wasm():
    return WasmEngine()


def same(spec, raw, wasm):
    ref = tokenize(spec, raw)
    got = wasm.tokenize(spec, raw)
    assert got.ok == ref.ok, (raw, ref.error, got.error)
    assert got.fields == ref.fields, raw
    assert got.unexplained == ref.unexplained, raw
    return ref


def test_module_has_no_imports(wasm):
    # no WASI, no host functions: the parser cannot touch files, network or clock
    assert wasm.imports == []


@pytest.mark.parametrize("name", [n for n, s in SOURCES.items() if s.has_pack])
def test_differential_full_corpus(name, wasm):
    spec = PACKS[name].spec
    for raw in (REPO / "samples" / ("%s.log" % name)).read_bytes().splitlines():
        assert same(spec, raw, wasm).ok


@pytest.mark.parametrize("name", [n for n, s in SOURCES.items() if s.has_pack])
def test_differential_on_mutated_lines(name, wasm):
    """Random byte flips, insertions, deletions and truncations: both engines
    must still agree exactly, including on errors and unexplained spans."""
    rng = random.Random("fuzz:" + name)
    spec = PACKS[name].spec
    lines = (REPO / "samples" / ("%s.log" % name)).read_bytes().splitlines()[:40]
    alphabet = b' ="|,\\{}[]:\t=0aZ.\xc3\xa9\xff'
    for raw in lines:
        for _ in range(25):
            b = bytearray(raw)
            op = rng.randrange(4)
            i = rng.randrange(len(b))
            if op == 0:
                b[i] = rng.choice(alphabet)
            elif op == 1:
                b.insert(i, rng.choice(alphabet))
            elif op == 2:
                del b[i]
            else:
                b = b[:i]
            same(spec, bytes(b), wasm)


@pytest.mark.parametrize("spec,raw", [
    ({"format": "kv"}, b'a=1 b="x y" c=3 junk'),
    ({"format": "csv", "columns": ["one"]}, b'1,"a, ""b""",,x'),
    ({"format": "cef"}, rb"CEF:0|Ven\|dor|P|1|100|Name|5|src=1.2.3.4 cs1=Allow Web msg=a\=b"),
    ({"format": "leef", "delimiter": "\t"}, b"LEEF:1.0|V|P|1|Accept|src=1.2.3.4\tbad\tdst=5.6.7.8"),
    ({"format": "json"}, b'{"a":{"b":"x\\"y","c":[1,true]},"d":null} trailing'),
    ({"format": "json"}, b'{"k\xc3\xa9y":"\xff"}'),
    ({"format": "regex", "patterns": [r"(?P<a>\d+)", r"(?P<a>\d+) (?P<b>\w+)"]}, b"12 ab !"),
    ({"format": "kv"}, b""),
])
def test_differential_edge_cases(spec, raw, wasm):
    same(spec, raw, wasm)


def test_batch_matches_single_calls(wasm):
    spec = PACKS["panos"].spec
    lines = (REPO / "samples" / "panos.log").read_bytes().splitlines()[:50] + [b"", b"garbage"]
    assert wasm.tokenize_many(spec, lines) == [wasm.tokenize(spec, ln) for ln in lines]


def test_runaway_line_in_batch_blocks_only_that_line():
    eng = WasmEngine(fuel=200_000)
    spec = {"format": "kv"}
    batch = [b"a=1", b"a=1 " * 200_000, b"b=2"]
    r = eng.tokenize_many(spec, batch)
    assert r[0].ok and r[2].ok and not r[1].ok and "fuel" in r[1].error


def test_fuel_budget_stops_runaway_parse():
    tight = WasmEngine(fuel=200_000)
    r = tight.tokenize({"format": "kv"}, b"a=1 " * 200_000)
    assert not r.ok and "fuel" in r.error
    assert tight.traps == 1
    ok = tight.tokenize({"format": "kv"}, b"a=1")                # fresh instance after the trap
    assert ok.ok and ok.fields == [["a", 2, 3, 0]]


def test_memory_limit_contains_huge_input():
    small = WasmEngine(memory_limit=4 * 1024 * 1024)
    r = small.tokenize({"format": "kv"}, b"x" * (8 * 1024 * 1024))
    assert not r.ok
    ok = small.tokenize({"format": "kv"}, b"a=1")
    assert ok.ok and ok.fields == [["a", 2, 3, 0]]          # engine recovered with a fresh instance


def test_fuel_needed_for_a_real_line_is_far_below_budget(wasm):
    raw = (REPO / "samples" / "fortigate.log").read_bytes().splitlines()[0]
    used = wasm.fuel_used(PACKS["fortigate"].spec, raw)
    assert 0 < used < wasm.fuel / 10
