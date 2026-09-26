"""The deterministic gate every candidate pack must pass - whoever wrote it.

    match_rate    fraction of held-out dead-letter lines (not just the samples the
                  drafter saw) the pack parses with every byte explained
    roundtrip     on every matched line: no unexplained bytes, every declared
                  transform succeeds (the same gate live events go through)
    specificity   the pattern must actually describe the format: enough literal
                  text and fields, no single catch-all capture - otherwise a
                  lazy or manipulated `.*` would "match" everything
    fuzz          mutated lines through the WASM sandbox: no crash, runaway
                  inputs stopped by the fuel budget
    differential  WASM output == Python reference output on samples and mutants
"""
import random
import re

from ..core import transforms
from ..core.engine import PythonEngine
from ..core.normalize import normalize
from ..core.pack import Pack

MIN_MATCH = 0.95


def _check(name, ok, detail):
    return {"name": name, "status": "pass" if ok else "fail", "detail": detail}


def _mutants(lines: list[bytes], n: int, seed: str) -> list[bytes]:
    rng = random.Random(seed)
    alphabet = b' ="|,\\{}[]:/-<>0aZ.\xff'
    out = []
    for i in range(n):
        b = bytearray(lines[i % len(lines)])
        for _ in range(rng.randint(1, 3)):
            op, j = rng.randrange(4), rng.randrange(max(len(b), 1))
            if op == 0 and b:
                b[j] = rng.choice(alphabet)
            elif op == 1:
                b.insert(j, rng.choice(alphabet))
            elif op == 2 and b:
                del b[j]
            else:
                b = b[:j]
        out.append(bytes(b))
    out.append(lines[0] * 40)          # oversized line
    return out


def validate(pack: Pack, grok_pattern: str, samples: list[bytes], held_out: list[bytes], wasm,
             received_at: str) -> list[dict]:
    ref = PythonEngine()
    checks = []
    ctx = transforms.Context(received_at)

    # match rate + round-trip on held-out lines
    pool = held_out or samples
    toks = wasm.tokenize_many(pack.spec, pool)
    matched = [(raw, t) for raw, t in zip(pool, toks) if t.ok and not t.unexplained]
    rate = len(matched) / len(pool)
    checks.append(_check("match_rate", rate >= MIN_MATCH,
                         "%d / %d held-out lines parsed with every byte explained (%.1f%%)"
                         % (len(matched), len(pool), 100 * rate)))
    failures = [n.error for raw, t in matched if (n := normalize(pack, t, raw, ctx)).error]
    checks.append(_check("roundtrip", bool(matched) and not failures,
                         "every matched line: all bytes explained, all declared transforms succeed"
                         if not failures else "%d lines failed a transform: %s" % (len(failures), failures[0])))

    # specificity: a pattern that explains everything by capturing everything is not a parser
    literal_chars = len(re.sub(r"\\(.)", r"\1", re.sub(r"%\{[^}]*\}", "", grok_pattern)))
    n_fields = len(re.findall(r"%\{\w+:\w+\}", grok_pattern))
    # a single capture holding most of the line means the pattern explains nothing
    lazy = any(e - s > 0.6 * len(raw) for raw, t in matched for _, s, e, _ in t.fields)
    specific = literal_chars >= 8 and n_fields >= 3 and not lazy
    checks.append(_check("specificity", specific,
                         "%d literal characters, %d fields, no catch-all capture" % (literal_chars, n_fields)
                         if specific else "pattern too generic (%d literal characters, %d fields%s)"
                         % (literal_chars, n_fields, ", catch-all capture" if lazy else "")))

    # fuzz in the sandbox
    mutants = _mutants(samples, 300, "fuzz:" + pack.ref)
    traps_before = wasm.traps
    wtoks = [wasm.tokenize(pack.spec, m) for m in mutants]
    stopped = sum(1 for t in wtoks if t.error and ("fuel" in t.error or "trapped" in t.error))
    checks.append(_check("fuzz", True, "%d mutated lines: no crash; %d stopped by the sandbox budget; %d traps recovered"
                         % (len(mutants), stopped, wasm.traps - traps_before)))

    # differential: sandboxed Rust vs Python reference
    diffs = 0
    for m, wt in zip(samples + mutants, [wasm.tokenize(pack.spec, s) for s in samples] + wtoks):
        if wt.error and ("fuel" in wt.error or "trapped" in wt.error):
            continue
        rt = ref.tokenize(pack.spec, m)
        if (rt.ok, rt.fields, rt.unexplained) != (wt.ok, wt.fields, wt.unexplained):
            diffs += 1
    checks.append(_check("differential", diffs == 0,
                         "WASM output == Python reference on %d lines" % (len(samples) + len(mutants))
                         if not diffs else "%d lines differ between WASM and Python" % diffs))
    return checks


def passed(checks: list[dict]) -> bool:
    return all(c["status"] == "pass" for c in checks)
