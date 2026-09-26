"""Tokenizer output + pack mapping -> UES event with field-level provenance.

Every non-empty field the tokenizer captured ends up in the event: mapped to a
UES field, or kept under unmapped.<name>. Nothing captured is dropped. If a
declared transform fails the event is blocked, never silently half-normalized.
"""
import re
from dataclasses import dataclass

from . import transforms
from .pack import Pack, unmapped_chain
from .tokenize import TokenResult


@dataclass
class Normalized:
    ues: dict | None
    provenance: list[dict]
    error: str | None


def _set(d: dict, path: str, value) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = value


def _named(fields: list) -> list[tuple[str, int, int, int]]:
    """Give repeated field names a #2, #3 ... suffix so every capture is addressable."""
    seen: dict[str, int] = {}
    out = []
    for name, s, e, kind in fields:
        seen[name] = seen.get(name, 0) + 1
        out.append((name if seen[name] == 1 else "%s#%d" % (name, seen[name]), s, e, kind))
    return out


def normalize(pack: Pack, tok: TokenResult, raw: bytes, ctx: transforms.Context) -> Normalized:
    fields = _named(tok.fields)
    by_name = {name: (s, e, kind) for name, s, e, kind in fields}
    ues: dict = {}
    provenance: list[dict] = []
    used: set[str] = set()

    def entry(target, s, e, chain):
        try:
            text = raw[s:e].decode("utf-8")
        except UnicodeDecodeError:
            raise transforms.TransformError("bytes[%d:%d] are not valid UTF-8" % (s, e))
        value = chain.run(text, ctx)
        _set(ues, target, value)
        provenance.append({"field": target, "value": value, "raw": text, "bytes": [s, e],
                           "transforms": chain.labels})

    try:
        if pack.exact_columns is not None:
            names = set(pack.spec["columns"])
            cols = sum(1 for name, *_ in fields if name in names or re.fullmatch(r"col\d+", name))
            if cols != pack.exact_columns:
                raise transforms.TransformError("expected %d columns, got %d (format changed?)"
                                                % (pack.exact_columns, cols))
        missing = [f for f in pack.required if f not in by_name]
        if missing:
            raise transforms.TransformError("required field%s %s missing (truncated message?)"
                                            % ("s" if len(missing) > 1 else "", ", ".join(missing[:4])))
        for fname, (rx, shown) in pack.validators.items():
            hit = by_name.get(fname)
            if hit and not rx.fullmatch(raw[hit[0]:hit[1]]):
                raise transforms.TransformError("field %s = %r does not match declared %s"
                                                % (fname, raw[hit[0]:hit[1]].decode("utf-8", "replace")[:40], shown))
        for fm in pack.maps:
            for src in fm.sources:
                hit = by_name.get(src)
                if hit and hit[1] > hit[0]:
                    entry(fm.target, hit[0], hit[1], fm.chain(hit[2]))
                    used.add(src)
                    break
        for name, s, e, kind in fields:
            if name not in used and e > s:
                entry("unmapped." + name.replace(".", "_"), s, e, unmapped_chain(kind))
    except transforms.TransformError as err:
        return Normalized(None, [], str(err))

    for target, value in pack.constants.items():
        _set(ues, target, value)
    provenance.sort(key=lambda p: (p["field"].startswith("unmapped."), p["bytes"][0]))
    return Normalized(ues, provenance, None)
