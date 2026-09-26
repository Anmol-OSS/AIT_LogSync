"""Tokenizer output + pack mapping -> UES event with field-level provenance.

Every non-empty field the tokenizer captured ends up in the event: mapped to a
UES field, or kept under unmapped.<name>. Nothing captured is dropped. If a
declared transform fails the event is blocked, never silently half-normalized.
"""
from dataclasses import dataclass

from . import transforms
from .pack import KIND_DECODE, Pack
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

    def entry(target, name, s, e, kind, steps):
        chain = KIND_DECODE.get(kind, []) + list(steps)
        try:
            text = raw[s:e].decode("utf-8")
        except UnicodeDecodeError:
            raise transforms.TransformError("bytes[%d:%d] are not valid UTF-8" % (s, e))
        value = transforms.apply(chain, text, ctx)
        _set(ues, target, value)
        provenance.append({"field": target, "value": value, "raw": text, "bytes": [s, e],
                           "transforms": ["utf8_decode"] + [transforms.describe(st) for st in chain]})

    try:
        for fm in pack.maps:
            for src in fm.sources:
                hit = by_name.get(src)
                if hit and hit[1] > hit[0]:
                    entry(fm.target, src, *hit, fm.steps)
                    used.add(src)
                    break
        for name, s, e, kind in fields:
            if name not in used and e > s:
                entry("unmapped." + name.replace(".", "_"), name, s, e, kind, [])
    except transforms.TransformError as err:
        return Normalized(None, [], str(err))

    for target, value in pack.constants.items():
        _set(ues, target, value)
    provenance.sort(key=lambda p: (p["field"].startswith("unmapped."), p["bytes"][0]))
    return Normalized(ues, provenance, None)
