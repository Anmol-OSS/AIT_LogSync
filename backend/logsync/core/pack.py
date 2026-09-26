"""Parser packs: declarative YAML describing one source format.

    id / version / vendor / product / family / source_name
    priority      lower is tried first when identifying
    fingerprint   regex searched in the first 1 KiB to identify the source
    format        regex | kv | csv | cef | leef | json
    header        optional grok/regex matched at byte 0 (syslog header etc.)
    patterns      (regex format) grok patterns tried in order
    columns       (csv format) column names
    map           UES field -> {from: source field(s), transforms: [...]}
    constants     UES field -> fixed value (class_uid, vendor name, ...)

A pack is data, not code: it is compiled into a spec for the tokenizer, which
runs inside the WASM sandbox. The pack's digest (SHA-256 of the file bytes)
is recorded in every event it produces.
"""
import hashlib
import re
from dataclasses import dataclass, field

import yaml

from . import grok, transforms

FORMATS = {"regex", "kv", "csv", "cef", "leef", "json"}
# transform applied first, by tokenizer field kind, to undo the wire encoding
KIND_DECODE = {1: ["json_string"], 2: ["csv_unquote"], 3: ["cef_unescape"]}


class PackError(ValueError):
    pass


@dataclass
class FieldMap:
    target: str
    sources: list[str]
    steps: list
    chains: dict = field(default_factory=dict)   # tokenizer kind -> compiled Chain

    def chain(self, kind: int) -> "transforms.Chain":
        c = self.chains.get(kind)
        if c is None:
            c = self.chains[kind] = transforms.Chain(KIND_DECODE.get(kind, []) + list(self.steps))
        return c


_UNMAPPED: dict[int, "transforms.Chain"] = {}


def unmapped_chain(kind: int) -> "transforms.Chain":
    """Unmapped fields only undo their wire encoding (JSON / CSV / CEF escapes)."""
    c = _UNMAPPED.get(kind)
    if c is None:
        c = _UNMAPPED[kind] = transforms.Chain(KIND_DECODE.get(kind, []))
    return c


@dataclass
class Pack:
    id: str
    version: str
    vendor: str
    product: str
    family: str
    source_name: str
    format: str
    fingerprint: re.Pattern
    spec: dict                              # compiled, handed to the tokenizer
    maps: list[FieldMap]
    constants: dict
    priority: int = 100
    digest: str = ""
    text: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return "%s@%s" % (self.id, self.version)


def load_pack(text: str) -> Pack:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PackError("invalid YAML: %s" % e) from e
    if not isinstance(doc, dict):
        raise PackError("pack must be a mapping")
    for key in ("id", "version", "format", "fingerprint"):
        if key not in doc:
            raise PackError("pack missing %r" % key)
    fmt = doc["format"]
    if fmt not in FORMATS:
        raise PackError("unknown format %r" % fmt)

    try:
        spec: dict = {"format": fmt}
        if doc.get("header"):
            spec["header"] = grok.expand(doc["header"])
        if fmt == "regex":
            pats = doc.get("patterns") or ([doc["pattern"]] if doc.get("pattern") else [])
            if not pats:
                raise PackError("regex pack needs patterns")
            spec["patterns"] = [grok.expand(p) for p in pats]
        if fmt == "csv":
            spec["columns"] = [str(c) for c in doc.get("columns", [])]
        if fmt == "leef":
            spec["delimiter"] = doc.get("delimiter", "\t")
        fingerprint = re.compile(doc["fingerprint"].encode())
    except (grok.GrokError, re.error) as e:
        raise PackError(str(e)) from e

    maps = []
    for target, m in (doc.get("map") or {}).items():
        if isinstance(m, str):
            m = {"from": m}
        sources = m["from"] if isinstance(m["from"], list) else [m["from"]]
        steps = m.get("transforms", [])
        try:
            for s in steps:
                transforms.parse_step(s)  # validate names now, not at runtime
        except transforms.TransformError as e:
            raise PackError("map %s: %s" % (target, e)) from e
        maps.append(FieldMap(target, [str(s) for s in sources], steps))

    return Pack(
        id=str(doc["id"]), version=str(doc["version"]), vendor=doc.get("vendor", ""),
        product=doc.get("product", ""), family=doc.get("family", doc.get("product", doc["id"])),
        source_name=doc.get("source_name", doc["id"]), format=fmt, fingerprint=fingerprint,
        spec=spec, maps=maps, constants=doc.get("constants", {}) or {},
        priority=int(doc.get("priority", 100)),
        digest="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(), text=text,
    )
