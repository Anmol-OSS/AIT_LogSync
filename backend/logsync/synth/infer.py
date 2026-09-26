"""Deterministic pack drafting from sample lines (the no-model fallback).

1. Recognise an RFC 3164 syslog header -> header grok with pri / ts / host.
2. Split the body on whitespace; positions that never change are literals.
3. Changing tokens are split further on punctuation (/ -> : , = ( ) [ ] ")
   when every sample splits the same way; each part gets a type (IP, INT,
   BASE16NUM, WORD, TOKEN) and a name taken from context (key=value keys,
   ip/port pairs) or f1, f2 ...
4. The first two IP[/port] groups are suggested as source and destination.

The result must fully match every sample; validation checks that.
"""
import re
from dataclasses import dataclass, field

from . import drain

SYSLOG_HEADER = re.compile(r"^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ")
HEADER_GROK = "<%{INT:pri}>%{SYSLOGTIMESTAMP:ts} %{HOSTNAME:host} "
SPLIT = re.compile(r'(->|[/:,=()\[\]"<>|])')
TYPES = [
    ("IPV4", re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")),
    ("INT", re.compile(r"\d+")),
    ("BASE16NUM", re.compile(r"0[xX][0-9A-Fa-f]+")),
    ("WORD", re.compile(r"\w+")),
]


@dataclass
class Candidate:
    header: str | None
    pattern: str                        # body pattern (grok)
    fingerprint: str                    # regex identifying the source
    suggestions: dict[str, str] = field(default_factory=dict)   # field -> UES target
    generator: str = "drain (deterministic fallback)"
    vendor: str = ""
    product: str = ""

    @property
    def full_pattern(self) -> str:
        return (self.header or "") + self.pattern


def _escape(s: str) -> str:
    return re.escape(s).replace("\\ ", " ")


def _type_of(values: list[str]) -> str:
    for name, rx in TYPES:
        if all(rx.fullmatch(v) for v in values):
            return name
    return "TOKEN"


def infer(lines: list[str]) -> Candidate:
    headers = [SYSLOG_HEADER.match(ln) for ln in lines]
    has_header = all(headers)
    bodies = [ln[m.end():] for ln, m in zip(lines, headers)] if has_header else list(lines)

    # use the dominant Drain template's members so every row has the same token count
    top = drain.cluster(bodies)[0]
    rows = [bodies[i].split(" ") for i in top.members]
    width = len(rows[0])
    rows = [r for r in rows if len(r) == width]

    parts: list[str] = []
    suggestions: dict[str, str] = {}
    literal_prefix: list[str] = []
    in_prefix = True
    counters = {"ip": 0, "port": 0, "f": 0}
    names: set[str] = set()

    def new_name(base: str) -> str:
        n = base
        k = 2
        while n in names:
            n = "%s_%d" % (base, k)
            k += 1
        names.add(n)
        return n

    for col in range(width):
        values = [r[col] for r in rows]
        if len(set(values)) == 1:
            parts.append(_escape(values[0]))
            if in_prefix:
                literal_prefix.append(values[0])
            continue
        in_prefix = False
        split = [SPLIT.split(v) for v in values]
        shape = [[p if i % 2 else None for i, p in enumerate(s)] for s in split]
        if all(s == shape[0] for s in shape) and len(split[0]) > 1:
            pieces = split[0]
            out = []
            last_ip = None
            for i in range(len(pieces)):
                col_vals = [s[i] for s in split]
                if i % 2:                                  # delimiter
                    out.append(_escape(pieces[i]))
                    continue
                if len(set(col_vals)) == 1:                # constant fragment
                    out.append(_escape(col_vals[0]))
                    continue
                t = _type_of(col_vals)
                prev = pieces[i - 1] if i else ""
                if t == "IPV4":
                    counters["ip"] += 1
                    name = new_name("ip%d" % counters["ip"])
                    last_ip = counters["ip"]
                    if counters["ip"] == 1:
                        suggestions[name] = "src_endpoint.ip"
                    elif counters["ip"] == 2:
                        suggestions[name] = "dst_endpoint.ip"
                elif t == "INT" and prev == "/" and last_ip:
                    name = new_name("port%d" % last_ip)
                    if last_ip == 1:
                        suggestions[name] = "src_endpoint.port"
                    elif last_ip == 2:
                        suggestions[name] = "dst_endpoint.port"
                else:
                    counters["f"] += 1
                    name = new_name("f%d" % counters["f"])
                out.append("%%{%s:%s}" % ("IP" if t == "IPV4" else t, name))
            parts.append("".join(out))
        else:
            counters["f"] += 1
            t = _type_of(values)
            if t == "TOKEN" and any(SPLIT.search(v) for v in values):
                t = "NOTSPACE"
            parts.append("%%{%s:%s}" % ("IP" if t == "IPV4" else t, new_name("f%d" % counters["f"])))

    header = HEADER_GROK if has_header else None
    if has_header:
        suggestions = {"ts": "time", "host": "device.hostname", **suggestions}
        fp = r"^<\d{1,3}>\w{3} [ \d]\d \d\d:\d\d:\d\d \S+ " + _escape(" ".join(literal_prefix[:3]))
    else:
        fp = "^" + _escape(" ".join(literal_prefix[:3]))
    return Candidate(header, " ".join(parts), fp, suggestions)
