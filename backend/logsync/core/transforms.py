"""Declared transformations: raw source text -> normalized UES value.

A pack declares, per field, an ordered list of transforms. Each one is
recorded in the event's provenance, and the Verification API re-runs the
same chain on the archived bytes, so every normalized value is reproducible.

In a pack a transform is either a name ("ipv4") or a one-key mapping
({"lookup": {"accept": "Allowed"}}, {"strptime": "%b %d %Y %H:%M:%S"}).
"""
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class TransformError(ValueError):
    pass


@dataclass
class Context:
    received_at: str          # ISO 8601 receive time, used for the year of RFC 3164 stamps
    default_tz: str = "+05:30"


def _tz(offset: str) -> timezone:
    sign = -1 if offset.startswith("-") else 1
    hh, mm = offset.lstrip("+-").replace(":", "")[:2], offset.lstrip("+-").replace(":", "")[2:4] or "00"
    return timezone(sign * timedelta(hours=int(hh), minutes=int(mm)))


def _need_str(v, name):
    if not isinstance(v, str):
        raise TransformError("%s expects text" % name)
    return v


def t_trim(v, arg, ctx): return _need_str(v, "trim").strip()
def t_lower(v, arg, ctx): return _need_str(v, "lower").lower()
def t_upper(v, arg, ctx): return _need_str(v, "upper").upper()


def t_int(v, arg, ctx):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise TransformError("not an integer: %r" % v)


def t_float(v, arg, ctx):
    try:
        return float(v)
    except (TypeError, ValueError):
        raise TransformError("not a number: %r" % v)


def t_to_string(v, arg, ctx): return str(v)


def t_ip(v, arg, ctx):
    try:
        return str(ipaddress.ip_address(_need_str(v, "ip").strip()))
    except ValueError:
        raise TransformError("not an IP address: %r" % v)


def t_json_string(v, arg, ctx):
    try:
        return json.loads('"%s"' % v)
    except json.JSONDecodeError:
        raise TransformError("bad JSON string escape")


def t_csv_unquote(v, arg, ctx): return _need_str(v, "csv_unquote").replace('""', '"')


def t_cef_unescape(v, arg, ctx):
    s, out, i = _need_str(v, "cef_unescape"), [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append({"n": "\n", "r": "\r"}.get(nxt, nxt))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def t_lookup(v, table, ctx):
    key = str(v)
    if key in table:
        return table[key]
    if "*" in table:
        return table["*"]
    raise TransformError("no lookup entry for %r" % key)


def _epoch(v, divisor):
    try:
        return datetime.fromtimestamp(int(v) / divisor, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        raise TransformError("bad epoch value %r" % v)


def t_epoch_s(v, arg, ctx): return _epoch(v, 1)
def t_epoch_ms(v, arg, ctx): return _epoch(v, 1_000)
def t_epoch_ns(v, arg, ctx): return _epoch(v, 1_000_000_000)


def t_strptime(v, fmt, ctx):
    try:
        return datetime.strptime(_need_str(v, "strptime"), fmt)
    except ValueError:
        raise TransformError("time %r does not match %r" % (v, fmt))


def t_rfc3164(v, arg, ctx):
    """'Sep 25 09:00:00' has no year: take it from the receive time (declared assumption)."""
    year = ctx.received_at[:4]
    try:
        return datetime.strptime("%s %s" % (year, " ".join(_need_str(v, "rfc3164").split())), "%Y %b %d %H:%M:%S")
    except ValueError:
        raise TransformError("not an RFC 3164 timestamp: %r" % v)


def t_iso8601(v, arg, ctx):
    s = _need_str(v, "iso8601")
    if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":   # +0530 -> +05:30
        s = s[:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise TransformError("not ISO 8601: %r" % v)


def t_tz(v, offset, ctx):
    """Attach a timezone to a naive time, or convert an aware one; default: LOGSYNC_TZ."""
    if not isinstance(v, datetime):
        raise TransformError("tz expects a time")
    tz = _tz(offset or ctx.default_tz)
    return v.replace(tzinfo=tz) if v.tzinfo is None else v.astimezone(tz)


IANA = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "ipv6-icmp"}


def t_iana_proto(v, arg, ctx):
    return IANA.get(str(v).strip(), str(v).strip().lower())


REGISTRY = {
    "trim": t_trim, "lower": t_lower, "upper": t_upper, "int": t_int, "float": t_float,
    "to_string": t_to_string, "ip": t_ip, "ipv4": t_ip, "json_string": t_json_string,
    "csv_unquote": t_csv_unquote, "cef_unescape": t_cef_unescape, "lookup": t_lookup,
    "epoch_s": t_epoch_s, "epoch_ms": t_epoch_ms, "epoch_ns": t_epoch_ns,
    "strptime": t_strptime, "rfc3164": t_rfc3164, "iso8601": t_iso8601, "tz": t_tz,
    "iana_proto": t_iana_proto,
}


def parse_step(step) -> tuple[str, object]:
    if isinstance(step, str):
        name, arg = step, None
    elif isinstance(step, dict) and len(step) == 1:
        (name, arg), = step.items()
    else:
        raise TransformError("bad transform %r" % (step,))
    if name not in REGISTRY:
        raise TransformError("unknown transform %r" % name)
    return name, arg


def describe(step) -> str:
    """Short label for provenance, e.g. 'lookup(accept→Allowed, deny→Blocked)'."""
    name, arg = parse_step(step)
    if arg is None:
        return name
    if isinstance(arg, dict):
        return "%s(%s)" % (name, ", ".join("%s→%s" % kv for kv in arg.items()))
    return "%s(%s)" % (name, arg)


class Chain:
    """A transform list parsed once (at pack load), applied many times."""

    def __init__(self, steps: list):
        parsed = [parse_step(s) for s in steps]
        self.calls = [(REGISTRY[name], arg) for name, arg in parsed]
        self.labels = ["utf8_decode"] + [describe(s) for s in steps]

    def run(self, text: str, ctx: Context):
        value = text
        for fn, arg in self.calls:
            value = fn(value, arg, ctx)
        if isinstance(value, datetime):
            value = value.isoformat()
        return value


def apply(steps: list, text: str, ctx: Context):
    return Chain(steps).run(text, ctx)
