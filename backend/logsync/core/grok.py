"""Grok -> regular expression expansion.

Packs (and the LLM) write patterns in grok syntax, e.g. %{IP:src_ip}. Expansion
happens once, here, so the Python reference parser and the WASM runtime run
the *same* regex. Every definition stays inside the syntax both Python `re`
and Rust `regex` accept (no look-around, no back-references).
"""
import re

PATTERNS = {
    "INT": r"[+-]?\d+",
    "POSINT": r"\d+",
    "NONNEGINT": r"\d+",
    "NUMBER": r"[+-]?\d+(?:\.\d+)?",
    "BASE16NUM": r"(?:0[xX])?[0-9A-Fa-f]+",
    "WORD": r"\w+",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s*",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "QUOTEDSTRING": r'"[^"]*"',
    "IPV4": r"(?:\d{1,3}\.){3}\d{1,3}",
    "IPV6": r"[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+",
    "IP": r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+)",
    "HOSTNAME": r"[A-Za-z0-9][A-Za-z0-9._-]*",
    "MAC": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
    "MONTH": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",
    "MONTHDAY": r"(?:[ 0-3]?\d)",
    "TIME": r"\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    "SYSLOGTIMESTAMP": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-3]\d \d{2}:\d{2}:\d{2}",
    "CISCOTIMESTAMP": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-3]\d(?: \d{4})? \d{2}:\d{2}:\d{2}",
    "TIMESTAMP_ISO8601": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    "SYSLOGPRI": r"<\d{1,3}>",
    "UUID": r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}",
}

_TOKEN = re.compile(r"%\{([A-Z0-9_]+)(?::([A-Za-z_][A-Za-z0-9_]*))?\}")


class GrokError(ValueError):
    pass


def expand(pattern: str) -> str:
    """Replace %{NAME} / %{NAME:field} with (?:...) / (?P<field>...)."""
    seen: set[str] = set()

    def repl(m: re.Match) -> str:
        name, field = m.group(1), m.group(2)
        if name not in PATTERNS:
            raise GrokError("unknown grok pattern %%{%s}" % name)
        body = PATTERNS[name]
        if not field:
            return "(?:%s)" % body
        if field in seen:
            raise GrokError("field %r captured twice" % field)
        seen.add(field)
        return "(?P<%s>%s)" % (field, body)

    out = _TOKEN.sub(repl, pattern)
    try:
        re.compile(out.encode())
    except re.error as e:
        raise GrokError("invalid pattern: %s" % e) from e
    return out


def field_names(pattern: str) -> list[str]:
    return [m.group(2) for m in _TOKEN.finditer(pattern) if m.group(2)]
