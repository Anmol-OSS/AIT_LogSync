"""Reference tokenizer - the Python twin of the Rust/WASM runtime (runtime/src/lib.rs).

Given a compiled pack spec and the raw bytes of one event it returns:

    ok          did the format's structure match at all?
    fields      [name, start, end, kind]  value byte spans, sorted
    unexplained [[start, end], ...]       bytes neither grammar nor any field accounts for

Every byte of the line is either structure (delimiters, keys, literal pattern
text - explained by the grammar), inside a field, or reported as unexplained.
That is what the round-trip gate checks.

kind: 0 plain, 1 JSON string (escaped), 2 CSV quoted ("" escaped), 3 CEF value (\\ escaped)

The two implementations must agree byte for byte; tests/test_wasm.py runs a
differential test over the whole sample corpus. Keep the algorithms in sync.
"""
import re
from dataclasses import dataclass, field

PLAIN, JSON_STRING, CSV_QUOTED, CEF_ESCAPED = 0, 1, 2, 3

CEF_HEADER = ["cef.version", "cef.vendor", "cef.product", "cef.device_version",
              "cef.signature_id", "cef.name", "cef.severity"]
LEEF_HEADER = ["leef.version", "leef.vendor", "leef.product", "leef.product_version", "leef.event_id"]
_KV_KEY = re.compile(rb"[A-Za-z0-9_.\-]+=")
_CEF_KEY = re.compile(rb"[A-Za-z0-9_]+=")


@dataclass
class TokenResult:
    ok: bool
    fields: list[list] = field(default_factory=list)       # [name, start, end, kind]
    unexplained: list[list[int]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {"ok": self.ok, "fields": self.fields, "unexplained": self.unexplained, "error": self.error}


class _Fail(Exception):
    pass


def _regex(pattern: str, cache: dict = {}) -> re.Pattern:
    r = cache.get(pattern)
    if r is None:
        r = cache[pattern] = re.compile(pattern.encode())
    return r


def _groups(m: re.Match, out: list) -> None:
    for name, (s, e) in ((n, m.span(n)) for n in m.re.groupindex):
        if s >= 0:
            out.append([name, s, e, PLAIN])


def tokenize(spec: dict, data: bytes) -> TokenResult:
    fields: list = []
    unexplained: list = []
    n = len(data)
    try:
        pos = 0
        if spec.get("header"):
            m = _regex(spec["header"]).match(data, 0)
            if not m:
                raise _Fail("header did not match")
            _groups(m, fields)
            pos = m.end()
        fmt = spec["format"]
        if fmt == "regex":
            _regex_body(spec["patterns"], data, pos, fields, unexplained)
        elif fmt == "kv":
            _kv(data, pos, fields, unexplained)
        elif fmt == "csv":
            _csv(spec.get("columns", []), data, pos, fields, unexplained)
        elif fmt == "cef":
            _cef(data, pos, fields, unexplained)
        elif fmt == "leef":
            _leef(spec.get("delimiter", "\t").encode(), data, pos, fields, unexplained)
        elif fmt == "json":
            _json_body(data, pos, fields, unexplained)
        else:
            raise _Fail("unknown format %r" % fmt)
    except _Fail as e:
        return TokenResult(False, error=str(e))
    fields.sort(key=lambda f: (f[1], f[2], f[0]))
    return TokenResult(True, fields, unexplained)


# ---------------------------------------------------------------- regex
def _regex_body(patterns, data, pos, fields, unexplained):
    """First pattern matching the whole rest of the line wins; otherwise the
    longest partial match (earliest pattern on ties) and the rest is unexplained."""
    n = len(data)
    best = None
    for p in patterns:
        m = _regex(p).match(data, pos)
        if m is None:
            continue
        if m.end() == n:
            _groups(m, fields)
            return
        if best is None or m.end() > best.end():
            best = m
    if best is None:
        raise _Fail("no pattern matched")
    _groups(best, fields)
    unexplained.append([best.end(), n])


# ---------------------------------------------------------------- key=value
def _kv(data, pos, fields, unexplained):
    n = len(data)
    while pos < n:
        if data[pos] == 0x20:          # ' ' separator
            pos += 1
            continue
        m = _KV_KEY.match(data, pos)
        if not m:
            unexplained.append([pos, n])
            return
        key = data[pos:m.end() - 1].decode("latin-1")
        pos = m.end()
        if pos < n and data[pos] == 0x22:  # '"'
            q = data.find(b'"', pos + 1)
            if q < 0:
                unexplained.append([m.start(), n])
                return
            fields.append([key, pos + 1, q, PLAIN])
            pos = q + 1
        else:
            end = data.find(b" ", pos)
            end = n if end < 0 else end
            fields.append([key, pos, end, PLAIN])
            pos = end


# ---------------------------------------------------------------- CSV
def _csv(columns, data, pos, fields, unexplained):
    n = len(data)
    col = 0
    while True:
        name = columns[col] if col < len(columns) else "col%d" % col
        if pos < n and data[pos] == 0x22:
            i = pos + 1
            while i < n:
                if data[i] == 0x22:
                    if i + 1 < n and data[i + 1] == 0x22:
                        i += 2
                        continue
                    break
                i += 1
            if i >= n:
                unexplained.append([pos, n])
                return
            fields.append([name, pos + 1, i, CSV_QUOTED])
            pos = i + 1
        else:
            end = data.find(b",", pos)
            end = n if end < 0 else end
            fields.append([name, pos, end, PLAIN])
            pos = end
        col += 1
        if pos >= n:
            return
        if data[pos] == 0x2C:  # ','
            pos += 1
            continue
        unexplained.append([pos, n])
        return


# ---------------------------------------------------------------- CEF
def _unescaped(data, byte, start):
    """Index of the next `byte` not preceded by a backslash, or -1."""
    i = data.find(byte, start)
    while i > 0 and data[i - 1] == 0x5C:
        i = data.find(byte, i + 1)
    return i


def _cef(data, pos, fields, unexplained):
    n = len(data)
    if not data.startswith(b"CEF:", pos):
        raise _Fail("not a CEF message")
    pos += 4
    for name in CEF_HEADER:
        bar = _unescaped(data, b"|", pos)
        if bar < 0:
            raise _Fail("CEF header truncated at %s" % name)
        fields.append([name, pos, bar, CEF_ESCAPED])
        pos = bar + 1
    keys = []
    for i in range(pos, n):
        if i == pos or data[i - 1] == 0x20:
            m = _CEF_KEY.match(data, i)
            if m:
                keys.append((data[i:m.end() - 1].decode("latin-1"), i, m.end()))
    if not keys:
        if pos < n:
            unexplained.append([pos, n])
        return
    if keys[0][1] != pos:
        unexplained.append([pos, keys[0][1]])
    for j, (key, _, vstart) in enumerate(keys):
        vend = keys[j + 1][1] - 1 if j + 1 < len(keys) else n
        fields.append([key, vstart, vend, CEF_ESCAPED])


# ---------------------------------------------------------------- LEEF 1.0
def _leef(delim, data, pos, fields, unexplained):
    n = len(data)
    if not data.startswith(b"LEEF:", pos):
        raise _Fail("not a LEEF message")
    pos += 5
    for name in LEEF_HEADER:
        bar = data.find(b"|", pos)
        if bar < 0:
            raise _Fail("LEEF header truncated at %s" % name)
        fields.append([name, pos, bar, PLAIN])
        pos = bar + 1
    while pos < n:
        end = data.find(delim, pos)
        end = n if end < 0 else end
        if end > pos:
            eq = data.find(b"=", pos, end)
            if eq < 0:
                unexplained.append([pos, end])
            else:
                fields.append([data[pos:eq].decode("latin-1"), eq + 1, end, PLAIN])
        pos = end + len(delim)


# ---------------------------------------------------------------- JSON
_WS = b" \t\r\n"


def _json_body(data, pos, fields, unexplained):
    n = len(data)
    pos = _ws(data, pos)
    if pos >= n or data[pos] != 0x7B:
        raise _Fail("JSON body must be an object")
    pos = _ws(data, _jvalue(data, pos, "", fields))
    if pos < n:
        unexplained.append([pos, n])


def _ws(data, pos):
    while pos < len(data) and data[pos] in _WS:
        pos += 1
    return pos


def _jstring_end(data, pos):
    """pos at opening quote; returns index of the closing quote."""
    i = pos + 1
    n = len(data)
    while i < n:
        c = data[i]
        if c == 0x5C:
            i += 2
            continue
        if c == 0x22:
            return i
        i += 1
    raise _Fail("unterminated JSON string")


def _join(path, key):
    return key if not path else path + "." + key


def _jvalue(data, pos, path, fields):
    n = len(data)
    pos = _ws(data, pos)
    if pos >= n:
        raise _Fail("unexpected end of JSON")
    c = data[pos]
    if c == 0x7B:  # {
        pos = _ws(data, pos + 1)
        if pos < n and data[pos] == 0x7D:
            return pos + 1
        while True:
            pos = _ws(data, pos)
            if pos >= n or data[pos] != 0x22:
                raise _Fail("expected JSON key")
            kend = _jstring_end(data, pos)
            key = data[pos + 1:kend].decode("utf-8", "replace")
            pos = _ws(data, kend + 1)
            if pos >= n or data[pos] != 0x3A:
                raise _Fail("expected ':'")
            pos = _ws(data, _jvalue(data, pos + 1, _join(path, key), fields))
            if pos < n and data[pos] == 0x2C:
                pos += 1
                continue
            if pos < n and data[pos] == 0x7D:
                return pos + 1
            raise _Fail("expected ',' or '}'")
    if c == 0x5B:  # [
        pos = _ws(data, pos + 1)
        if pos < n and data[pos] == 0x5D:
            return pos + 1
        i = 0
        while True:
            pos = _ws(data, _jvalue(data, pos, _join(path, str(i)), fields))
            i += 1
            if pos < n and data[pos] == 0x2C:
                pos += 1
                continue
            if pos < n and data[pos] == 0x5D:
                return pos + 1
            raise _Fail("expected ',' or ']'")
    if c == 0x22:
        end = _jstring_end(data, pos)
        fields.append([path, pos + 1, end, JSON_STRING])
        return end + 1
    start = pos
    while pos < n and data[pos] not in b",}] \t\r\n":
        pos += 1
    token = data[start:pos]
    if token in (b"true", b"false", b"null") or re.fullmatch(rb"-?\d+(\.\d+)?([eE][+-]?\d+)?", token):
        fields.append([path, start, pos, PLAIN])
        return pos
    raise _Fail("invalid JSON value")
