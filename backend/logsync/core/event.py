"""Assemble the proof-carrying event (the JSON shape in frontend/src/types.ts)."""
from . import transforms
from .normalize import normalize
from .pack import Pack
from .tokenize import TokenResult

UNKNOWN_PARSER = {"pack_id": "none", "version": "-", "digest": "-"}


def build_event(*, event_id: str, received_at: str, source_host: str, raw: bytes, sha256: str,
                archive_ref: str, leaf_index: int, pack: Pack | None, tok: TokenResult | None,
                default_tz: str = "+05:30") -> dict:
    """Status is decided here:
        unparsed  no pack's fingerprint matched (dead-letter; raw still archived and sealed)
        blocked   a pack matched but structure, round-trip or a transform failed
        accepted  every byte explained and every declared transform succeeded
    """
    n = len(raw)
    event = {
        "event_id": event_id,
        "status": "unparsed",
        "received_at": received_at,
        "source": {"name": "unknown", "family": "Unknown", "format": "?", "host": source_host},
        "raw": {"text": raw.decode("utf-8", "replace"), "length": n,
                "sha256": "sha256:" + sha256, "archive_ref": archive_ref},
        "parser": dict(UNKNOWN_PARSER),
        "ues": None,
        "provenance": [],
        "roundtrip": {"status": "fail", "total_bytes": n, "field_bytes": 0, "unexplained": [[0, n]],
                      "reason": "no parser pack matches this format"},
        "merkle": {"leaf_index": leaf_index},
    }
    if pack is None or tok is None:
        return event

    event["source"].update(name=pack.source_name, family=pack.family, format=pack.format)
    event["parser"] = {"pack_id": pack.id, "version": pack.version, "digest": pack.digest}
    rt = event["roundtrip"]
    rt["field_bytes"] = sum(e - s for _, s, e, _ in tok.fields)
    rt["unexplained"] = tok.unexplained

    if not tok.ok:
        event["status"] = "blocked"
        rt.update(unexplained=[[0, n]], reason="structure did not match pack %s: %s" % (pack.ref, tok.error))
        return event
    if tok.unexplained:
        event["status"] = "blocked"
        count = sum(e - s for s, e in tok.unexplained)
        rt["reason"] = "%d byte%s not explained by pack %s" % (count, "" if count == 1 else "s", pack.ref)
        return event

    norm = normalize(pack, tok, raw, transforms.Context(received_at, default_tz))
    if norm.error:
        event["status"] = "blocked"
        rt.update(unexplained=[], reason="declared transform failed: %s" % norm.error)
        return event

    event.update(status="accepted", ues=norm.ues, provenance=norm.provenance)
    rt.update(status="pass", reason=None)
    return event
