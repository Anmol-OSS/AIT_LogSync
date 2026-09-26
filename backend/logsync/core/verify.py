"""Verification: start from the archived bytes and re-check the whole proof chain.

Nothing stored about the event is trusted. Each check recomputes from:
the archived bytes, the signed pack that produced the event, and the signed
Merkle tree head.
"""
import hashlib

from ..storage.evidence import EvidenceStore
from .engine import Engine
from .event import build_event
from .registry import Registry


def _check(name, ok, detail):
    return {"name": name, "status": "pass" if ok else "fail", "detail": detail}


def verify_event(event: dict, evidence: EvidenceStore, registry: Registry, engine: Engine,
                 default_tz: str = "+05:30") -> dict:
    checks = []
    expected_sha = event["raw"]["sha256"].removeprefix("sha256:")
    ref = event["raw"]["archive_ref"]
    try:
        archived = evidence.archive.get(ref)
    except (OSError, ValueError, IndexError) as e:
        archived = b""
        checks.append(_check("archive_integrity", False, "archive unreadable: %s" % e))
    actual_sha = hashlib.sha256(archived).hexdigest()
    tampered = actual_sha != expected_sha
    if not checks:
        checks.append(_check(
            "archive_integrity", not tampered,
            "archived bytes hash to sha256:%s…" % actual_sha[:16] if not tampered
            else "expected sha256:%s… got sha256:%s…" % (expected_sha[:16], actual_sha[:16])))

    # 2. parser integrity: the exact signed pack version that produced this event
    pk = event["parser"]
    pack = registry.get(pk["pack_id"], pk["version"]) if pk["pack_id"] != "none" else None
    if pk["pack_id"] == "none":
        checks.append(_check("parser_integrity", True, "no parser applied (unparsed event)"))
    elif pack is None:
        checks.append(_check("parser_integrity", False, "pack %s@%s not in registry" % (pk["pack_id"], pk["version"])))
    elif pack.digest != pk["digest"]:
        checks.append(_check("parser_integrity", False, "pack digest changed since the event was parsed"))
    elif not registry.is_signed(pack):
        checks.append(_check("parser_integrity", False, "pack signature invalid"))
    else:
        checks.append(_check("parser_integrity", True, "%s digest matches signed pack" % pack.ref))

    # 3 + 4. re-parse the archived bytes and compare with what the event claims
    tok = engine.tokenize(pack.spec, archived) if pack else None
    redo = build_event(event_id=event["event_id"], received_at=event["received_at"],
                       source_host=event["source"]["host"], raw=archived, sha256=actual_sha,
                       archive_ref=ref, leaf_index=event["merkle"]["leaf_index"],
                       pack=pack, tok=tok, default_tz=default_tz)
    mapped = [p for p in event["provenance"] if p["bytes"]]
    if not mapped:
        checks.append(_check("provenance_integrity", redo["provenance"] == event["provenance"],
                             "no normalized fields to re-derive (%s event)" % event["status"]))
    else:
        redo_by_field = {p["field"]: p for p in redo["provenance"]}
        bad = next((p for p in mapped if redo_by_field.get(p["field"]) != p), None)
        if bad is None and len(redo["provenance"]) == len(event["provenance"]) and redo["ues"] == event["ues"]:
            checks.append(_check("provenance_integrity", True,
                                 "%d of %d fields re-derived from their byte ranges" % (len(mapped), len(mapped))))
        else:
            if bad is None:
                bad = mapped[0]
            s, e = bad["bytes"]
            now = archived[s:e].decode("utf-8", "replace")
            checks.append(_check("provenance_integrity", False,
                                 "%s: bytes[%d:%d] now read %s, event says %s" % (bad["field"], s, e, now, bad["raw"])))

    rt_ok = (redo["status"] == event["status"] and redo["roundtrip"]["unexplained"] == event["roundtrip"]["unexplained"])
    if event["status"] == "accepted":
        detail = "all %d bytes explained by pack" % len(archived) if rt_ok \
            else "re-parse no longer explains every byte: %s" % (redo["roundtrip"].get("reason") or redo["status"])
    else:
        detail = ("re-parse reproduces the recorded %s decision" % event["status"]) if rt_ok \
            else "re-parse disagrees with recorded %s decision" % event["status"]
    checks.append(_check("roundtrip_integrity", rt_ok, detail))

    # 5. Merkle inclusion against the signed tree head
    ok, detail = evidence.check_inclusion(event["event_id"], event["received_at"], archived,
                                          event["merkle"]["leaf_index"])
    checks.append(_check("merkle_integrity", ok, detail))

    report = {"event_id": event["event_id"], "tampered": tampered,
              "overall": "verified" if all(c["status"] == "pass" for c in checks) else "failed",
              "checks": checks}
    if tampered:
        original = event["raw"]["text"].encode("utf-8")
        diff = next((i for i, (a, b) in enumerate(zip(original, archived)) if a != b),
                    min(len(original), len(archived)))
        report.update(tampered_byte=diff, tampered_raw=archived.decode("utf-8", "replace"))
    return report
