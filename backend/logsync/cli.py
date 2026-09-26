"""Command-line entry point:  logsync <command>  (or  python -m logsync <command>)."""
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def cmd_archive(args) -> int:
    """Archive every line of a file, seal a signed tree head, prove one line."""
    from .config import Settings
    from .storage.db import Database
    from .storage.evidence import EvidenceStore

    settings = Settings()
    ev = EvidenceStore(settings, Database(settings.db_path))
    lines = Path(args.file).read_bytes().splitlines()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    recorded = []
    for i, raw in enumerate(lines):
        eid = "cli-%s-%d" % (Path(args.file).stem, i)
        recorded.append((eid, raw, ev.record(eid, now, raw)))
    head = ev.seal()
    print("archived %d lines into %s" % (len(lines), settings.data_dir / "archive"))
    print("signed tree head: size=%d root=%s" % (head.tree_size, head.root))
    print("RFC 3161 timestamp: %s" % (ev.tsa.describe(head.rfc3161) if head.rfc3161 else "unavailable"))
    eid, raw, (sha, ref, idx) = recorded[min(args.prove, len(recorded) - 1)]
    ok, detail = ev.check_inclusion(eid, now, ev.archive.get(ref), idx)
    print("line %d: %s -> %s" % (args.prove, "VERIFIED" if ok else "FAILED", detail))
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="logsync", description="LogSync ULPF")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("api", help="run the REST API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)

    s = sub.add_parser("archive", help="archive a log file into the evidence store and prove a line")
    s.add_argument("file")
    s.add_argument("--prove", type=int, default=0, help="line number to prove (default 0)")

    args = p.parse_args(argv)
    if args.cmd == "api":
        import uvicorn
        uvicorn.run("logsync.api.app:app", host=args.host, port=args.port)
        return 0
    if args.cmd == "archive":
        return cmd_archive(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
