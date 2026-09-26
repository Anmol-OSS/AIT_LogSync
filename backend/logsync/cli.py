"""Command-line entry point:  logsync <command>  (or  python -m logsync <command>).

    serve    everything in one process: syslog ingest + worker + API + UI (memory bus)
    ingest   syslog listener publishing to Kafka           } the same pipeline split into
    worker   Kafka consumer: archive, parse, gate, index    } services (docker-compose)
    api      REST API + UI over the shared data directory   }
    replay   send synthetic device traffic over syslog
    archive  archive a file into the evidence store and prove a line
"""
import argparse
import logging
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _static_dir() -> Path | None:
    p = Path(os.environ.get("LOGSYNC_STATIC", REPO / "frontend" / "dist"))
    return p if (p / "index.html").exists() else None


def _forwarder():
    url = os.environ.get("LOGSYNC_FORWARD")
    if not url:
        return None
    from .pipeline.forwarder import SyslogForwarder
    return SyslogForwarder(url, os.environ.get("LOGSYNC_FORWARD_FORMAT", "json"))


def _synth(settings, processor=None):
    try:
        from .synth.loop import SynthesisLoop
    except ImportError:
        return None
    return SynthesisLoop(settings, processor=processor)


def _run_api(service, host: str, port: int) -> None:
    import uvicorn
    from .api.app import create_app
    uvicorn.run(create_app(service, static_dir=_static_dir()), host=host, port=port, log_level="warning")


def cmd_serve(args) -> int:
    from .api.live import LiveService
    from .config import Settings
    from .core.processor import Processor
    from .pipeline.bus import MemoryBus
    from .pipeline.ingest import SyslogServer
    from .pipeline.worker import Worker

    settings = Settings()
    bus = MemoryBus()
    processor = Processor(settings, forwarder=_forwarder())
    worker = Worker(processor, bus).start()
    ingest = SyslogServer(bus, args.host, args.syslog_port, tz=settings.default_tz).start()
    service = LiveService(settings, publish=bus.publish, synth=_synth(settings, processor))
    print("LogSync ULPF")
    print("  syslog ingest  udp+tcp %s:%d" % (args.host, args.syslog_port))
    print("  API + UI       http://%s:%d  (docs at /docs)" % (args.host, args.port))
    print("  data           %s   engine: %s" % (settings.data_dir.resolve(), processor.engine.name))
    if not _static_dir():
        print("  (UI not built: run `npm run build` in frontend/, or use `npm run dev` on :5173)")
    try:
        _run_api(service, args.host, args.port)
    finally:
        ingest.stop()
        worker.stop()
    return 0


def cmd_ingest(args) -> int:
    from .config import Settings
    from .pipeline.bus import KafkaBus, wait_for_kafka
    from .pipeline.ingest import SyslogServer

    wait_for_kafka(args.kafka)
    bus = KafkaBus(args.kafka)
    SyslogServer(bus, args.host, args.syslog_port, tz=Settings().default_tz).start()
    print("ingest: syslog %s:%d -> kafka %s" % (args.host, args.syslog_port, args.kafka), flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.wait(1):
            bus.flush(0)
    except KeyboardInterrupt:
        pass
    bus.close()
    return 0


def cmd_worker(args) -> int:
    from .config import Settings
    from .core.processor import Processor
    from .pipeline.bus import KafkaBus, wait_for_kafka
    from .pipeline.worker import Worker

    wait_for_kafka(args.kafka)
    bus = KafkaBus(args.kafka, consume=True)
    worker = Worker(Processor(Settings(), forwarder=_forwarder()), bus)
    print("worker: kafka %s -> evidence store %s" % (args.kafka, Settings().data_dir), flush=True)
    signal.signal(signal.SIGTERM, lambda *_: worker._stop.set())
    try:
        worker.run()
    except KeyboardInterrupt:
        worker.processor.flush()
    bus.close()
    return 0


def cmd_api(args) -> int:
    from .api.live import LiveService
    from .config import Settings

    settings = Settings()
    publish = None
    if args.kafka:
        from .pipeline.bus import KafkaBus
        publish = KafkaBus(args.kafka).publish
    _run_api(LiveService(settings, publish=publish, synth=_synth(settings)), args.host, args.port)
    return 0


def cmd_replay(args) -> int:
    from .pipeline.replay import replay
    sources = args.sources.split(",") if args.sources else None
    n = replay(args.target, rate=args.rate, count=args.count, sources=sources, proto=args.proto)
    print("replayed %d events" % n)
    return 0


def cmd_archive(args) -> int:
    """Archive every line of a file, seal a signed tree head, prove one line."""
    from .config import Settings
    from .storage.db import Database
    from .storage.evidence import EvidenceStore

    settings = Settings()
    ev = EvidenceStore(settings, Database(settings.db_path))
    lines = Path(args.file).read_bytes().splitlines()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    recorded = ev.record_many([("cli-%s-%d" % (Path(args.file).stem, i), now, raw) for i, raw in enumerate(lines)])
    head = ev.seal()
    print("archived %d lines into %s" % (len(lines), settings.data_dir / "archive"))
    print("signed tree head: size=%d root=%s" % (head.tree_size, head.root))
    print("RFC 3161 timestamp: %s" % (ev.tsa.describe(head.rfc3161) if head.rfc3161 else "unavailable"))
    i = min(args.prove, len(lines) - 1)
    sha, ref, idx = recorded[i]
    ok, detail = ev.check_inclusion("cli-%s-%d" % (Path(args.file).stem, i), now, ev.archive.get(ref), idx)
    print("line %d: %s -> %s" % (i, "VERIFIED" if ok else "FAILED", detail))
    return 0 if ok else 1


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="logsync", description="LogSync ULPF",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    kafka_default = os.environ.get("LOGSYNC_KAFKA", "localhost:9092")

    s = sub.add_parser("serve", help="ingest + worker + API + UI in one process")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--syslog-port", type=int, default=5514)

    s = sub.add_parser("ingest", help="syslog listener -> Kafka")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--syslog-port", type=int, default=5514)
    s.add_argument("--kafka", default=kafka_default)

    s = sub.add_parser("worker", help="Kafka -> archive, parse, gate, index")
    s.add_argument("--kafka", default=kafka_default)

    s = sub.add_parser("api", help="REST API + UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--kafka", default=os.environ.get("LOGSYNC_KAFKA"), help="publish HTTP ingest to Kafka")

    s = sub.add_parser("replay", help="send synthetic device traffic over syslog")
    s.add_argument("--target", default="127.0.0.1:5514")
    s.add_argument("--rate", type=float, default=200, help="events per second (0 = as fast as possible)")
    s.add_argument("--count", type=int, default=0, help="stop after N events (0 = run until Ctrl+C)")
    s.add_argument("--sources", help="comma-separated, default: all including juniper_srx")
    s.add_argument("--proto", choices=["tcp", "udp"], default="tcp")

    s = sub.add_parser("archive", help="archive a log file into the evidence store and prove a line")
    s.add_argument("file")
    s.add_argument("--prove", type=int, default=0, help="line number to prove (default 0)")

    args = p.parse_args(argv)
    return {"serve": cmd_serve, "ingest": cmd_ingest, "worker": cmd_worker, "api": cmd_api,
            "replay": cmd_replay, "archive": cmd_archive}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
