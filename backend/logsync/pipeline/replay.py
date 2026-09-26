"""Replay synthetic perimeter traffic over syslog - the demo's "devices".

    logsync replay --rate 200 --target 127.0.0.1:5514
    logsync replay --sources fortigate,juniper_srx --count 500 --proto udp

Lines come from the deterministic generators, round-robin across sources, so
every family appears in the stream. juniper_srx has no pack: it is the
unknown device whose lines land in the dead-letter queue.
"""
import itertools
import socket
import time

from ..generators import SOURCES, generate_lines


def lines_forever(sources: list[str], seed: int = 7, chunk: int = 2000):
    """Endless round-robin stream; each chunk uses a new seed so lines keep changing."""
    for round_no in itertools.count():
        streams = [iter(generate_lines(s, chunk, seed + round_no)) for s in sources]
        for group in zip(*streams):
            yield from (ln.encode() for ln in group)


def replay(target: str, rate: float = 200, count: int = 0, sources: list[str] | None = None,
           proto: str = "tcp", quiet: bool = False) -> int:
    host, port = target.rsplit(":", 1)
    sources = sources or list(SOURCES)
    sent = 0
    interval = 1.0 / rate if rate > 0 else 0
    sock = socket.create_connection((host, int(port))) if proto == "tcp" \
        else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start = time.monotonic()
    try:
        for ln in lines_forever(sources):
            if proto == "tcp":
                sock.sendall(b"%d %s" % (len(ln), ln))
            else:
                sock.sendto(ln, (host, int(port)))
            sent += 1
            if count and sent >= count:
                break
            if interval:
                ahead = start + sent * interval - time.monotonic()
                if ahead > 0:
                    time.sleep(ahead)
            if not quiet and sent % 1000 == 0:
                print("sent %d events (%.0f/s)" % (sent, sent / (time.monotonic() - start)), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return sent
