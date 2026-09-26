"""Shared building blocks for the synthetic perimeter-log generators.

Every generator is a function ``generate(rng, i) -> str`` that returns ONE log
line (no trailing newline) for event number ``i``. All randomness comes from the
``random.Random`` instance passed in, so the same seed always produces the same
bytes - tests and the demo depend on that.
"""
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))

# Events start here and advance 1-3 seconds each, so timestamps look like a
# real stream instead of all being identical.
BASE_TIME = datetime(2026, 9, 25, 9, 0, 0, tzinfo=IST)

INTERNAL_IPS = ["10.2.1.7", "10.20.30.40", "192.168.4.11", "172.16.9.2", "10.55.3.90"]
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "142.250.183.14", "52.95.110.1", "13.107.42.14"]
ATTACKER_IPS = ["203.0.113.5", "198.51.100.23", "192.0.2.77"]  # RFC 5737 documentation ranges

SERVICES = [  # (name, protocol, port)
    ("DNS", "udp", 53),
    ("HTTP", "tcp", 80),
    ("HTTPS", "tcp", 443),
    ("SSH", "tcp", 22),
    ("HTTPS-ALT", "tcp", 8443),
]

PROTO_NUM = {"tcp": 6, "udp": 17}


def event_time(i: int) -> datetime:
    """Deterministic timestamp for event ``i`` (roughly 2 seconds apart)."""
    return BASE_TIME + timedelta(seconds=i * 2 + (i % 3))


def ephemeral_port(rng) -> int:
    return rng.randint(1024, 65535)
