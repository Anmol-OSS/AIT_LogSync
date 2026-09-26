"""Deterministic synthetic log generators for the five perimeter source families.

    from logsync.generators import SOURCES, generate_lines
    lines = generate_lines("fortigate", count=100, seed=7)
"""
import random
from dataclasses import dataclass
from typing import Callable

from . import asa, checkpoint, fortigate, panos, suricata


@dataclass(frozen=True)
class Source:
    name: str          # sample file is samples/<name>.log
    family: str        # vendor / product family
    fmt: str           # wire format of the message body
    generate: Callable


SOURCES = {s.name: s for s in [
    Source("cisco_asa", "Cisco ASA", "syslog", asa.generate),
    Source("fortigate", "FortiGate", "key-value", fortigate.generate),
    Source("panos", "PAN-OS", "csv", panos.generate),
    Source("checkpoint_cef", "Check Point", "cef", checkpoint.generate_cef),
    Source("checkpoint_leef", "Check Point", "leef", checkpoint.generate_leef),
    Source("suricata", "Suricata IDS", "json", suricata.generate),
]}


def generate_lines(name: str, count: int, seed: int = 7) -> list[str]:
    """Return ``count`` log lines for source ``name``; same seed -> same lines."""
    # A string seed is hashed deterministically by random.Random (unlike hash()),
    # and gives each source its own independent stream.
    rng = random.Random("%d:%s" % (seed, name))
    gen = SOURCES[name].generate
    return [gen(rng, i) for i in range(count)]
