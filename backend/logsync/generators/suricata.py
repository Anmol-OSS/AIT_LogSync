"""Suricata IDS - EVE JSON events forwarded over syslog.

Mix of ``alert``, ``flow`` and ``dns`` event types, one compact JSON object per line.
"""
import json

from .common import ATTACKER_IPS, EXTERNAL_IPS, INTERNAL_IPS, ephemeral_port, event_time

FACILITY_LOCAL5 = 21
SIGNATURES = [  # (sid, signature, category, severity)
    (2010935, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2),
    (2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
    (2024364, "ET WEB_SERVER Possible SQL Injection Attempt", "Web Application Attack", 1),
]


def generate(rng, i: int) -> str:
    t = event_time(i)
    kind = rng.choice(("alert", "flow", "dns"))
    event = {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.") + "%06d+0530" % rng.randint(0, 999999),
        "flow_id": rng.getrandbits(50),
        "in_iface": "eth1",
        "event_type": kind,
    }
    if kind == "alert":
        sid, sig, cat, sev = rng.choice(SIGNATURES)
        event.update(src_ip=rng.choice(ATTACKER_IPS), src_port=ephemeral_port(rng),
                     dest_ip=rng.choice(INTERNAL_IPS), dest_port=rng.choice((22, 80, 1433)),
                     proto="TCP",
                     alert={"action": "allowed", "gid": 1, "signature_id": sid, "rev": 3,
                            "signature": sig, "category": cat, "severity": sev})
    elif kind == "flow":
        event.update(src_ip=rng.choice(INTERNAL_IPS), src_port=ephemeral_port(rng),
                     dest_ip=rng.choice(EXTERNAL_IPS), dest_port=443, proto="TCP",
                     app_proto="tls",
                     flow={"pkts_toserver": rng.randint(1, 500), "pkts_toclient": rng.randint(1, 500),
                           "bytes_toserver": rng.randint(60, 90000),
                           "bytes_toclient": rng.randint(60, 900000),
                           "state": "closed", "reason": "timeout"})
    else:
        event.update(src_ip=rng.choice(INTERNAL_IPS), src_port=ephemeral_port(rng),
                     dest_ip="8.8.8.8", dest_port=53, proto="UDP",
                     dns={"type": "query", "id": rng.randint(1, 65535),
                          "rrname": rng.choice(("example.com", "gov.in", "updates.vendor.net")),
                          "rrtype": "A"})
    severity = 1 if kind == "alert" else 6
    header = "<%d>%s ids01 suricata[2211]:" % (FACILITY_LOCAL5 * 8 + severity,
                                               t.strftime("%b %d %H:%M:%S"))
    return header + " " + json.dumps(event, separators=(",", ":"))
