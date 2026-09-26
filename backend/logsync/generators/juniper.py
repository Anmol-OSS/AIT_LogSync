"""Juniper SRX - RT_FLOW session logs (BSD syslog format).

No parser pack ships for this family: it is the "unknown device" that lands in
the dead-letter queue until the self-evolving parser loop onboards it.
"""
from .common import EXTERNAL_IPS, INTERNAL_IPS, SERVICES, ephemeral_port, event_time

FACILITY_USER = 1
APPS = {"DNS": "junos-dns-udp", "HTTP": "junos-http", "HTTPS": "junos-https", "SSH": "junos-ssh",
        "HTTPS-ALT": "junos-https"}
PROTO = {"tcp": 6, "udp": 17}


def generate(rng, i: int) -> str:
    t = event_time(i)
    service, proto, dport = rng.choice(SERVICES)
    src, dst = rng.choice(INTERNAL_IPS), rng.choice(EXTERNAL_IPS)
    policy = "allow-dns" if service == "DNS" else "allow-web"
    return ("<%d>%s srx-edge01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created "
            "%s/%d->%s/%d 0x0 %s 203.0.113.10/%d->%s/%d 0x0 source-nat-rule-1 N/A N/A %d %s "
            "trust untrust %d N/A(N/A) ge-0/0/1.0"
            % (FACILITY_USER * 8 + 6, t.strftime("%b %d %H:%M:%S"), src, ephemeral_port(rng), dst,
               dport, APPS[service], ephemeral_port(rng), dst, dport, PROTO[proto], policy,
               rng.randint(40000, 99999)))
