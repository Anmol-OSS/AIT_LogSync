"""Fortinet FortiGate - key=value traffic logs sent over syslog (FortiOS 7.x style).

Values are bare (srcip=10.2.1.7) or double-quoted (devname="FG100E").
"""
from .common import EXTERNAL_IPS, INTERNAL_IPS, PROTO_NUM, SERVICES, ephemeral_port, event_time

FACILITY_LOCAL7 = 23


def generate(rng, i: int) -> str:
    t = event_time(i)
    service, proto, dport = rng.choice(SERVICES)
    action = rng.choice(("accept", "accept", "close", "deny"))
    level = "warning" if action == "deny" else "notice"
    severity = 4 if action == "deny" else 5
    return (
        '<%d>date=%s time=%s devname="FG100E" devid="FG100E4Q17000123" '
        'eventtime=%d tz="+0530" logid="0000000013" type="traffic" subtype="forward" '
        'level="%s" vd="root" srcip=%s srcport=%d srcintf="port1" srcintfrole="lan" '
        'dstip=%s dstport=%d dstintf="wan1" dstintfrole="wan" sessionid=%d proto=%d '
        'action="%s" policyid=%d policytype="policy" service="%s" duration=%d '
        'sentbyte=%d rcvdbyte=%d sentpkt=%d rcvdpkt=%d'
        % (FACILITY_LOCAL7 * 8 + severity, t.strftime("%Y-%m-%d"), t.strftime("%H:%M:%S"),
           int(t.timestamp()) * 10**9, level, rng.choice(INTERNAL_IPS), ephemeral_port(rng),
           rng.choice(EXTERNAL_IPS), dport, rng.randint(10000, 9999999), PROTO_NUM[proto],
           action, rng.randint(1, 40), service, rng.randint(0, 3600),
           rng.randint(60, 90000), rng.randint(60, 900000), rng.randint(1, 900),
           rng.randint(1, 900))
    )
