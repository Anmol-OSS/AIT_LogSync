"""Cisco ASA - RFC 3164 syslog with %ASA-<sev>-<msgid> messages.

Three common message IDs:
  106100  access-list permitted/denied (the example on our slide 2)
  106023  packet denied by access-group
  302013  built inbound/outbound TCP connection
"""
from .common import ATTACKER_IPS, EXTERNAL_IPS, INTERNAL_IPS, SERVICES, ephemeral_port, event_time

# RFC 3164 PRI = facility * 8 + severity. ASA default facility is local4 (20).
FACILITY_LOCAL4 = 20


def _header(i: int, severity: int) -> str:
    ts = event_time(i).strftime("%b %d %H:%M:%S")
    return "<%d>%s fw01" % (FACILITY_LOCAL4 * 8 + severity, ts)


def generate(rng, i: int) -> str:
    kind = rng.choice(("106100", "106100", "106023", "302013"))
    src, dst = rng.choice(INTERNAL_IPS), rng.choice(EXTERNAL_IPS)
    _, proto, dport = rng.choice(SERVICES)
    sport = ephemeral_port(rng)

    if kind == "106100":
        verb = rng.choice(("permitted", "permitted", "denied"))
        sev = 6 if verb == "permitted" else 4
        return ("%s %%ASA-%d-106100: access-list outside_acl %s %s inside/%s(%d) -> "
                "outside/%s(%d) hit-cnt %d first hit [0x%08x, 0x0]"
                % (_header(i, sev), sev, verb, proto, src, sport, dst, dport,
                   rng.randint(1, 500), rng.getrandbits(32)))

    if kind == "106023":
        attacker = rng.choice(ATTACKER_IPS)
        return ('%s %%ASA-4-106023: Deny %s src outside:%s/%d dst inside:%s/%d '
                'by access-group "outside_acl" [0x0, 0x0]'
                % (_header(i, 4), proto, attacker, sport, src, dport))

    conn_id = rng.randint(100000, 999999)
    return ("%s %%ASA-6-302013: Built outbound TCP connection %d for outside:%s/%d (%s/%d) "
            "to inside:%s/%d (%s/%d)"
            % (_header(i, 6), conn_id, dst, dport, dst, dport, src, sport, src, sport))
