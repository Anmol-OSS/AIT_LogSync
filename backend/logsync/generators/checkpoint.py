"""Check Point - Log Exporter output in CEF and LEEF, sent over syslog.

CEF:  CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value ...
      Extension values may contain spaces; '=' and '\\' inside values are escaped.
LEEF: LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>key=value ...
"""
from .common import ATTACKER_IPS, EXTERNAL_IPS, INTERNAL_IPS, SERVICES, ephemeral_port, event_time

FACILITY_LOCAL0 = 16
VENDOR, PRODUCT, VERSION = "Check Point", "VPN-1 & FireWall-1", "R81.20"
RULES = ["Allow Web", "Allow DNS", "Block Inbound", "Cleanup rule"]


def _flow(rng):
    service, proto, dport = rng.choice(SERVICES)
    action = rng.choice(("Accept", "Accept", "Drop", "Reject"))
    inbound = action != "Accept"
    src = rng.choice(ATTACKER_IPS) if inbound else rng.choice(INTERNAL_IPS)
    dst = rng.choice(INTERNAL_IPS) if inbound else rng.choice(EXTERNAL_IPS)
    rule = "Block Inbound" if inbound else rng.choice(RULES[:2])
    return service, proto, dport, action, src, dst, rule


def _header(i: int, action: str) -> str:
    severity = 6 if action == "Accept" else 4
    return "<%d>%s gw-cp01" % (FACILITY_LOCAL0 * 8 + severity, event_time(i).strftime("%b %d %H:%M:%S"))


def generate_cef(rng, i: int) -> str:
    service, proto, dport, action, src, dst, rule = _flow(rng)
    severity = "Low" if action == "Accept" else "Medium"
    ext = ("act=%s rt=%d src=%s spt=%d dst=%s dpt=%d proto=%s app=%s "
           "cs1Label=Rule Name cs1=%s cs2Label=Layer Name cs2=Network deviceDirection=%d "
           "msg=policy match\\=%s"
           % (action, int(event_time(i).timestamp() * 1000), src, ephemeral_port(rng), dst,
              dport, proto.upper(), service, rule, 0 if action == "Accept" else 1,
              "yes" if action == "Accept" else "no"))
    return "%s CEF:0|%s|%s|%s|%s|%s|%s|%s" % (
        _header(i, action), VENDOR, PRODUCT, VERSION, action, "Log", severity, ext)


def generate_leef(rng, i: int) -> str:
    service, proto, dport, action, src, dst, rule = _flow(rng)
    attrs = [
        "cat=Firewall",
        "devTime=%s" % event_time(i).strftime("%b %d %Y %H:%M:%S"),
        "devTimeFormat=MMM dd yyyy HH:mm:ss",
        "src=%s" % src,
        "dst=%s" % dst,
        "srcPort=%d" % ephemeral_port(rng),
        "dstPort=%d" % dport,
        "proto=%s" % proto,
        "action=%s" % action,
        "service=%s" % service,
        "rule_name=%s" % rule,
    ]
    return "%s LEEF:1.0|%s|%s|%s|%s|%s" % (
        _header(i, action), VENDOR, PRODUCT, VERSION, action, "\t".join(attrs))
