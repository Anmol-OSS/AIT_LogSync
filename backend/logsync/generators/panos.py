"""Palo Alto Networks PAN-OS - comma-separated TRAFFIC log over syslog.

Column order follows the PAN-OS traffic log format (first 40 columns). Empty
columns (e.g. no user identified) are left empty, exactly as PAN-OS sends them.
"""
from .common import EXTERNAL_IPS, INTERNAL_IPS, SERVICES, ephemeral_port, event_time

FACILITY_USER = 1
APPS = {"DNS": "dns", "HTTP": "web-browsing", "HTTPS": "ssl", "SSH": "ssh", "HTTPS-ALT": "ssl"}
CATEGORIES = ["computer-and-internet-info", "search-engines", "business-and-economy", "any"]


def generate(rng, i: int) -> str:
    t = event_time(i)
    ts = t.strftime("%Y/%m/%d %H:%M:%S")
    service, proto, dport = rng.choice(SERVICES)
    action = rng.choice(("allow", "allow", "deny", "drop"))
    sent, rcvd = rng.randint(60, 90000), rng.randint(60, 900000)
    cols = [
        "1",                      # FUTURE_USE
        ts,                       # receive time
        "012801098765",           # serial number
        "TRAFFIC",                # type
        "end",                    # subtype
        "2561",                   # FUTURE_USE
        ts,                       # generated time
        rng.choice(INTERNAL_IPS), # source address
        rng.choice(EXTERNAL_IPS), # destination address
        "0.0.0.0",                # NAT source IP
        "0.0.0.0",                # NAT destination IP
        "rule-%d" % rng.randint(1, 30),  # rule name
        "",                       # source user
        "",                       # destination user
        APPS[service],            # application
        "vsys1",                  # virtual system
        "trust",                  # source zone
        "untrust",                # destination zone
        "ethernet1/1",            # inbound interface
        "ethernet1/2",            # outbound interface
        "log-forward",            # log action
        "",                       # FUTURE_USE
        str(rng.randint(1000, 999999)),  # session ID
        "1",                      # repeat count
        str(ephemeral_port(rng)), # source port
        str(dport),               # destination port
        "0",                      # NAT source port
        "0",                      # NAT destination port
        "0x400000",               # flags
        proto,                    # protocol
        action,                   # action
        str(sent + rcvd),         # bytes
        str(sent),                # bytes sent
        str(rcvd),                # bytes received
        str(rng.randint(2, 900)), # packets
        ts,                       # start time
        str(rng.randint(0, 3600)),# elapsed time
        rng.choice(CATEGORIES),   # category
        "",                       # FUTURE_USE
        str(rng.randint(10**6, 10**7)),  # sequence number
    ]
    severity = 4 if action != "allow" else 6
    header = "<%d>%s PA-3220" % (FACILITY_USER * 8 + severity, t.strftime("%b %d %H:%M:%S"))
    return header + " " + ",".join(cols)
