"""LogSync ULPF - prototype benchmark.

Measures, on THIS machine, the per-core cost of the core pipeline stages:
  parse (regex) -> UES map -> canonical serialize -> SHA-256 -> Merkle leaf
plus archive compression ratios (gzip vs zstd) on synthetic perimeter-device logs.

Nothing here is simulated: every figure is timed with perf_counter on real data.
Run it on your own hardware to reproduce:  python3 bench.py
"""
import gzip, hashlib, io, json, os, platform, random, re, statistics, sys, time, zlib

try:
    import zstandard as zstd
except ImportError:
    zstd = None

random.seed(7)
N = int(os.environ.get("BENCH_N", "200000"))

# ---------------------------------------------------------------- generators
IPS = ["10.20.30.40", "192.168.4.11", "172.16.9.2", "10.2.1.7", "10.55.3.90"]
DST = ["8.8.8.8", "1.1.1.1", "142.250.183.14", "52.95.110.1", "13.107.42.14"]
ACT = ["deny", "accept", "allow", "drop"]
IFS = ["port1", "port2", "wan1", "internal"]


def gen_fortigate(i):
    return ('date=2026-09-25 time=%02d:%02d:%02d devname="FG100E" devid="FGT60E4Q17" '
            'logid="0000000013" type="traffic" subtype="forward" level="notice" '
            'srcip=%s srcport=%d dstip=%s dstport=%d srcintf="%s" dstintf="wan1" '
            'action="%s" policyid=%d service="HTTPS" proto=6 sentbyte=%d rcvdbyte=%d'
            % (i % 24, i % 60, (i * 7) % 60, random.choice(IPS), 1024 + i % 60000,
               random.choice(DST), random.choice([53, 80, 443, 8443]),
               random.choice(IFS), random.choice(ACT), i % 40,
               random.randint(80, 90000), random.randint(80, 900000)))


def gen_asa(i):
    return ('<134>Sep 25 %02d:%02d:%02d fw01 %%ASA-6-106100: access-list outside_acl '
            'permitted tcp outside/%s(%d) -> inside/%s(%d) hit-cnt %d first hit '
            '[0x%08x, 0x0]'
            % (i % 24, i % 60, (i * 3) % 60, random.choice(IPS), 1024 + i % 60000,
               random.choice(DST), random.choice([53, 80, 443]), i % 500,
               random.getrandbits(32)))


def gen_panos(i):
    return ('1,2026/09/25 %02d:%02d:%02d,012801098765,TRAFFIC,end,2561,'
            '2026/09/25 %02d:%02d:%02d,%s,%s,0.0.0.0,0.0.0.0,rule-%d,,,ssl,vsys1,'
            'trust,untrust,ethernet1/1,ethernet1/2,log-forward,%d,%d,%d,%d'
            % (i % 24, i % 60, (i * 5) % 60, i % 24, i % 60, (i * 5) % 60,
               random.choice(IPS), random.choice(DST), i % 30,
               i % 1000, random.randint(1, 9), random.randint(200, 90000),
               random.randint(200, 90000)))


GENS = [("FortiGate KV", gen_fortigate), ("Cisco ASA syslog", gen_asa), ("PAN-OS CSV", gen_panos)]

# ---------------------------------------------------------------- parsers
RE_FG = re.compile(
    r'srcip=(?P<srcip>\S+)\s+srcport=(?P<srcport>\d+)\s+dstip=(?P<dstip>\S+)\s+'
    r'dstport=(?P<dstport>\d+)\s+srcintf="(?P<srcintf>[^"]+)"\s+dstintf="(?P<dstintf>[^"]+)"\s+'
    r'action="(?P<action>[^"]+)"')
RE_ASA = re.compile(
    r'%ASA-(?P<sev>\d)-(?P<msgid>\d+):\s+access-list\s+(?P<acl>\S+)\s+(?P<action>\w+)\s+'
    r'(?P<proto>\w+)\s+\S+/(?P<srcip>[\d.]+)\((?P<srcport>\d+)\)\s+->\s+\S+/(?P<dstip>[\d.]+)\((?P<dstport>\d+)\)')


def parse_fg(line):
    m = RE_FG.search(line)
    if not m:
        return None
    d = m.groupdict()
    return {"src_endpoint.ip": d["srcip"], "src_endpoint.port": int(d["srcport"]),
            "dst_endpoint.ip": d["dstip"], "dst_endpoint.port": int(d["dstport"]),
            "activity_name": d["action"], "observer.ingress": d["srcintf"],
            "observer.egress": d["dstintf"]}


def parse_asa(line):
    m = RE_ASA.search(line)
    if not m:
        return None
    d = m.groupdict()
    return {"src_endpoint.ip": d["srcip"], "src_endpoint.port": int(d["srcport"]),
            "dst_endpoint.ip": d["dstip"], "dst_endpoint.port": int(d["dstport"]),
            "activity_name": d["action"], "severity_id": int(d["sev"]),
            "metadata.event_code": d["msgid"]}


def parse_panos(line):
    f = line.split(",")
    if len(f) < 20:
        return None
    return {"src_endpoint.ip": f[7], "dst_endpoint.ip": f[8], "rule": f[11],
            "observer.ingress": f[16], "observer.egress": f[17],
            "traffic.bytes_in": int(f[-2]), "traffic.bytes_out": int(f[-1])}


PARSERS = {"FortiGate KV": parse_fg, "Cisco ASA syslog": parse_asa, "PAN-OS CSV": parse_panos}


def timeit(fn, n):
    t0 = time.perf_counter()
    fn()
    return n / (time.perf_counter() - t0)


def main():
    print("=" * 66)
    print("LogSync ULPF prototype benchmark")
    print("python %s | %s | %s" % (platform.python_version(), platform.machine(),
                                   platform.system()))
    print("N = %d events per source family, single core, no parallelism" % N)
    print("=" * 66)

    results = {}
    all_lines = []

    for name, gen in GENS:
        lines = [gen(i) for i in range(N)]
        all_lines.extend(lines)
        raw = [ln.encode() for ln in lines]
        avg_len = statistics.mean(len(b) for b in raw)
        parser = PARSERS[name]

        eps_parse = timeit(lambda: [parser(ln) for ln in lines], N)
        recs = [parser(ln) for ln in lines]
        ok = sum(1 for r in recs if r)
        eps_ser = timeit(lambda: [json.dumps(r, separators=(",", ":"), sort_keys=True)
                                  for r in recs if r], ok)
        eps_hash = timeit(lambda: [hashlib.sha256(b).digest() for b in raw], N)

        def full():
            for ln, b in zip(lines, raw):
                r = parser(ln)
                if r:
                    json.dumps(r, separators=(",", ":"), sort_keys=True)
                    hashlib.sha256(b).digest()
        eps_full = timeit(full, N)

        results[name] = {"avg_bytes": avg_len, "match_rate": ok / N * 100,
                         "eps_parse": eps_parse, "eps_ser": eps_ser,
                         "eps_hash": eps_hash, "eps_full": eps_full}
        print("\n%-18s avg %.0f B/event   field match %.1f%%" % (name, avg_len, ok / N * 100))
        print("   parse only          %10s events/sec" % f"{eps_parse:,.0f}")
        print("   canonical serialize %10s events/sec" % f"{eps_ser:,.0f}")
        print("   SHA-256 of raw      %10s events/sec" % f"{eps_hash:,.0f}")
        print("   full stage chain    %10s events/sec" % f"{eps_full:,.0f}")

    # ------------------------------------------------ Merkle (RFC 6962 style)
    leaves = [hashlib.sha256(b"\x00" + ln.encode()).digest() for ln in all_lines[:N]]

    def merkle(nodes):
        while len(nodes) > 1:
            nodes = [hashlib.sha256(b"\x01" + nodes[i] + nodes[i + 1]).digest()
                     if i + 1 < len(nodes) else nodes[i]
                     for i in range(0, len(nodes), 2)]
        return nodes[0]
    t0 = time.perf_counter()
    root = merkle(list(leaves))
    merkle_eps = N / (time.perf_counter() - t0)
    print("\nMerkle tree (RFC 6962 leaf/node hashing)")
    print("   build over %s leaves  %10s events/sec" % (f"{N:,}", f"{merkle_eps:,.0f}"))
    print("   root = %s" % root.hex()[:32])

    # ------------------------------------------------ compression
    blob = ("\n".join(all_lines)).encode()
    raw_mb = len(blob) / 1e6
    t0 = time.perf_counter(); gz = gzip.compress(blob, 6); gz_s = time.perf_counter() - t0
    comp = {"gzip-6": (len(blob) / len(gz), raw_mb / gz_s)}
    if zstd:
        for lvl in (3, 12, 19):
            c = zstd.ZstdCompressor(level=lvl)
            t0 = time.perf_counter(); out = c.compress(blob); dt = time.perf_counter() - t0
            comp["zstd-%d" % lvl] = (len(blob) / len(out), raw_mb / dt)
    print("\nArchive compression on %.1f MB of mixed perimeter logs" % raw_mb)
    for k, (ratio, mbs) in comp.items():
        print("   %-9s ratio %5.1f x    %7.0f MB/s" % (k, ratio, mbs))

    results["_merkle_eps"] = merkle_eps
    results["_compression"] = comp
    results["_raw_mb"] = raw_mb
    results["_n"] = N
    with open("bench_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nwrote bench_results.json")


if __name__ == "__main__":
    main()
