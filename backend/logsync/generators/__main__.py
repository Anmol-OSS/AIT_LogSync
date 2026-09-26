"""Write sample log files, one per source.

    python -m logsync.generators                      # 200 lines each into samples/
    python -m logsync.generators --count 10000 --out data/corpus
    python -m logsync.generators --source fortigate --count 5 --stdout
"""
import argparse
import sys
from pathlib import Path

from . import SOURCES, generate_lines


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m logsync.generators", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default="samples", help="output directory (default: samples)")
    p.add_argument("--count", type=int, default=200, help="lines per source (default: 200)")
    p.add_argument("--seed", type=int, default=7, help="random seed (default: 7)")
    p.add_argument("--source", action="append", choices=sorted(SOURCES),
                   help="only this source (repeatable); default: all")
    p.add_argument("--stdout", action="store_true", help="print lines instead of writing files")
    args = p.parse_args(argv)

    names = args.source or list(SOURCES)
    out = Path(args.out)
    if not args.stdout:
        out.mkdir(parents=True, exist_ok=True)

    for name in names:
        lines = generate_lines(name, args.count, args.seed)
        if args.stdout:
            sys.stdout.write("\n".join(lines) + "\n")
            continue
        # Write bytes, not text: on Windows text mode would turn \n into \r\n
        # and silently change the evidence.
        path = out / ("%s.log" % name)
        path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
        print("wrote %-28s %6d lines  (%s, %s)"
              % (path.as_posix(), len(lines), SOURCES[name].family, SOURCES[name].fmt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
