"""Command-line entry point:  logsync <command>  (or  python -m logsync <command>)."""
import argparse
import sys


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="logsync", description="LogSync ULPF")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("api", help="run the REST API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)

    if args.cmd == "api":
        import uvicorn
        uvicorn.run("logsync.api.app:app", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
