"""Report which tools LogSync needs are installed, and which milestone needs them.

    python scripts/check_env.py

Exit code 0 when everything needed *now* is present; tools for later
milestones are reported but never fail the check.
"""
import re
import shutil
import subprocess
import sys

NOW = "now"


def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (out.stdout + out.stderr).strip()
    except (OSError, subprocess.TimeoutExpired):
        return None


def version_of(cmd):
    # Resolve the full path first: on Windows tools like npm are npm.cmd,
    # which subprocess cannot find by bare name.
    exe = shutil.which(cmd[0])
    if not exe:
        return None
    out = run([exe] + cmd[1:])
    return out.splitlines()[0] if out else None


def check_python():
    v = sys.version_info
    ok = (v.major, v.minor) == (3, 12)
    return ok, "Python %d.%d.%d (%s)" % (v.major, v.minor, v.micro, sys.executable)


def check_pytest():
    try:
        import pytest
        return True, "pytest " + pytest.__version__
    except ImportError:
        return False, "pytest not importable"


def check_logsync():
    try:
        import logsync
        return True, "logsync %s installed" % logsync.__version__
    except ImportError:
        return False, "run: pip install -e ."


def check_tool(cmd, minimum_major=None):
    def check():
        v = version_of(cmd)
        if not v:
            return False, "%s not found on PATH" % cmd[0]
        if minimum_major:
            m = re.search(r"(\d+)\.", v)
            if not m or int(m.group(1)) < minimum_major:
                return False, "%s (need >= %d)" % (v, minimum_major)
        return True, v
    return check


def check_wasm_target():
    rustup = shutil.which("rustup")
    if not rustup:
        return False, "rustup not found"
    out = run([rustup, "target", "list", "--installed"]) or ""
    if "wasm32-unknown-unknown" in out.split():
        return True, "wasm32-unknown-unknown installed"
    return False, "run: rustup target add wasm32-unknown-unknown"


CHECKS = [
    # (label, needed at, check function)
    ("Python 3.12", NOW, check_python),
    ("pytest", NOW, check_pytest),
    ("logsync package", NOW, check_logsync),
    ("git", NOW, check_tool(["git", "--version"])),
    ("Node.js >= 20", "M2 frontend", check_tool(["node", "--version"], 20)),
    ("npm", "M2 frontend", check_tool(["npm", "--version"])),
    ("Rust (cargo)", "M5b WASM runtime", check_tool(["cargo", "--version"])),
    ("Rust wasm32 target", "M5b WASM runtime", check_wasm_target),
    ("Docker", "M5c Kafka pipeline", check_tool(["docker", "--version"])),
    ("Ollama", "M5d LLM parser drafts", check_tool(["ollama", "--version"])),
]


def main() -> int:
    print("LogSync ULPF - environment check\n")
    missing_now = 0
    for label, needed, fn in CHECKS:
        ok, detail = fn()
        status = "OK     " if ok else ("MISSING" if needed == NOW else "later  ")
        if not ok and needed == NOW:
            missing_now += 1
        print("  [%s] %-20s %-22s %s" % (status, label, "(needed " + needed + ")", detail))
    print()
    if missing_now:
        print("%d tool(s) needed now are missing - see README 'Setup'." % missing_now)
        return 1
    print("Everything needed for the current milestone is installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
