"""Rebuild the WASM tokenizer and copy it next to the Python host.

    python scripts/build_wasm.py

Run after changing runtime/src/lib.rs. On Windows run it from PowerShell, not
Git Bash (Git Bash puts GNU `link` ahead of the Rust toolchain on PATH).
The built module is committed so the backend runs without a Rust toolchain.
"""
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BUILT = REPO / "runtime" / "target" / "wasm32-unknown-unknown" / "release" / "logsync_runtime.wasm"
DEST = REPO / "backend" / "logsync" / "core" / "wasm" / "logsync_runtime.wasm"


def main() -> int:
    subprocess.run(["cargo", "build", "--release", "--target", "wasm32-unknown-unknown"],
                   cwd=REPO / "runtime", check=True)
    DEST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(BUILT, DEST)
    digest = hashlib.sha256(DEST.read_bytes()).hexdigest()
    print("copied %s (%d bytes, sha256 %s)" % (DEST.relative_to(REPO), DEST.stat().st_size, digest[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
