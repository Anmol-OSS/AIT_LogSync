"""Runtime settings, read from environment variables (12-factor, container friendly)."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("LOGSYNC_DATA", "data")))
    packs_dir: Path = field(default_factory=lambda: Path(_env(
        "LOGSYNC_PACKS", str(Path(__file__).resolve().parents[2] / "packs"))))
    # Signed tree head cadence: seal after this many new leaves or seconds.
    sth_every_leaves: int = field(default_factory=lambda: int(_env("LOGSYNC_STH_LEAVES", "5000")))
    sth_every_seconds: float = field(default_factory=lambda: float(_env("LOGSYNC_STH_SECONDS", "2")))
    segment_max_bytes: int = field(default_factory=lambda: int(_env("LOGSYNC_SEGMENT_BYTES", str(4 * 1024 * 1024))))
    # Timezone assumed for syslog timestamps that carry none (RFC 3164). CERT-In
    # directions require NTP sync to NIC/NPL, i.e. IST clocks.
    default_tz: str = field(default_factory=lambda: _env("LOGSYNC_TZ", "+05:30"))
    parser_engine: str = field(default_factory=lambda: _env("LOGSYNC_ENGINE", "wasm"))  # wasm | python
    tsa: str = field(default_factory=lambda: _env("LOGSYNC_TSA", "openssl"))  # openssl | off
    ollama_url: str = field(default_factory=lambda: _env("LOGSYNC_OLLAMA_URL", "http://127.0.0.1:11434"))
    ollama_model: str = field(default_factory=lambda: _env("LOGSYNC_OLLAMA_MODEL", "llama3:8b"))
    demo: bool = field(default_factory=lambda: _env("LOGSYNC_DEMO", "1") == "1")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "logsync.db"

    def ensure_dirs(self) -> None:
        for sub in ("archive", "merkle", "keys", "lake", "tsa"):
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)
