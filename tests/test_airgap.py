"""Air-gap readiness (PS requirement j): nothing reaches outside the machine at runtime.

Static checks - the Docker network-off run is documented in the README:
  * the built UI loads no external script, stylesheet, font or image and
    fetches only its own origin (/api)
  * every network default in the backend points at this host
  * the WASM parser has no imports at all (tests/test_wasm.py)
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DIST = REPO / "frontend" / "dist"
EXTERNAL = re.compile(rb"""(?:src|href)\s*=\s*["']https?://|@import\s+url\(\s*["']?https?://|url\(\s*["']?https?://|"""
                      rb"""fetch\(\s*["'`]https?://|import\(\s*["'`]https?://""")


@pytest.mark.skipif(not (DIST / "index.html").exists(), reason="run `npm run build` in frontend/ first")
def test_built_ui_loads_nothing_from_the_internet():
    offenders = []
    for f in DIST.rglob("*"):
        if f.suffix in (".html", ".js", ".css") and EXTERNAL.search(f.read_bytes()):
            offenders.append(f.name)
    assert offenders == []


def test_ui_source_calls_only_its_own_origin():
    api = (REPO / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
    assert "fetch(`/api${path}`" in api
    for f in (REPO / "frontend" / "src").rglob("*.ts*"):
        assert not re.search(r"https?://(?!localhost|127\.0\.0\.1)", f.read_text(encoding="utf-8")), f.name
    assert "fonts.googleapis" not in (REPO / "frontend" / "index.html").read_text(encoding="utf-8")


def test_backend_network_defaults_are_local():
    from logsync.config import Settings
    s = Settings()
    assert re.match(r"http://(127\.0\.0\.1|localhost)", s.ollama_url)
    code = "\n".join(p.read_text(encoding="utf-8") for p in (REPO / "backend" / "logsync").rglob("*.py"))
    urls = set(re.findall(r"https?://[\w.\-]+", code))
    assert urls <= {"http://127.0.0.1", "http://localhost"}, urls
