# LogSync ULPF

**Universal Log Pre-processing Framework** - Smart India Hackathon 2026, PS 26156
(Blockchain & Cybersecurity). Team AIT_LogSync, Team ID 135911.

A proof-carrying telemetry fabric: perimeter-device logs are archived byte-exact *before* parsing,
parsed inside a WebAssembly sandbox, normalized to an OCSF-aligned Universal Event Schema, and every
normalized field proves which original bytes produced it. Any event can be re-verified from the archive
against a signed, time-stamped Merkle tree. New devices are onboarded in the browser: Drain mines the
format, an **offline** Llama 3 labels it, deterministic tests decide, an analyst approves.

* Architecture (2 pages): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
* Measured performance: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
* Demo video script: [`docs/DEMO.md`](docs/DEMO.md)
* Deck vs. prototype: [`docs/DECK_CHECK.md`](docs/DECK_CHECK.md)

## What the PS asks for, and where it is

| PS 26156 expected solution | Where |
|---|---|
| a) preserve raw data without loss | write-first archive, round-trip gate (`backend/logsync/storage/archive.py`, `core/event.py`) |
| b) parse source-specific attributes | parser packs (`packs/*.yaml`), tokenizer (`runtime/`, `core/tokenize.py`) |
| c) normalize to a common taxonomy | OCSF-aligned UES (`core/normalize.py`) |
| d) traceability normalized ↔ original | per-field byte provenance, RFC 6962 Merkle proofs, Verification API (`core/verify.py`) |
| e) plug-and-play onboarding | Pack editor + synthesis loop (`synth/`), signed hot-loaded registry (`core/registry.py`) |
| f) unified visibility | web UI (`frontend/`) |
| g) SIEM and data-lake integration | syslog JSON/CEF forwarder, Parquet lake (`pipeline/forwarder.py`, `storage/lake.py`) |
| h) AI/ML-ready | typed columnar Parquet, stable UES fields |
| i) reduced parser effort | LLM-assisted pack drafting with a deterministic gate |
| j) air-gapped deployment | no runtime network access (tested in `tests/test_airgap.py`), local LLM and TSA |
| k) container | `Dockerfile`, `docker-compose.yml` |

## Quick start (Windows, single process)

Prerequisites: [Miniconda](https://docs.conda.io/en/latest/miniconda.html), Git, Node.js 20+.
Optional: [Ollama](https://ollama.com) with `llama3:8b` for LLM-assisted drafting (without it, drafting
falls back to Drain only). Run in **PowerShell** from the repository folder:

```powershell
conda env create -f environment.yml          # one time: Python 3.12 environment "logsync"
conda activate logsync
pip install -e ".[dev,kafka]"                # the logsync package and its dependencies
cd frontend; npm install; npm run build; cd ..   # build the UI (served by the backend)
python scripts/check_env.py                  # what is installed, what is optional

python -m logsync demo                       # fresh data + server + replayed device traffic
```

Open **http://127.0.0.1:8000**. `logsync demo` wipes `demo-data/` on start; use `python -m logsync serve`
for persistent data in `data/`, and `python -m logsync replay` in a second window to send traffic.

For LLM drafting: install Ollama, then `ollama pull llama3:8b` (4.7 GB, once). If `conda` is not recognised
in PowerShell, run `& "$env:USERPROFILE\miniconda3\Scripts\conda.exe" init powershell` once and reopen it,
or use *Anaconda Prompt*.

## Commands

```
python -m logsync serve     ingest + worker + API + UI in one process   (--port 8000 --syslog-port 5514)
python -m logsync demo      serve with fresh data and background traffic from 7 device types
python -m logsync replay    send synthetic syslog traffic                (--rate 200 --count 0 --proto tcp)
python -m logsync ingest    syslog -> Kafka          } the same pipeline as separate services
python -m logsync worker    Kafka -> evidence store  } (used by docker-compose; --kafka host:9092)
python -m logsync api       REST API + UI            }
python -m logsync archive FILE --prove N   archive a file, seal a signed tree head, prove line N
python -m logsync.generators               regenerate samples/
```

REST API documentation: http://127.0.0.1:8000/docs (interactive).

## Docker and air-gapped deployment

```powershell
docker compose up --build                     # Kafka, ingest (udp/tcp 5514), worker, API + UI (:8000)
docker compose --profile llm up --build       # plus Ollama; load llama3:8b into its volume
```

For an air-gapped site, build on a connected machine and carry the images across:

```powershell
docker compose build
docker save -o logsync-images.tar logsync-ulpf-api logsync-ulpf-worker logsync-ulpf-ingest apache/kafka:4.3.1 ollama/ollama
# on the air-gapped host:
docker load -i logsync-images.tar ; docker compose up
```

The images contain everything (UI assets, WASM module, Python dependencies, OpenSSL for the local
time-stamp authority); nothing is downloaded at runtime.

Docker was not available on the development machine, so the compose file is untested as a whole; each
service's command was run natively, including against a real Kafka 4.3.1 broker.

## Tests

```powershell
python -m pytest                              # 140+ tests, ~20 s
cd frontend; npm test; cd ..                  # UI unit tests
$env:LOGSYNC_TEST_OLLAMA = "1"; python -m pytest tests/test_synth.py     # + the real Llama 3 test
$env:LOGSYNC_TEST_KAFKA = "127.0.0.1:9092"; python -m pytest tests/test_pipeline.py   # + a real broker
python bench/bench_pipeline.py                # regenerates docs/BENCHMARKS.md
```

Highlights: RFC 6962 reference roots; WASM-vs-Python differential on every sample line and 6,000 mutated
lines; sandbox fuel and memory limits; tamper detection through the API; end-to-end over real sockets;
prompt-injection isolation; the gate rejecting catch-all and overfitted patterns; air-gap checks.

## Repository layout

```
backend/logsync/
  api/          FastAPI app, response models (the contract), live service
  core/         packs, grok, tokenizer (Python reference), WASM host, transforms, normalizer,
                round-trip gate, registry, processor, verification
  storage/      raw archive, Merkle log, signed tree heads, RFC 3161 TSA, SQLite, Parquet lake
  pipeline/     syslog ingest, memory/Kafka bus, worker, SIEM forwarder, replayer
  synth/        Drain, drafter, Ollama client, validation gate, draft/approve loop
  generators/   deterministic synthetic logs for 7 device types
runtime/        Rust tokenizer compiled to wasm32-unknown-unknown (built module in core/wasm/)
packs/          built-in parser packs (signed into the registry on first start)
frontend/       React + Vite + TypeScript UI
samples/        byte-exact sample logs (never line-ending converted)
bench/          bench.py (slide 4) and bench_pipeline.py (full chain)
docs/           architecture, benchmarks, demo script, deck check
```

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LOGSYNC_DATA` | `data` | evidence store: archive, Merkle log, keys, packs, index, lake |
| `LOGSYNC_ENGINE` | `wasm` | tokenizer engine: `wasm` (sandboxed) or `python` (reference) |
| `LOGSYNC_TZ` | `+05:30` | timezone for syslog timestamps that carry none (RFC 3164) |
| `LOGSYNC_STH_SECONDS` / `_LEAVES` | `2` / `5000` | signed tree head cadence |
| `LOGSYNC_TSA` | `openssl` | RFC 3161 time-stamps via local openssl, or `off` |
| `LOGSYNC_KAFKA` | `localhost:9092` | Kafka bootstrap for ingest/worker/api |
| `LOGSYNC_FORWARD` | - | SIEM forwarder, e.g. `udp://siem:514`; `LOGSYNC_FORWARD_FORMAT=json|cef` |
| `LOGSYNC_OLLAMA_URL` / `_MODEL` | `http://127.0.0.1:11434` / `llama3:8b` | offline LLM |
| `LOGSYNC_DEMO` | `1` | enables the tamper/restore demo endpoints; set `0` in production |
| `LOGSYNC_TLS_CERT` / `_KEY` | - | enables syslog over TLS on 6514 |

## Rebuilding the WASM tokenizer

After changing `runtime/src/lib.rs`: `python scripts/build_wasm.py` from **PowerShell** (in Git Bash the GNU
`link` command shadows the Rust toolchain's linker). Needs Rust and `rustup target add wasm32-unknown-unknown`;
no C toolchain.

## License

Apache-2.0
