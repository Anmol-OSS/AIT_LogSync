# LogSync ULPF

**Universal Log Pre-processing Framework** - Smart India Hackathon 2026, PS 26156
(Blockchain & Cybersecurity). Team AIT_LogSync, Team ID 135911.

A proof-carrying telemetry fabric: perimeter-device logs are archived byte-exact,
parsed in a WASM sandbox, normalized to an OCSF-aligned Universal Event Schema,
and every normalized field can prove which original bytes produced it.

> **Status: Milestone 2 (frontend skeleton).** Sample data, benchmark, tooling, and the
> web UI running on **mock data**. Parsing, storage and the API arrive in later milestones.

## Repository layout

```
frontend/                     React + Vite + TypeScript web UI (see "Frontend" below)
backend/logsync/generators/   synthetic log generators, one module per vendor family
samples/                      200-line sample log per source (generated, byte-exact, committed)
bench/bench.py                per-core throughput / Merkle / compression benchmark (slide 4)
scripts/check_env.py          checks which required tools are installed
tests/                        pytest suite
```

## Source families

| Sample file | Family | Wire format |
|---|---|---|
| `cisco_asa.log` | Cisco ASA | RFC 3164 syslog, `%ASA-x-106100/106023/302013` |
| `fortigate.log` | FortiGate | key=value (PRI-only syslog header) |
| `panos.log` | PAN-OS | CSV traffic log, 40 columns |
| `checkpoint_cef.log` | Check Point | CEF over syslog |
| `checkpoint_leef.log` | Check Point | LEEF 1.0 (tab-delimited) over syslog |
| `suricata.log` | Suricata IDS | EVE JSON over syslog |

All samples are synthetic and deterministic: the same seed always produces the same bytes.

## Setup (Windows)

Prerequisites: [Miniconda](https://docs.conda.io/en/latest/miniconda.html) and Git.
Run these in **PowerShell** from the repository folder:

```powershell
conda env create -f environment.yml      # one time: creates the "logsync" env (Python 3.12)
conda activate logsync
pip install -e .                         # installs the logsync package in editable mode
python scripts/check_env.py              # shows what is installed and what later milestones need
```

If `conda` is not recognised, open **Anaconda Prompt** instead of PowerShell, or run
`conda init powershell` once and reopen the terminal.

## Usage

```powershell
python -m logsync.generators                               # regenerate samples/ (200 lines each)
python -m logsync.generators --source fortigate --count 5 --stdout
python -m logsync.generators --count 100000 --out data/corpus   # large corpus (git-ignored)
python -m pytest                                            # run the tests
python bench/bench.py                                       # full benchmark (N=200000, ~1 min)
```

Set `$env:BENCH_N = "20000"` before running the benchmark for a quick run.

## Frontend

Requires Node.js 20+. From the repository folder:

```powershell
cd frontend
npm install          # one time
npm run dev          # http://localhost:5173
npm test             # unit tests (byte-range logic + mock-data consistency)
npm run build        # type-check + production build into frontend/dist
```

Screens: **Dashboard**, **Event inspector** (field-to-byte provenance), **Verify**
(five integrity checks + tamper demo) and **Pack editor** (four-step device onboarding).

Until the backend is connected (M6) every screen reads `frontend/src/mock/*.json` through
`frontend/src/api.ts`, and the sidebar shows a **MOCK DATA** badge. The mock events are
built from real lines in `samples/`, with byte offsets computed rather than typed; only the
Merkle hashes and signatures are placeholders. These JSON files define the contract the
M3 API must return (types in `frontend/src/types.ts`).

## Tools needed by later milestones

| Tool | Needed from | Install |
|---|---|---|
| Node.js 20+ / npm | M2 frontend | nodejs.org |
| Rust + `wasm32-unknown-unknown` | M5b WASM runtime | rustup.rs, then `rustup target add wasm32-unknown-unknown` |
| WSL2 + Docker Desktop | M5c Kafka pipeline | `wsl --install` (admin, reboot), then Docker Desktop |
| Ollama + Llama 3 8B | M5d parser drafting | ollama.com, then `ollama pull llama3:8b` |

## License

Apache-2.0
