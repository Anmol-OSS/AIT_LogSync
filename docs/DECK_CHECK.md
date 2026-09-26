# Deck vs. prototype - claims to keep, fix or reword

Checked against `AIT_LogSync_Final.pptx` (6 slides) and the measurements in `docs/BENCHMARKS.md`.
**Note: the evaluation deliverable is a technical presentation of at most 5 slides** - the current deck has 6.

## Numbers on slide 4

| Deck says | Measured | Recommendation |
|---|---|---|
| 139,654 events/s per core, "slowest full chain" | 145k/s with `bench/bench.py` (parse → serialize → SHA-256) - reproduces | Keep, but label it "parse + hash stage". The **full evidence chain** (archive, Merkle, WASM parse, provenance for ~20 fields, gate, index, lake) is **~2.2k events/s per core** → ~5 cores for 1 B events/day average, ~16 for the 3× burst. Judges who run the code will see the second number. |
| 1,468,709 events/s Merkle leaf + node | 1.5M/s - reproduces | Keep. |
| 11.4× gzip-6 at 94 MB/s | 11.3× at 127 MB/s on bench.py's 3-family corpus; **8.8×** on the 6-family pipeline archive (JSON compresses less) | Say "9-11× on synthetic logs (upper bound)". |
| 225 B average event | 318 B across all 6 families | Update, or say "225-320 B". |
| ≈ 3.6 TB for 180 days at 1 B/day | 318 B / 8.8× → ≈ 6.5 TB | Update or show as a range (3.6-6.5 TB). |
| 100 % field match, 600k events | 100 % of clean synthetic lines accepted by the round-trip gate (18k lines, 6 families) | Keep; say "synthetic". |

## Open questions on slide 4 - now answered

| Open question | Answer from the prototype |
|---|---|
| WASM sandbox overhead | Per call ~6k lines/s (crossing overhead); **batched 512 per call: ~55k lines/s, faster than the Python reference (37k)**. |
| I/O, Kafka, object storage | Kafka path tested against a real Kafka 4.3.1 broker (ingest and worker as separate processes). Full-chain figure above includes disk (fsync per batch). |
| Unknown-format accuracy | One held-out vendor (Juniper SRX, synthetic): 100 % of held-out lines. Not yet on LogHub. |
| Lossless under declared canonicalization | Measured per family (table in BENCHMARKS.md), including what no parser can detect. |

## Wording to adjust

| Slide | Current | Suggested |
|---|---|---|
| 2, 3 | "An offline LLM creates the parser from sample data" | "Drain mines the structure; an offline LLM labels it; deterministic tests decide; an analyst approves." (An 8B model writing the regex matched 0/200 lines; labelling works - LibreLog does the same.) |
| 2 | "The CLP archive is secured in an RFC 6962 Merkle tree" | Prototype: content-addressed gzip segments sealed in the RFC 6962 tree. Say "CLP planned" or drop CLP. |
| 3 | Technologies: "Arrow / DataFusion", "Docker / Helm", "Prometheus" | Built: Arrow/Parquet, Docker + compose. Not built: DataFusion queries, Helm, Prometheus - move to roadmap or drop. |
| 2 | Source list includes "NetFlow / IDS" | Prototype IDS is Suricata EVE JSON; NetFlow (binary) not implemented. |
| 3 | "Parser health / schema drift radar" | Built: unknown-format and blocked-by-gate signals on the dashboard. Latency/crash health panels not built. |

## Claims the prototype backs exactly

Field-level byte provenance · write-first immutable archive · RFC 6962 inclusion proofs · Ed25519-signed
tree heads with RFC 3161 time-stamps · Wasmtime sandbox with fuel and memory limits, no imports ·
round-trip gate that blocks unexplained loss · signed, versioned, hot-loaded packs · offline Llama 3 8B
(Ollama) · Kafka at-least-once with dead-letter topic · OCSF-aligned UES · the four "live at the finale" demos.
