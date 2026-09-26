# LogSync ULPF - Architecture

**Universal Log Pre-processing Framework** · SIH 2026 · PS 26156 · Team AIT_LogSync

A proof-carrying telemetry fabric: perimeter-device logs are archived byte-exact *before* parsing,
parsed inside a WebAssembly sandbox, normalized to an OCSF-aligned Universal Event Schema (UES), and
every normalized field carries the byte range and transformation chain that produced it. Any event can be
re-verified from the archive against a signed Merkle tree.

## Data flow

```
 devices ──syslog UDP/TCP/TLS──▶ INGEST ──▶ Kafka logsync.raw ──▶ WORKER (one batch at a time)
                                  │                                 │
                        event id + receive time            1 ARCHIVE raw bytes (content-addressed, gzip-6)
                        raw bytes never re-encoded         2 MERKLE leaf = H(0x00 ‖ id ‖ time ‖ raw)  (RFC 6962)
                                                           3 IDENTIFY pack by fingerprint
                                                           4 TOKENIZE in Wasmtime (fuel + memory limits)
                                                           5 NORMALIZE → UES + per-field provenance
                                                           6 ROUND-TRIP GATE: accept | block | dead-letter
                                                           7 INDEX (SQLite) · LAKE (Parquet) · SIEM (syslog JSON/CEF)
                                                                    │
     signed tree head every 2 s: Ed25519 + RFC 3161 time-stamp ◀────┘
                                                                    ▼
      REST API + UI ── dashboard · event inspector · verify · pack editor ── Verification API
                                                                    ▲
 dead letters ─▶ Drain ─▶ Llama 3 8B (offline) labels ─▶ gate ─▶ analyst approves ─▶ Ed25519-signed pack ─▶ hot-load
```

## Components

| Component | Implementation | PS requirement |
|---|---|---|
| Ingest | Python syslog server: UDP, TCP, TLS (RFC 5425), RFC 6587 framing, TCP backpressure | ingest any perimeter source |
| Bus | Apache Kafka 4 (KRaft), at-least-once, commit after store, dedup by event id; in-process queue in single-node mode | scalable, Big Data |
| Raw archive | append-only segments, SHA-256 content addressing, gzip-6 sealing | (a) preserve raw data without loss |
| Evidence log | RFC 6962 Merkle tree, inclusion proofs (RFC 9162 verify), Ed25519-signed tree heads, RFC 3161 time-stamps from a local TSA | (d) traceability, forensic integrity |
| Parser packs | declarative YAML: fingerprint, format (regex/grok, key=value, CSV, CEF, LEEF, JSON), UES mapping, declared transforms, typed checks; signed and versioned | (b) parse, (e) plug-and-play |
| Tokenizer | Rust compiled to `wasm32-unknown-unknown` (no imports), run in Wasmtime; a Python reference twin for differential testing | untrusted input isolated |
| Normalizer | OCSF Network Activity (4001) UES; every captured value is mapped or kept under `unmapped.*` | (c) common taxonomy |
| Round-trip gate | every byte is grammar or inside a field; every declared transform/check holds; otherwise **blocked**, never half-normalized | (a) lossless, verified |
| Synthesis loop | Drain template mining → offline Llama 3 labels fields and UES targets → deterministic gate → human approval | (i) reduced parser effort |
| Outputs | SQLite index + REST API, Parquet (Hive layout) data lake, syslog JSON/CEF forwarder to any SIEM | (f) visibility, (g) SIEM/lake, (h) AI/ML-ready |
| Packaging | one Docker image (UI, WASM, Python stages), docker-compose with Kafka and optional Ollama | (j) air-gap, (k) container |

## The proof-carrying event

Each event carries: `raw` (text, length, SHA-256, archive reference), `parser` (pack id, version, digest of
the signed pack file), `ues`, `provenance` (per field: value, exact source text, `bytes[start:end]`,
transform chain such as `utf8_decode → json_string → ip`), `roundtrip` (status, unexplained byte ranges), and
`merkle` (leaf index, signed tree size and root, inclusion proof).

**Verification trusts nothing stored.** It reads the archived bytes and re-checks five things: archive hash;
pack digest and signature; provenance re-derived by re-parsing with the same signed pack; the round-trip
decision reproduced; the Merkle inclusion proof against a validly signed, time-stamped tree head. Changing
one archived byte fails archive, provenance and Merkle integrity.

## Self-evolving parser: LLM proposes, deterministic tests decide, human approves

1. **Detect:** lines matching no fingerprint are archived, sealed and dead-lettered (Kafka `logsync.dlq`).
2. **Synthesize:** Drain (He et al. 2017) mines the dominant template from the pasted sample plus dead letters
   of that format; a deterministic drafter types each variable (IP, INT, TOKEN ...). The offline Llama 3 8B
   *labels* the template - field names, UES targets, vendor, product - as in LibreLog (Ma et al. 2024). Log
   lines enter the prompt only as a JSON array inside a delimited data block; output is schema-constrained,
   names sanitised, targets whitelisted and type-checked. (Asked to write the regex itself, the 8B model
   matched 0 of 200 lines in our test; labelling works.) Without a model, Drain alone drafts the pack.
3. **Validate:** held-out match rate ≥ 95 %, round-trip, specificity (no catch-all capture), fuzzing in the
   sandbox, WASM-vs-Python differential.
4. **Promote:** the analyst fixes mappings in the UI; the final pack passes the gate again, is Ed25519-signed,
   hot-loaded without restart, and archived dead letters are re-parsed from their original bytes.

## Security properties

* Parser code never runs outside the sandbox: no system calls, files, network or clock; per-line fuel
  budget; memory cap; a trap blocks one event and the instance is replaced.
* Packs are data, signed; a tampered pack file is refused at load. Versions are immutable, so events parsed
  by old versions stay verifiable.
* Telemetry is data, never instructions: prompt isolation plus a deterministic gate the model cannot bypass.
* No outbound network at runtime (tested): UI assets bundled, model local, time-stamps from a local TSA.

## Measured (single core, this laptop; `bench/bench_pipeline.py`, `docs/BENCHMARKS.md`)

| | |
|---|---|
| Tokenize, WASM batched / Python reference | ≈ 55k / 37k lines/s |
| Full evidence chain (archive, Merkle, parse, provenance, gate, index, lake) | ≈ 2.2k events/s per core → ~5 cores for 1 B events/day |
| Verification of one event from archived bytes | 1.6 ms median |
| Clean synthetic lines accepted, 6 families | 100 % |
| Held-out accuracy of a synthesized pack (Juniper SRX) | 100 % (150 / 150) |

## Limits and next steps

Synthetic corpora only (compression and accuracy are upper bounds until measured on real captures); one
evidence-store writer per worker (horizontal scale = one store per Kafka partition group); CLP-style
searchable compression, Prometheus metrics, RBAC and Helm charts are not in the prototype.
