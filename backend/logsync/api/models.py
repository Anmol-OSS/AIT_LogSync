"""API response models - the backend half of the contract in frontend/src/types.ts.

Field names and shapes must stay identical to the TypeScript types; the tests
validate the frontend mock JSON against these models to catch any drift.
"""
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

ByteRange = tuple[int, int]  # half-open byte offsets into the archived raw line


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProvenanceEntry(Model):
    field: str
    value: str | int | float
    raw: str | None
    bytes: ByteRange | None
    transforms: list[str]
    derived_from: list[str] | None = None


class SourceInfo(Model):
    name: str
    family: str
    format: str
    host: str


class RawInfo(Model):
    text: str
    length: int
    sha256: str
    archive_ref: str


class ParserInfo(Model):
    pack_id: str
    version: str
    digest: str


class RoundTrip(Model):
    status: Literal["pass", "fail"]
    total_bytes: int
    field_bytes: int
    unexplained: list[ByteRange]
    reason: str | None = None


class MerkleInfo(Model):
    leaf_index: int
    tree_size: int
    root: str
    inclusion_proof: list[str]
    status: Literal["sealed", "pending"]   # covered by a signed tree head yet? (verify checks the proof)


class ProofCarryingEvent(Model):
    event_id: str
    status: Literal["accepted", "blocked", "unparsed"]
    received_at: str
    source: SourceInfo
    raw: RawInfo
    parser: ParserInfo
    ues: dict[str, Any] | None
    provenance: list[ProvenanceEntry]
    roundtrip: RoundTrip
    merkle: MerkleInfo


class VerifyCheck(Model):
    name: str
    status: Literal["pass", "fail"]
    detail: str


class VerifyReport(Model):
    event_id: str
    tampered: bool
    overall: Literal["verified", "failed"]
    checks: list[VerifyCheck]
    tampered_byte: int | None = None
    tampered_raw: str | None = None


class SourceStats(Model):
    name: str
    family: str
    format: str
    pack: str | None
    events: int
    parse_rate: float


class Totals(Model):
    received: int
    archived: int
    normalized: int
    blocked: int
    dead_letter: int
    eps: float
    parse_success_rate: float
    roundtrip_pass_rate: float


class DriftSignal(Model):
    source: str
    signal: str
    detail: str


class DashboardSummary(Model):
    window: str
    totals: Totals
    sources: list[SourceStats]
    drift: list[DriftSignal]


class DraftField(Model):
    name: str
    grok: str
    sample_value: str
    bytes: ByteRange
    mapped_to: str


class DetectedFormat(Model):
    fingerprint: str
    lines: int
    source_ip: str


class PackDraft(Model):
    draft_id: str
    detected: DetectedFormat
    generator: str
    sample: list[str]
    pattern: str
    confidence: float
    validation: list[VerifyCheck]
    fields: list[DraftField]
    ues_targets: list[str]


# ---------------------------------------------------------------- requests

class DraftRequest(Model):
    sample: list[str]


class FieldMapping(Model):
    name: str
    mapped_to: str


class ApproveRequest(Model):
    draft_id: str
    fields: list[FieldMapping]


class ApproveResult(Model):
    pack_id: str
    version: str
    draft_id: str
    mapped_fields: int
    signature: str
    status: str


class TamperResult(Model):
    event_id: str
    tampered_byte: int
    tampered_raw: str


class PackInfo(Model):
    pack_id: str
    version: str
    vendor: str
    product: str
    format: str
    digest: str
    signed: bool


class IngestRequest(Model):
    lines: list[str]
    source_host: str = "http-ingest"


class IngestResult(Model):
    accepted: int
    event_ids: list[str]
