// Data contract between the UI and the backend.
// The M3 API must return exactly these shapes (see src/mock/*.json for examples).

export type ByteRange = [start: number, end: number]; // half-open: bytes[start:end]

export interface ProvenanceEntry {
  field: string; // UES field path, e.g. "src_endpoint.ip"
  value: string | number; // normalized value
  raw: string | null; // exact source text, null for derived fields
  bytes: ByteRange | null; // where `raw` sits in the archived bytes
  transforms: string[]; // declared transformation chain, in order
  derived_from?: string[]; // for derived fields: which inputs produced it
}

export interface ProofCarryingEvent {
  event_id: string;
  status: "accepted" | "blocked" | "unparsed";
  received_at: string;
  source: { name: string; family: string; format: string; host: string };
  raw: { text: string; length: number; sha256: string; archive_ref: string };
  parser: { pack_id: string; version: string; digest: string };
  ues: Record<string, unknown> | null; // OCSF-aligned Universal Event Schema
  provenance: ProvenanceEntry[];
  roundtrip: {
    status: "pass" | "fail";
    total_bytes: number;
    field_bytes: number;
    unexplained: ByteRange[];
    reason?: string;
  };
  merkle: {
    leaf_index: number;
    tree_size: number;
    root: string;
    inclusion_proof: string[];
    status: "sealed" | "pending"; // covered by a signed tree head yet? (Verify checks the proof)
  };
}

export interface VerifyCheck {
  name: string;
  status: "pass" | "fail";
  detail: string;
}

export interface VerifyReport {
  event_id: string;
  tampered: boolean;
  overall: "verified" | "failed";
  checks: VerifyCheck[];
  tampered_byte?: number;
  tampered_raw?: string;
}

export interface SourceStats {
  name: string;
  family: string;
  format: string;
  pack: string | null;
  events: number;
  parse_rate: number;
}

export interface DashboardSummary {
  window: string;
  totals: {
    received: number;
    archived: number;
    normalized: number;
    blocked: number;
    dead_letter: number;
    eps: number;
    parse_success_rate: number;
    roundtrip_pass_rate: number;
  };
  sources: SourceStats[];
  drift: { source: string; signal: string; detail: string }[];
}

export interface DraftField {
  name: string;
  grok: string;
  sample_value: string;
  bytes: ByteRange;
  mapped_to: string;
}

export interface PackDraft {
  draft_id: string;
  detected: { fingerprint: string; lines: number; source_ip: string };
  generator: string;
  sample: string[];
  pattern: string;
  confidence: number;
  validation: VerifyCheck[];
  fields: DraftField[];
  ues_targets: string[];
}
