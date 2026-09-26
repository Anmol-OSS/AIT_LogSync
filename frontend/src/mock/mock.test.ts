// The mock data defines the API contract, so it must be internally consistent:
// every provenance byte range has to point at exactly the text it claims.
import { describe, expect, it } from "vitest";
import { sliceBytes } from "../lib/bytes";
import type { PackDraft, ProofCarryingEvent, VerifyReport } from "../types";
import eventsJson from "./events.json";
import draftJson from "./pack_draft.json";
import verifyJson from "./verify.json";

const events = eventsJson as ProofCarryingEvent[];
const draft = draftJson as PackDraft;
const reports = verifyJson as Record<string, { clean: VerifyReport; tampered: VerifyReport }>;

describe("mock events", () => {
  it("has one accepted event per source family plus a blocked one", () => {
    const families = new Set(events.filter((e) => e.status === "accepted").map((e) => e.source.family));
    expect(families.size).toBe(5);
    expect(events.some((e) => e.status === "blocked")).toBe(true);
  });

  it("accepted events carry the core UES fields the UI summarises", () => {
    const core = ["time", "src_endpoint.ip", "dst_endpoint.ip", "dst_endpoint.port", "disposition"];
    for (const e of events.filter((e) => e.status === "accepted")) {
      const fields = e.provenance.map((p) => p.field);
      for (const f of core) expect(fields, `${e.event_id} missing ${f}`).toContain(f);
    }
  });

  for (const e of events) {
    it(`${e.event_id}: provenance bytes match raw text`, () => {
      expect(new TextEncoder().encode(e.raw.text).length).toBe(e.raw.length);
      for (const p of e.provenance) {
        if (p.bytes) expect(sliceBytes(e.raw.text, p.bytes)).toBe(p.raw);
        else expect(p.derived_from?.length).toBeGreaterThan(0);
      }
    });
  }
});

describe("mock verify reports", () => {
  it("clean reports pass all five checks, tampered ones fail", () => {
    for (const { clean, tampered } of Object.values(reports)) {
      expect(clean.checks).toHaveLength(5);
      expect(clean.checks.every((c) => c.status === "pass")).toBe(true);
      expect(tampered.overall).toBe("failed");
      expect(tampered.checks.some((c) => c.status === "fail")).toBe(true);
    }
  });
});

describe("mock pack draft", () => {
  it("field byte ranges point at their sample values", () => {
    for (const f of draft.fields) expect(sliceBytes(draft.sample[0], f.bytes)).toBe(f.sample_value);
  });
});
