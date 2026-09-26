// Every screen gets its data through these functions.
// M2: they return mock JSON. M6 replaces the bodies with fetch() calls to the
// FastAPI backend - the signatures stay the same, so the pages do not change.
import type { DashboardSummary, PackDraft, ProofCarryingEvent, VerifyReport } from "./types";
import dashboard from "./mock/dashboard.json";
import events from "./mock/events.json";
import packDraft from "./mock/pack_draft.json";
import verify from "./mock/verify.json";

export const USING_MOCK_DATA = true;

const allEvents = events as ProofCarryingEvent[];
const reports = verify as Record<string, { clean: VerifyReport; tampered: VerifyReport }>;

const delay = <T,>(value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(value), 150));

export function getDashboard(): Promise<DashboardSummary> {
  return delay(dashboard as DashboardSummary);
}

export function listEvents(): Promise<ProofCarryingEvent[]> {
  return delay(allEvents);
}

export function getEvent(id: string): Promise<ProofCarryingEvent | undefined> {
  return delay(allEvents.find((e) => e.event_id === id));
}

export function verifyEvent(id: string, tamper = false): Promise<VerifyReport | undefined> {
  const r = reports[id];
  return delay(r ? (tamper ? r.tampered : r.clean) : undefined);
}

// Juniper SRX lines: a vendor with no pack yet, used as the "unknown device" in the demo.
export const DEMO_UNKNOWN_SAMPLE = (packDraft as PackDraft).sample.join("\n");

export function draftPack(_sample: string[]): Promise<PackDraft> {
  return delay(packDraft as PackDraft);
}

export function approvePack(draftId: string, fields: { name: string; mapped_to: string }[]) {
  return delay({
    pack_id: "juniper-srx-rt-flow",
    version: "0.1.0",
    draft_id: draftId,
    mapped_fields: fields.filter((f) => f.mapped_to !== "(ignore)").length,
    signature: "ed25519:MOCK-SIGNATURE-7c1e…",
    status: "signed → hot-loaded → source live",
  });
}
