// Every screen gets its data through these functions - one place that knows the API.
// Same-origin "/api": in production FastAPI serves this UI; in development Vite
// proxies /api to the backend (vite.config.ts).
import type {
  DashboardSummary, PackDraft, PackInfo, ProofCarryingEvent, VerifyReport,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

const post = <T,>(path: string, body?: unknown) =>
  call<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export function getHealth(): Promise<{ status: string; version: string; service: string }> {
  return call("/health");
}

export function getDashboard(): Promise<DashboardSummary> {
  return call("/dashboard");
}

export function listEvents(opts: { limit?: number; status?: string; source?: string } = {}): Promise<ProofCarryingEvent[]> {
  const q = new URLSearchParams();
  q.set("limit", String(opts.limit ?? 50));
  if (opts.status) q.set("status", opts.status);
  if (opts.source) q.set("source", opts.source);
  return call(`/events?${q}`);
}

export function getEvent(id: string): Promise<ProofCarryingEvent> {
  return call(`/events/${encodeURIComponent(id)}`);
}

export function verifyEvent(id: string): Promise<VerifyReport> {
  return post(`/events/${encodeURIComponent(id)}/verify`);
}

export function tamperEvent(id: string): Promise<{ event_id: string; tampered_byte: number; tampered_raw: string }> {
  return post(`/demo/tamper/${encodeURIComponent(id)}`);
}

export function restoreEvent(id: string): Promise<{ restored: string }> {
  return post(`/demo/restore/${encodeURIComponent(id)}`);
}

export function listPacks(): Promise<PackInfo[]> {
  return call("/packs");
}

export function draftPack(sample: string[]): Promise<PackDraft> {
  return post("/packs/draft", { sample });
}

export interface ApproveResult {
  pack_id: string;
  version: string;
  draft_id: string;
  mapped_fields: number;
  signature: string;
  status: string;
}

export function approvePack(draftId: string, fields: { name: string; mapped_to: string }[]): Promise<ApproveResult> {
  return post("/packs/approve", { draft_id: draftId, fields });
}

export function ingestLines(lines: string[], sourceHost = "ui"): Promise<{ accepted: number; event_ids: string[] }> {
  return post("/ingest", { lines, source_host: sourceHost });
}
