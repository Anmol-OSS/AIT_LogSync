import type { ReactNode } from "react";
import type { ProofCarryingEvent, VerifyCheck } from "../types";

type Tone = "ok" | "bad" | "warn" | "muted";

export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function statusTone(status: string): Tone {
  if (["accepted", "pass", "verified", "sealed"].includes(status)) return "ok";
  if (["blocked", "fail", "failed"].includes(status)) return "bad";
  if (["unparsed", "pending"].includes(status)) return "warn";
  return "muted";
}

export function Stat({ label, value, tone }: { label: string; value: string; tone?: Tone }) {
  return (
    <div className="stat">
      <div className={`stat-value${tone ? ` text-${tone}` : ""}`}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function CheckList({ checks }: { checks: VerifyCheck[] }) {
  return (
    <ul className="checks">
      {checks.map((c) => (
        <li key={c.name}>
          <span className={`check-mark text-${c.status === "pass" ? "ok" : "bad"}`}>
            {c.status === "pass" ? "✓" : "✗"}
          </span>
          <code className="check-name">{c.name}</code>
          <Pill tone={statusTone(c.status)}>{c.status.toUpperCase()}</Pill>
          <span className="check-detail">{c.detail}</span>
        </li>
      ))}
    </ul>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return <p className="muted">{what}…</p>;
}

export function ErrorNote({ error }: { error?: string }) {
  if (!error) return null;
  return <p className="error-note">Could not reach the LogSync API: {error}. Is <code>logsync serve</code> running?</p>;
}

/** One-line human summary of an event, e.g. "10.2.1.7 → 8.8.8.8:53 · Allowed". */
export function summary(e: ProofCarryingEvent): string {
  if (e.status !== "accepted") return e.roundtrip.reason ?? e.status;
  const f = Object.fromEntries(e.provenance.map((p) => [p.field, p.value]));
  const dst = f["dst_endpoint.ip"] ? `${f["dst_endpoint.ip"]}${f["dst_endpoint.port"] !== undefined ? ":" + f["dst_endpoint.port"] : ""}` : "?";
  return `${f["src_endpoint.ip"] ?? "?"} → ${dst}${f["disposition"] ? " · " + f["disposition"] : ""}`;
}

export const pct = (x: number) => `${(x * 100).toFixed(x === 1 || x === 0 ? 0 : 2)}%`;
export const num = (x: number) => x.toLocaleString("en-IN");
