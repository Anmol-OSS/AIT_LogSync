import type { ReactNode } from "react";
import type { VerifyCheck } from "../types";

type Tone = "ok" | "bad" | "warn" | "muted";

export function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function statusTone(status: string): Tone {
  if (["accepted", "pass", "verified"].includes(status)) return "ok";
  if (["blocked", "fail", "failed"].includes(status)) return "bad";
  return "warn";
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

export function Loading() {
  return <p className="muted">Loading…</p>;
}

export const pct = (x: number) => `${(x * 100).toFixed(x === 1 ? 0 : 2)}%`;
export const num = (x: number) => x.toLocaleString("en-IN");
