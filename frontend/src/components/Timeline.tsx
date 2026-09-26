import { useState } from "react";
import type { TimelinePoint } from "../types";

// Status colours are reserved for state (accepted / dead-letter / blocked) and
// always appear with a text label in the legend and tooltip - never colour alone.
const SERIES = [
  { key: "accepted", label: "accepted", color: "var(--st-good)" },
  { key: "unparsed", label: "dead-letter", color: "var(--st-warn)" },
  { key: "blocked", label: "blocked", color: "var(--st-crit)" },
] as const;

const W = 720, H = 160, PAD_L = 36, PAD_T = 12, PAD_B = 18, GAP = 2;

/** Smallest 1-2-5 × 10^k value >= v, for a readable axis maximum. */
export function niceCeil(v: number): number {
  const base = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1))));
  return [1, 2, 5, 10].map((m) => m * base).find((c) => c >= v)!;
}

/** Events per second over the last 60 s, stacked by status, with a hover tooltip. */
export function Timeline({ points }: { points: TimelinePoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const totals = points.map((p) => p.accepted + p.unparsed + p.blocked);
  const peak = Math.max(1, ...totals);
  const niceMax = niceCeil(peak);
  const plotW = W - PAD_L, plotH = H - PAD_B - PAD_T;
  const slot = plotW / Math.max(points.length, 1);
  const barW = Math.max(slot - GAP, 1);
  const y = (v: number) => (v / niceMax) * plotH;
  const sum = totals.reduce((a, b) => a + b, 0);
  const h = hover !== null ? points[hover] : null;

  return (
    <div className="timeline">
      <div className="legend" aria-hidden="true">
        {SERIES.map((s) => (
          <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>
        ))}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" preserveAspectRatio="none"
           aria-label={`Events per second over the last 60 seconds: ${sum} events, peak ${peak} per second`}
           onMouseLeave={() => setHover(null)}>
        {[0.5, 1].map((f) => (
          <g key={f}>
            <line x1={PAD_L} x2={W} y1={PAD_T + plotH - f * plotH} y2={PAD_T + plotH - f * plotH} className="grid" />
            <text x={PAD_L - 6} y={PAD_T + plotH - f * plotH + 4} className="axis" textAnchor="end">{Math.round(f * niceMax)}</text>
          </g>
        ))}
        <line x1={PAD_L} x2={W} y1={PAD_T + plotH} y2={PAD_T + plotH} className="baseline" />
        {points.map((p, i) => {
          let acc = 0;
          const x = PAD_L + i * slot + GAP / 2;
          return (
            <g key={p.t} opacity={hover === null || hover === i ? 1 : 0.45}>
              {SERIES.map((s) => {
                const v = p[s.key];
                if (!v) return null;
                const hgt = Math.max(y(v) - (acc > 0 ? GAP : 0), 1);
                const top = PAD_T + plotH - y(acc) - y(v);
                acc += v;
                return <rect key={s.key} x={x} y={top} width={barW} height={hgt} rx={Math.min(2, barW / 2)} fill={s.color} />;
              })}
              <rect x={PAD_L + i * slot} y={0} width={slot} height={PAD_T + plotH} fill="transparent" onMouseEnter={() => setHover(i)} />
            </g>
          );
        })}
        <text x={PAD_L} y={H - 4} className="axis">−60 s</text>
        <text x={W} y={H - 4} className="axis" textAnchor="end">now</text>
      </svg>
      {h && (
        <div className="tooltip" style={{ left: `${((PAD_L + (hover! + 0.5) * slot) / W) * 100}%` }}>
          <strong>{new Date(h.t * 1000).toLocaleTimeString()}</strong>
          {SERIES.map((s) => (
            <div key={s.key}><i style={{ background: s.color }} />{s.label} <b>{h[s.key]}</b></div>
          ))}
        </div>
      )}
    </div>
  );
}
