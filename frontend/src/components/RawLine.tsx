import { segment } from "../lib/bytes";
import type { ByteRange } from "../types";

interface Props {
  text: string;
  highlights: { key: string; range: ByteRange }[];
  active?: string | null; // key currently hovered/selected elsewhere
  onHover?: (key: string | null) => void;
  tone?: "field" | "danger";
}

/** A raw log line with byte ranges highlighted. Hovering a highlight reports its key. */
export function RawLine({ text, highlights, active, onHover, tone = "field" }: Props) {
  return (
    <pre className="raw-line">
      {segment(text, highlights).map((s) =>
        s.key === null ? (
          <span key={s.range[0]}>{s.text}</span>
        ) : (
          <mark
            key={s.range[0]}
            className={`hl hl-${tone}${s.key === active ? " hl-active" : ""}`}
            title={`${s.key}  bytes[${s.range[0]}:${s.range[1]}]`}
            onMouseEnter={() => onHover?.(s.key)}
            onMouseLeave={() => onHover?.(null)}
          >
            {s.text}
          </mark>
        ),
      )}
    </pre>
  );
}
