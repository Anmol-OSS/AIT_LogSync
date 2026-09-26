// Byte-range helpers. Provenance offsets are BYTE offsets into the archived raw
// line, not JavaScript string indexes - they differ as soon as a log contains a
// non-ASCII character, so we always slice the UTF-8 bytes.
import type { ByteRange } from "../types";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function sliceBytes(text: string, [start, end]: ByteRange): string {
  return decoder.decode(encoder.encode(text).slice(start, end));
}

export interface Segment {
  text: string;
  range: ByteRange;
  key: string | null; // which highlight this segment belongs to, null = plain text
}

/**
 * Split `text` into plain and highlighted segments.
 * `highlights` maps a key (e.g. a field name) to its byte range. Ranges must not overlap.
 */
export function segment(text: string, highlights: { key: string; range: ByteRange }[]): Segment[] {
  const bytes = encoder.encode(text);
  const sorted = [...highlights].sort((a, b) => a.range[0] - b.range[0]);
  const out: Segment[] = [];
  let pos = 0;
  for (const h of sorted) {
    const [start, end] = h.range;
    if (start < pos || end > bytes.length || start > end) {
      throw new Error(`bad or overlapping range ${h.key} [${start}:${end}]`);
    }
    if (start > pos) out.push({ text: decoder.decode(bytes.slice(pos, start)), range: [pos, start], key: null });
    out.push({ text: decoder.decode(bytes.slice(start, end)), range: [start, end], key: h.key });
    pos = end;
  }
  if (pos < bytes.length) {
    out.push({ text: decoder.decode(bytes.slice(pos)), range: [pos, bytes.length], key: null });
  }
  return out;
}
