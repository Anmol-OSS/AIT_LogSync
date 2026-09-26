import { describe, expect, it } from "vitest";
import { segment, sliceBytes } from "./bytes";

describe("sliceBytes", () => {
  it("slices by byte offset, not string index", () => {
    // "é" is 2 bytes in UTF-8, so "srcip" starts at byte 7 but string index 6
    const text = "hé:ok srcip=10.2.1.7";
    expect(sliceBytes(text, [13, 21])).toBe("10.2.1.7");
    expect(text.slice(13, 21)).not.toBe("10.2.1.7");
  });
});

describe("segment", () => {
  const text = "src=10.2.1.7 dst=8.8.8.8";

  it("covers every byte exactly once, in order", () => {
    const segs = segment(text, [
      { key: "dst", range: [17, 24] },
      { key: "src", range: [4, 12] },
    ]);
    expect(segs.map((s) => s.text).join("")).toBe(text);
    expect(segs.filter((s) => s.key).map((s) => [s.key, s.text])).toEqual([
      ["src", "10.2.1.7"],
      ["dst", "8.8.8.8"],
    ]);
  });

  it("returns one plain segment with no highlights", () => {
    expect(segment(text, [])).toEqual([{ text, range: [0, text.length], key: null }]);
  });

  it("rejects overlapping or out-of-bounds ranges", () => {
    expect(() => segment(text, [{ key: "a", range: [0, 6] }, { key: "b", range: [4, 8] }])).toThrow();
    expect(() => segment(text, [{ key: "a", range: [20, 99] }])).toThrow();
  });
});
