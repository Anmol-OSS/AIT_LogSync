import { describe, expect, it } from "vitest";
import { niceCeil } from "./Timeline";

describe("niceCeil", () => {
  it("rounds up to the next 1-2-5 step", () => {
    expect([0, 1, 3, 7, 12, 180, 350, 900].map(niceCeil)).toEqual([1, 1, 5, 10, 20, 200, 500, 1000]);
  });
});
