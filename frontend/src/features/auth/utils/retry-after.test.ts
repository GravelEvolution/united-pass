import { describe, expect, it } from "vitest";
import { formatRetryAfter } from "./retry-after";

describe("formatRetryAfter", () => {
  it.each<[number, string]>([
    [30, "30 秒"],
    [61, "2 分钟"],
    [3_600, "1 小时"],
    [30_000, "8 小时 20 分钟"],
    [86_400, "1 天"],
    [93_540, "1 天 2 小时"],
  ])("formats %s seconds as a readable duration", (seconds, expected) => {
    expect(formatRetryAfter(seconds)).toBe(expected);
  });

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])("rejects invalid duration %s", (seconds) => {
    expect(formatRetryAfter(seconds)).toBeUndefined();
  });
});
