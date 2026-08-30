import { describe, expect, it } from "vitest";
import { hasDreamUPAdministrationAccess } from "./permissions";

describe("DreamUP 管理入口可见性", () => {
  it("只在后端返回至少一个获授权活动时显示", () => {
    expect(hasDreamUPAdministrationAccess([])).toBe(false);
    expect(hasDreamUPAdministrationAccess([{ eventId: "event", displayName: "上海站" }])).toBe(true);
  });
});
