import { describe, it, expect } from "vitest";
import { formatPersonaLabel } from "./persona";

describe("formatPersonaLabel", () => {
  it("shows '外部用户' for consumer-only persona", () => {
    expect(formatPersonaLabel(["consumer"])).toBe("外部用户");
  });

  it("shows '员工' for employee-only persona", () => {
    expect(formatPersonaLabel(["employee"])).toBe("员工");
  });

  it("shows '外部用户 · 员工' for dual persona", () => {
    expect(formatPersonaLabel(["consumer", "employee"])).toBe("外部用户 · 员工");
  });

  it("shows '外部用户' as default for empty personas", () => {
    expect(formatPersonaLabel([])).toBe("外部用户");
  });

  it("treats persona order consistently", () => {
    expect(formatPersonaLabel(["employee", "consumer"])).toBe("外部用户 · 员工");
  });
});
