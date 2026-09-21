import { describe, expect, it } from "vitest";
import { getControlledAvatarUrl } from "./avatar-url";

describe("getControlledAvatarUrl", () => {
  it("keeps a controlled same-origin avatar path", () => {
    const avatarUrl = "/api/v1/media/avatars/user_abc123?v=3";
    expect(getControlledAvatarUrl(avatarUrl)).toBe(avatarUrl);
  });

  it("rejects missing, external, and unrelated avatar values", () => {
    expect(getControlledAvatarUrl(undefined)).toBeUndefined();
    expect(getControlledAvatarUrl("https://cdn.example.com/avatar.png")).toBeUndefined();
    expect(getControlledAvatarUrl("//cdn.example.com/avatar.png")).toBeUndefined();
    expect(getControlledAvatarUrl("data:image/png;base64,AAAA")).toBeUndefined();
    expect(getControlledAvatarUrl("/api/v1/media/other/user_abc123")).toBeUndefined();
  });
});
