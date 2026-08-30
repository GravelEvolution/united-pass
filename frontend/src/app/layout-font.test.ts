import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("production font loading", () => {
  it("does not require a remote font during build", async () => {
    const layout = await readFile(path.join(process.cwd(), "src/app/layout.tsx"), "utf8");
    const globals = await readFile(path.join(process.cwd(), "src/app/globals.css"), "utf8");

    expect(layout).not.toContain("next/font/google");
    expect(layout).not.toContain("Noto_Sans_SC");
    expect(globals).toContain("--font-sans:");
    expect(globals).toContain('"PingFang SC"');
    expect(globals).toContain('"Microsoft YaHei"');
  });
});
