import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("official product naming", () => {
  it("does not expose the retired English product name in TSX UI", async () => {
    const sourceRoot = path.join(process.cwd(), "src");
    const files = await collectTsxFiles(sourceRoot);
    const offenders: string[] = [];

    for (const file of files) {
      const source = await readFile(file, "utf8");
      if (/United\s+Pass/iu.test(source)) {
        offenders.push(path.relative(sourceRoot, file));
      }
    }

    expect(offenders).toEqual([]);
  });
});

async function collectTsxFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return collectTsxFiles(target);
    return entry.isFile() && entry.name.endsWith(".tsx") ? [target] : [];
  }));
  return nested.flat();
}
