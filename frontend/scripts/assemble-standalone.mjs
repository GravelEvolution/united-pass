import { access, cp, mkdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const standaloneRoot = path.join(projectRoot, ".next", "standalone");

await access(path.join(standaloneRoot, "server.js"));

const copies = [
  [path.join(projectRoot, "public"), path.join(standaloneRoot, "public")],
  [path.join(projectRoot, ".next", "static"), path.join(standaloneRoot, ".next", "static")],
];

for (const [source, destination] of copies) {
  const sourceStat = await stat(source);
  if (!sourceStat.isDirectory()) throw new Error(`Standalone source is not a directory: ${source}`);
  if (!destination.startsWith(`${standaloneRoot}${path.sep}`)) {
    throw new Error(`Refusing to write outside standalone output: ${destination}`);
  }
  await rm(destination, { force: true, recursive: true });
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true });
}

await access(path.join(standaloneRoot, "public"));
await access(path.join(standaloneRoot, ".next", "static"));
console.log("Standalone runtime assembled with public and static assets.");
