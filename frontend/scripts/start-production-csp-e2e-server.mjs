import { spawn } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const standaloneRoot = path.join(projectRoot, ".next", "standalone");
const hostname = "127.0.0.1";
const port = Number(process.env.UP_CSP_E2E_PORT ?? "3011");

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("UP_CSP_E2E_PORT must be a valid TCP port");
}

const apiServer = createHttpServer((request, response) => {
  if (request.url === "/api/v1/auth/providers") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ items: [] }));
    return;
  }
  response.writeHead(401, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: { code: "session.unauthenticated", message: "unauthenticated" } }));
});

await new Promise((resolve, reject) => {
  apiServer.once("error", reject);
  apiServer.listen(0, hostname, resolve);
});
const apiAddress = apiServer.address();
if (typeof apiAddress !== "object" || !apiAddress) {
  throw new Error("Production CSP test API did not bind");
}

const child = spawn(process.execPath, ["server.js"], {
  cwd: standaloneRoot,
  env: {
    ...process.env,
    API_BASE_URL: `http://${hostname}:${apiAddress.port}/api/v1`,
    HOSTNAME: hostname,
    PORT: String(port),
  },
  stdio: "inherit",
  windowsHide: true,
});

let closing = false;
async function close(exitCode = 0) {
  if (closing) return;
  closing = true;
  if (child.exitCode === null) child.kill("SIGTERM");
  await new Promise((resolve) => apiServer.close(() => resolve()));
  process.exit(exitCode);
}

process.once("SIGINT", () => void close());
process.once("SIGTERM", () => void close());
child.once("error", (error) => {
  console.error(error);
  void close(1);
});
child.once("exit", (code) => void close(code ?? 1));
