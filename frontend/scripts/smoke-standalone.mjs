import { spawn } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const standaloneRoot = path.join(projectRoot, ".next", "standalone");
const hostname = "127.0.0.1";
const port = await reservePort(hostname);
const origin = `http://${hostname}:${port}`;
const apiServer = createHttpServer((request, response) => {
  if (request.url === "/api/v1/auth/providers") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ items: [] }));
    return;
  }
  response.writeHead(404, { "content-type": "application/json" });
  response.end(JSON.stringify({ code: "not_found" }));
});
await new Promise((resolve, reject) => {
  apiServer.once("error", reject);
  apiServer.listen(0, hostname, resolve);
});
const apiAddress = apiServer.address();
if (typeof apiAddress !== "object" || !apiAddress) throw new Error("Smoke API did not bind");
const child = spawn(process.execPath, ["server.js"], {
  cwd: standaloneRoot,
  env: {
    ...process.env,
    API_BASE_URL: `http://${hostname}:${apiAddress.port}/api/v1`,
    HOSTNAME: hostname,
    NEXT_PUBLIC_USE_MOCK: "false",
    PORT: String(port),
  },
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
});

let output = "";
for (const stream of [child.stdout, child.stderr]) {
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    output = `${output}${chunk}`.slice(-8_192);
  });
}

try {
  const register = await waitForResponse(`${origin}/register`, child);
  const registerHtml = await register.text();
  assert(register.status === 200, `Registration route returned ${register.status}`);
  const registrationEnabled = process.env.UP_PUBLIC_REGISTRATION_ENABLED === "true";
  if (registrationEnabled) {
    assert(registerHtml.includes("创建统一账户"), "Open-registration copy is missing");
    assert(/<form\b/iu.test(registerHtml), "Registration form is missing");
    assert(registerHtml.includes('name="passwordConfirmation"'), "Registration password confirmation is missing");
  } else {
    assert(registerHtml.includes("注册暂未开放"), "Closed-registration copy is missing");
    assert(!/<form\b/iu.test(registerHtml), "Closed registration route rendered a form");
    assert(!/<input\b/iu.test(registerHtml), "Closed registration route rendered an input");
  }

  const login = await fetch(`${origin}/login`, { redirect: "manual" });
  assert(login.status === 200, `Login route returned ${login.status}`);
  const loginHtml = await login.text();
  assert(/<form\b/iu.test(loginHtml), "Login form is missing");
  assert(
    loginHtml.includes(registrationEnabled ? "立即注册" : "查看注册状态"),
    "Login registration link is missing",
  );

  const assetPaths = new Set([
    "/brand/gravel-evolution-logo.png",
    ...extractStaticAssets(registerHtml),
    ...extractStaticAssets(loginHtml),
  ]);
  assert(assetPaths.size > 2, "No standalone static assets were discovered");
  for (const assetPath of assetPaths) {
    const response = await fetch(new URL(assetPath, origin), { redirect: "manual" });
    assert(response.status === 200, `Standalone asset ${assetPath} returned ${response.status}`);
  }

  console.log(`Standalone smoke passed: register/login and ${assetPaths.size} assets.`);
} catch (error) {
  if (output.trim()) console.error(output.trim());
  throw error;
} finally {
  await stopChild(child);
  await new Promise((resolve, reject) => apiServer.close((error) => error ? reject(error) : resolve()));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function extractStaticAssets(html) {
  return [...html.matchAll(/(?:href|src)="([^"]+)"/giu)]
    .map((match) => match[1].replaceAll("&amp;", "&"))
    .filter((value) => value.startsWith("/_next/static/"));
}

async function reservePort(host) {
  const server = createTcpServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, resolve);
  });
  const address = server.address();
  const selectedPort = typeof address === "object" && address ? address.port : null;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (!selectedPort) throw new Error("Could not reserve a smoke-test port");
  return selectedPort;
}

async function waitForResponse(url, processHandle) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (processHandle.exitCode !== null) {
      throw new Error(`Standalone server exited early with code ${processHandle.exitCode}`);
    }
    try {
      return await fetch(url, { redirect: "manual" });
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error("Standalone server did not become ready within 15 seconds");
}

async function stopChild(processHandle) {
  if (processHandle.exitCode !== null) return;
  processHandle.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise((resolve) => processHandle.once("exit", () => resolve(true))),
    new Promise((resolve) => setTimeout(() => resolve(false), 5_000)),
  ]);
  if (!exited) processHandle.kill("SIGKILL");
}
