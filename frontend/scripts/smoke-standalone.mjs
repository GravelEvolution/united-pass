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
  const registerNonce = assertSecurityHeaders(register, "Registration");
  const registerHtml = await register.text();
  assert(register.status === 200, `Registration route returned ${register.status}`);
  assertScriptNonces(registerHtml, registerNonce, "Registration");
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

  const login = await fetch(`${origin}/login`, {
    redirect: "manual",
    headers: { Accept: "text/html" },
  });
  const loginNonce = assertSecurityHeaders(login, "Login");
  assert(login.status === 200, `Login route returned ${login.status}`);
  const loginHtml = await login.text();
  assertScriptNonces(loginHtml, loginNonce, "Login");
  assert(loginNonce !== registerNonce, "Document CSP nonce was reused across requests");
  assert(/<form\b/iu.test(loginHtml), "Login form is missing");
  assert(
    loginHtml.includes(registrationEnabled ? "立即注册" : "查看注册状态"),
    "Login registration link is missing",
  );

  // Accept is caller-controlled and cannot decide whether a Next.js route is
  // an HTML document. A mismatched value must still receive the document CSP.
  const mismatchedAcceptLogin = await fetch(`${origin}/login`, {
    redirect: "manual",
    headers: { Accept: "application/json" },
  });
  const mismatchedAcceptNonce = assertSecurityHeaders(
    mismatchedAcceptLogin,
    "Login with mismatched Accept",
  );
  const mismatchedAcceptHtml = await mismatchedAcceptLogin.text();
  assert(mismatchedAcceptLogin.status === 200, "Mismatched-Accept login did not render");
  assert(
    mismatchedAcceptLogin.headers.get("content-type")?.startsWith("text/html"),
    "Mismatched-Accept login was not an HTML document",
  );
  assertScriptNonces(mismatchedAcceptHtml, mismatchedAcceptNonce, "Mismatched-Accept login");

  const documentNonces = new Set([registerNonce, loginNonce, mismatchedAcceptNonce]);
  for (const legalPath of ["/privacy", "/terms"]) {
    const legal = await fetch(`${origin}${legalPath}`, {
      redirect: "manual",
      headers: { Accept: "text/html" },
    });
    const legalNonce = assertSecurityHeaders(legal, legalPath);
    const legalHtml = await legal.text();
    assert(legal.status === 200, `${legalPath} route returned ${legal.status}`);
    assertScriptNonces(legalHtml, legalNonce, legalPath);
    documentNonces.add(legalNonce);
  }
  assert(documentNonces.size === 5, "Document CSP nonce was reused across requests");

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

  const optimizedImagePath = "/_next/image?url=%2Fbrand%2Fgravel-evolution-logo.png&w=64&q=75";
  const optimizedImage = await fetch(new URL(optimizedImagePath, origin), { redirect: "manual" });
  assert(
    optimizedImage.status === 200,
    `Standalone image optimizer returned ${optimizedImage.status}`,
  );
  assert(
    optimizedImage.headers.get("content-type")?.startsWith("image/"),
    "Standalone image optimizer did not return an image",
  );
  assert((await optimizedImage.arrayBuffer()).byteLength > 0, "Optimized image is empty");

  console.log(
    `Standalone smoke passed: register/login/privacy/terms CSP, image optimization and ${assetPaths.size} assets.`,
  );
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

function assertSecurityHeaders(response, label) {
  const policy = response.headers.get("content-security-policy") ?? "";
  const nonce = policy.match(/'nonce-([^']+)'/u)?.[1] ?? "";
  assert(nonce.length >= 22, `${label} response CSP nonce is missing or too short`);
  assert(policy.includes("'strict-dynamic'"), `${label} response CSP is not strict-dynamic`);
  assert(policy.includes("frame-ancestors 'none'"), `${label} response allows framing`);
  assert(!policy.includes("'unsafe-eval'"), `${label} production CSP allows eval`);
  assert(
    response.headers.get("strict-transport-security") === "max-age=31536000; includeSubDomains",
    `${label} response is missing HSTS`,
  );
  assert(response.headers.get("x-content-type-options") === "nosniff", `${label} response can be MIME-sniffed`);
  assert(response.headers.get("x-frame-options") === "DENY", `${label} response is missing legacy frame denial`);
  assert(response.headers.get("referrer-policy") === "no-referrer", `${label} response leaks referrers`);
  assert(response.headers.get("cache-control") === "no-store", `${label} nonce-bearing response is cacheable`);
  return nonce;
}

function assertScriptNonces(html, nonce, label) {
  const scriptTags = [...html.matchAll(/<script\b[^>]*>/giu)].map((match) => match[0]);
  assert(scriptTags.length > 0, `${label} response has no Next.js scripts`);
  for (const scriptTag of scriptTags) {
    assert(scriptTag.includes(`nonce="${nonce}"`), `${label} contains a script without its CSP nonce`);
  }
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
      return await fetch(url, {
        redirect: "manual",
        headers: { Accept: "text/html" },
      });
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
