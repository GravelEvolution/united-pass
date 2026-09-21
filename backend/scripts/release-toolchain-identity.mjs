import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";

const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_VERSION_OUTPUT = /^git version (\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?)\r?\n?$/u;
const GO_VERSION = /^go1\.\d+(?:\.\d+)?(?:[a-z0-9.-]+)?$/u;
const NODE_VERSION = /^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u;
const MAX_PROTECTED_TREE_FILES = 250_000;
const MAX_PROTECTED_TREE_BYTES = 16 * 1024 * 1024 * 1024;

export const UNITED_PASS_RELEASE_ENVIRONMENT_POLICY = Object.freeze({
  schemaVersion: 1,
  inheritedEnvironment: "none",
  commandInvocation: "absolute-ci-pinned-executables",
  homeAndXdg: "fresh-private-directories",
  temporaryAndBuildCache: "fresh-private-directories",
  goModuleCache: "external-read-only-ci-pinned-complete-tree",
  goEnvironment: "off",
  goProxy: "off",
  goChecksumDatabase: "off",
  goToolchainSelection: "local",
  goWorkspace: "off",
  goVcs: "off",
  cgo: "off",
  target: "linux-amd64",
  gitSystemAndGlobalConfiguration: "disabled",
  gitHooksAttributesExcludesCredentialsDiffSsh: "disabled",
  gitProtocols: "local-file-only",
});

export const UNITED_PASS_RELEASE_ENVIRONMENT_SHA256 = sha256(
  Buffer.from(`${JSON.stringify(UNITED_PASS_RELEASE_ENVIRONMENT_POLICY)}\n`, "utf8"),
);

export function assertUnitedPassReleaseHost(
  platform = process.platform,
  arch = process.arch,
  stage = "release builder",
) {
  invariant(platform === "linux" && arch === "x64",
    `United Pass ${stage} must run on protected linux/x64`);
}

export function resolveProtectedNodeIdentity({
  executablePath = process.execPath,
  expectedSha256,
  expectedVersion,
  sourceRoot,
}) {
  invariant(SHA256.test(expectedSha256 ?? ""),
    "United Pass release Node runtime requires a CI-pinned executable SHA-256");
  invariant(NODE_VERSION.test(expectedVersion ?? ""),
    "United Pass release Node runtime requires a CI-pinned exact version");
  invariant(typeof executablePath === "string" && path.isAbsolute(executablePath),
    "United Pass release Node executable must be absolute");
  const runtime = readProtectedRegularFile(executablePath, "United Pass release Node executable", {
    executable: true,
    maximumBytes: 512 * 1024 * 1024,
    sourceRoot,
  });
  invariant(sameLocalPath(runtime.path, realpathSync.native(process.execPath)),
    "United Pass release script must run under the CI-pinned Node executable");
  invariant(runtime.sha256 === expectedSha256,
    "United Pass release Node executable does not match its CI-pinned SHA-256");
  invariant(process.version === expectedVersion,
    "United Pass release Node runtime does not match its CI-pinned exact version");
  invariant(process.platform === "linux" && process.arch === "x64",
    "United Pass release Node runtime must execute on protected linux/x64");
  const version = execFileSync(runtime.path, ["--version"], {
    encoding: "utf8",
    env: {
      HOME: "/nonexistent/moonstone-united-pass-node/home",
      LANG: "C",
      LC_ALL: "C",
      PATH: path.dirname(runtime.path),
      TEMP: "/nonexistent/moonstone-united-pass-node/temporary",
      TMP: "/nonexistent/moonstone-united-pass-node/temporary",
      TMPDIR: "/nonexistent/moonstone-united-pass-node/temporary",
      TZ: "UTC",
      XDG_CACHE_HOME: "/nonexistent/moonstone-united-pass-node/xdg-cache",
      XDG_CONFIG_HOME: "/nonexistent/moonstone-united-pass-node/xdg-config",
      XDG_DATA_HOME: "/nonexistent/moonstone-united-pass-node/xdg-data",
    },
    maxBuffer: 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10_000,
  }).trim();
  invariant(version === expectedVersion,
    "United Pass release Node executable reports an unexpected version");
  const finalRuntime = readProtectedRegularFile(runtime.path, "United Pass release Node executable", {
    executable: true,
    maximumBytes: 512 * 1024 * 1024,
    sourceRoot,
  });
  invariant(finalRuntime.sha256 === runtime.sha256 && sameSnapshot(finalRuntime.stat, runtime.stat),
    "United Pass release Node executable changed while it was verified");
  return Object.freeze({
    path: runtime.path,
    sha256: runtime.sha256,
    stat: runtime.stat,
    version,
    platform: process.platform,
    arch: process.arch,
  });
}

export function createUnitedPassGitEnvironment(executablePath, isolation) {
  for (const [label, value] of Object.entries({
    home: isolation?.home,
    xdgConfig: isolation?.xdgConfig,
    gitTemplate: isolation?.gitTemplate,
    temporary: isolation?.temporary,
  })) {
    invariant(typeof value === "string" && path.isAbsolute(value),
      `United Pass release Git ${label} directory must be absolute`);
  }
  invariant(typeof executablePath === "string" && path.isAbsolute(executablePath),
    "United Pass release Git executable must be absolute");
  const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
  const enforced = [
    ["core.fsmonitor", "false"],
    ["core.autocrlf", "false"],
    ["core.hooksPath", nullDevice],
    ["core.attributesFile", nullDevice],
    ["core.excludesFile", nullDevice],
    ["credential.helper", ""],
    ["diff.external", ""],
    ["core.sshCommand", ""],
  ];
  const environment = {
    ALL_PROXY: "",
    GIT_ALLOW_PROTOCOL: "file",
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_COUNT: String(enforced.length),
    GIT_EXTERNAL_DIFF: "",
    GIT_EXEC_PATH: path.dirname(executablePath),
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat",
    GIT_PROTOCOL_FROM_USER: "0",
    GIT_SSH: "",
    GIT_SSH_COMMAND: "",
    GIT_TEMPLATE_DIR: isolation.gitTemplate,
    GIT_TERMINAL_PROMPT: "0",
    HOME: isolation.home,
    HTTPS_PROXY: "",
    HTTP_PROXY: "",
    LANG: "C",
    LC_ALL: "C",
    NO_PROXY: "*",
    PATH: path.dirname(executablePath),
    TEMP: isolation.temporary,
    TMP: isolation.temporary,
    TMPDIR: isolation.temporary,
    TZ: "UTC",
    XDG_CONFIG_HOME: isolation.xdgConfig,
    all_proxy: "",
    http_proxy: "",
    https_proxy: "",
    no_proxy: "*",
  };
  enforced.forEach(([key, value], index) => {
    environment[`GIT_CONFIG_KEY_${index}`] = key;
    environment[`GIT_CONFIG_VALUE_${index}`] = value;
  });
  return Object.freeze(environment);
}

export function createUnitedPassGoEnvironment(toolchainDirectory, moduleCacheDirectory, isolation) {
  for (const [label, value] of Object.entries({
    toolchainDirectory,
    moduleCacheDirectory,
    home: isolation?.home,
    xdgCache: isolation?.xdgCache,
    xdgConfig: isolation?.xdgConfig,
    xdgData: isolation?.xdgData,
    temporary: isolation?.temporary,
    goBuildCache: isolation?.goBuildCache,
    goPath: isolation?.goPath,
  })) {
    invariant(typeof value === "string" && path.isAbsolute(value),
      `United Pass release Go ${label} must be absolute`);
  }
  return Object.freeze({
    ALL_PROXY: "",
    CGO_ENABLED: "0",
    GOCACHE: isolation.goBuildCache,
    GOENV: "off",
    GOFLAGS: "-mod=readonly -trimpath -buildvcs=false",
    GOINSECURE: "",
    GOMODCACHE: moduleCacheDirectory,
    GONOPROXY: "",
    GONOSUMDB: "",
    GOPATH: isolation.goPath,
    GOPRIVATE: "",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOTMPDIR: isolation.temporary,
    GOTOOLCHAIN: "local",
    GOVCS: "*:off",
    GOWORK: "off",
    GOARCH: "amd64",
    GOOS: "linux",
    HOME: isolation.home,
    HTTPS_PROXY: "",
    HTTP_PROXY: "",
    LANG: "C",
    LC_ALL: "C",
    NETRC: process.platform === "win32" ? "NUL" : "/dev/null",
    NO_PROXY: "*",
    PATH: path.join(toolchainDirectory, "bin"),
    SSH_AUTH_SOCK: "",
    TEMP: isolation.temporary,
    TMP: isolation.temporary,
    TMPDIR: isolation.temporary,
    TZ: "UTC",
    XDG_CACHE_HOME: isolation.xdgCache,
    XDG_CONFIG_HOME: isolation.xdgConfig,
    XDG_DATA_HOME: isolation.xdgData,
    all_proxy: "",
    http_proxy: "",
    https_proxy: "",
    no_proxy: "*",
  });
}

export function resolveProtectedGitIdentity({
  executablePath,
  expectedSha256,
  expectedVersion,
  environment,
  sourceRoot,
}) {
  invariant(typeof executablePath === "string" && path.isAbsolute(executablePath),
    "United Pass release Git executable must be an absolute protected path");
  invariant(path.basename(executablePath).toLowerCase() === (process.platform === "win32" ? "git.exe" : "git"),
    "United Pass release Git executable must be the native Git binary, not a wrapper");
  invariant(SHA256.test(expectedSha256 ?? ""),
    "United Pass release Git executable requires a CI-pinned SHA-256");
  invariant(/^\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?$/u.test(expectedVersion ?? ""),
    "United Pass release Git requires a CI-pinned version");
  const file = readProtectedRegularFile(executablePath, "United Pass release Git executable", {
    executable: true,
    maximumBytes: 256 * 1024 * 1024,
    sourceRoot,
  });
  invariant(file.sha256 === expectedSha256,
    "United Pass release Git executable does not match its CI-pinned SHA-256");
  const directory = path.dirname(file.path);
  const directoryBefore = lstatSync(directory, { bigint: true });
  invariant(directoryBefore.isDirectory() && !directoryBefore.isSymbolicLink()
    && (directoryBefore.mode & 0o222n) === 0n && sameLocalPath(realpathSync.native(directory), directory),
  "United Pass release Git directory must be a stable read-only real directory");
  const siblings = readdirSync(directory, { withFileTypes: true });
  invariant(siblings.length === 1 && siblings[0].isFile() && !siblings[0].isSymbolicLink()
    && siblings[0].name.toLowerCase() === path.basename(file.path).toLowerCase(),
  "United Pass release Git must be isolated from sibling commands and wrappers");
  const versionOutput = execFileSync(file.path, ["--version"], {
    encoding: "utf8",
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
  });
  const version = GIT_VERSION_OUTPUT.exec(versionOutput)?.[1] ?? "";
  invariant(version === expectedVersion,
    "United Pass release Git version does not match its CI-pinned version");
  const builtins = new Set(execFileSync(file.path, ["--list-cmds=builtins"], {
    encoding: "utf8",
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
  }).split(/\s+/u).filter(Boolean));
  for (const command of ["cat-file", "checkout", "clone", "config", "ls-files", "rev-parse", "status"]) {
    invariant(builtins.has(command), `United Pass release Git must provide ${command} as an in-process builtin`);
  }
  const directoryAfter = lstatSync(directory, { bigint: true });
  invariant(sameSnapshot(directoryBefore, directoryAfter),
    "United Pass release Git directory changed while it was verified");
  return Object.freeze({
    path: file.path,
    sha256: file.sha256,
    version,
    stat: file.stat,
    directory,
    directoryStat: directoryAfter,
    environment,
  });
}

export function runProtectedGit(identity, cwd, args, { encoding = "utf8", allowLocalFile = false } = {}) {
  invariant(identity && typeof identity.path === "string" && path.isAbsolute(identity.path),
    "United Pass protected Git identity is missing");
  return execFileSync(identity.path, [
    "--no-optional-locks",
    "-c", "core.quotepath=false",
    ...(allowLocalFile ? ["-c", "protocol.file.allow=always"] : []),
    ...args,
  ], {
    cwd,
    encoding,
    env: identity.environment,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 120_000,
  });
}

export function resolveProtectedModuleCacheIdentity({ directoryPath, expectedSha256, sourceRoot }) {
  invariant(SHA256.test(expectedSha256 ?? ""),
    "United Pass release Go module cache requires a CI-pinned complete-tree SHA-256");
  const tree = hashProtectedTree(directoryPath, "United Pass release Go module cache", { sourceRoot });
  invariant(tree.fileCount > 0, "United Pass release Go module cache must not be empty");
  invariant(tree.sha256 === expectedSha256,
    "United Pass release Go module cache does not match its CI-pinned complete-tree SHA-256");
  return tree;
}

export function resolveProtectedGoIdentity({
  executablePath,
  toolchainDirectory,
  expectedExecutableSha256,
  expectedToolchainSha256,
  expectedVersion,
  environment,
  sourceRoot,
}) {
  invariant(SHA256.test(expectedExecutableSha256 ?? ""),
    "United Pass release Go executable requires a CI-pinned SHA-256");
  invariant(SHA256.test(expectedToolchainSha256 ?? ""),
    "United Pass release Go toolchain requires a CI-pinned complete-tree SHA-256");
  invariant(GO_VERSION.test(expectedVersion ?? ""),
    "United Pass release Go requires a CI-pinned version");
  const tree = hashProtectedTree(toolchainDirectory, "United Pass release Go toolchain", { sourceRoot });
  invariant(tree.sha256 === expectedToolchainSha256,
    "United Pass release Go toolchain does not match its CI-pinned complete-tree SHA-256");
  const expectedExecutablePath = path.join(tree.path, "bin", process.platform === "win32" ? "go.exe" : "go");
  invariant(sameLocalPath(path.resolve(executablePath), expectedExecutablePath),
    "United Pass release Go executable must be the protected toolchain bin/go");
  const executable = readProtectedRegularFile(executablePath, "United Pass release Go executable", {
    executable: true,
    maximumBytes: 256 * 1024 * 1024,
    sourceRoot,
  });
  invariant(executable.sha256 === expectedExecutableSha256,
    "United Pass release Go executable does not match its CI-pinned SHA-256");
  let goEnvironment;
  try {
    goEnvironment = JSON.parse(execFileSync(executable.path, ["env", "-json", "GOVERSION", "GOROOT", "GOTOOLDIR", "GOHOSTOS", "GOHOSTARCH"], {
      encoding: "utf8",
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    }));
  } catch (error) {
    throw new Error("United Pass release Go environment identity is invalid", { cause: error });
  }
  invariant(goEnvironment && Object.keys(goEnvironment).sort().join(",") ===
    ["GOHOSTARCH", "GOHOSTOS", "GOROOT", "GOTOOLDIR", "GOVERSION"].sort().join(","),
  "United Pass release Go environment identity fields are invalid");
  invariant(goEnvironment.GOVERSION === expectedVersion
    && sameLocalPath(goEnvironment.GOROOT, tree.path)
    && isInside(goEnvironment.GOTOOLDIR, tree.path)
    && goEnvironment.GOHOSTOS === "linux" && goEnvironment.GOHOSTARCH === "amd64",
  "United Pass release Go environment differs from the protected linux/amd64 toolchain");
  const versionOutput = execFileSync(executable.path, ["version"], {
    encoding: "utf8",
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
  }).trim();
  invariant(versionOutput === `go version ${expectedVersion} linux/amd64`,
    "United Pass release Go version output differs from the CI-pinned toolchain");
  for (const tool of ["compile", "link"]) {
    const output = execFileSync(executable.path, ["tool", tool, "-V=full"], {
      encoding: "utf8",
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    }).trim();
    invariant(output.startsWith(`${tool} version ${expectedVersion}`),
      `United Pass release Go ${tool} tool does not match the protected toolchain`);
  }
  return Object.freeze({
    path: executable.path,
    sha256: executable.sha256,
    stat: executable.stat,
    version: expectedVersion,
    toolchainPath: tree.path,
    toolchainSha256: tree.sha256,
    toolchainFileCount: tree.fileCount,
    toolchainBytes: tree.bytes,
    environment,
  });
}

export function runProtectedGo(identity, cwd, args, { capture = false, timeout = 15 * 60_000 } = {}) {
  invariant(identity && typeof identity.path === "string" && path.isAbsolute(identity.path),
    "United Pass protected Go identity is missing");
  const result = execFileSync(identity.path, args, {
    cwd,
    env: identity.environment,
    encoding: capture ? "utf8" : undefined,
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
    timeout,
  });
  return capture ? result.trim() : "";
}

export function hashProtectedTree(inputPath, label, { sourceRoot } = {}) {
  invariant(typeof inputPath === "string" && path.isAbsolute(inputPath), `${label} must be an absolute path`);
  const rootPathStat = lstatSync(inputPath, { bigint: true });
  invariant(rootPathStat.isDirectory() && !rootPathStat.isSymbolicLink()
    && (rootPathStat.mode & 0o222n) === 0n,
  `${label} must be a read-only real directory`);
  const canonicalRoot = realpathSync.native(inputPath);
  invariant(sameLocalPath(path.resolve(inputPath), canonicalRoot), `${label} must not traverse a symbolic-link parent`);
  if (sourceRoot) invariant(!isInside(canonicalRoot, sourceRoot), `${label} must be outside the source repository`);
  const rootBefore = lstatSync(canonicalRoot, { bigint: true });
  invariant(sameSnapshot(rootPathStat, rootBefore), `${label} changed before it was inspected`);
  const entries = [];
  let fileCount = 0;
  let totalBytes = 0;

  const visit = (directory, relativeDirectory) => {
    const before = lstatSync(directory, { bigint: true });
    invariant(before.isDirectory() && !before.isSymbolicLink() && (before.mode & 0o222n) === 0n,
      `${label} contains a writable or non-directory path: ${relativeDirectory || "."}`);
    if (relativeDirectory) entries.push({ path: `${relativeDirectory}/`, type: "directory" });
    const names = readdirSync(directory);
    names.sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
    for (const name of names) {
      invariant(name !== "." && name !== ".." && !name.includes("\0"), `${label} contains an invalid path entry`);
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      const absolutePath = path.join(directory, name);
      const metadata = lstatSync(absolutePath, { bigint: true });
      invariant(!metadata.isSymbolicLink(), `${label} contains a symbolic link: ${relativePath}`);
      if (metadata.isDirectory()) {
        visit(absolutePath, relativePath);
        continue;
      }
      invariant(metadata.isFile() && metadata.nlink === 1n && (metadata.mode & 0o222n) === 0n,
        `${label} contains a writable, linked or non-regular file: ${relativePath}`);
      const file = readProtectedRegularFile(absolutePath, `${label} file ${relativePath}`, {
        maximumBytes: MAX_PROTECTED_TREE_BYTES,
      });
      fileCount += 1;
      totalBytes += file.bytes;
      invariant(fileCount <= MAX_PROTECTED_TREE_FILES && totalBytes <= MAX_PROTECTED_TREE_BYTES,
        `${label} exceeds the reviewed file-count or byte limit`);
      entries.push({
        path: relativePath.replaceAll(path.sep, "/"),
        type: "file",
        bytes: file.bytes,
        sha256: file.sha256,
        executable: (metadata.mode & 0o111n) !== 0n,
      });
    }
    invariant(sameSnapshot(before, lstatSync(directory, { bigint: true })),
      `${label} directory changed while it was inspected: ${relativeDirectory || "."}`);
  };
  visit(canonicalRoot, "");
  invariant(sameSnapshot(rootBefore, lstatSync(canonicalRoot, { bigint: true }))
    && sameLocalPath(realpathSync.native(inputPath), canonicalRoot),
  `${label} root changed while it was inspected`);
  const manifestBytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, entries })}\n`, "utf8");
  return Object.freeze({
    path: canonicalRoot,
    sha256: sha256(manifestBytes),
    fileCount,
    bytes: totalBytes,
    entryCount: entries.length,
  });
}

function readProtectedRegularFile(inputPath, label, {
  executable = false,
  maximumBytes = 512 * 1024 * 1024,
  sourceRoot,
} = {}) {
  invariant(typeof inputPath === "string" && path.isAbsolute(inputPath), `${label} must be an absolute path`);
  const pathStat = lstatSync(inputPath, { bigint: true });
  invariant(pathStat.isFile() && !pathStat.isSymbolicLink() && pathStat.nlink === 1n
    && pathStat.size >= 1n && pathStat.size <= BigInt(maximumBytes) && (pathStat.mode & 0o222n) === 0n,
  `${label} must be a singly-linked read-only regular file within its size limit`);
  if (executable && process.platform !== "win32") {
    invariant((pathStat.mode & 0o111n) !== 0n, `${label} must be executable`);
  }
  const canonicalPath = realpathSync.native(inputPath);
  invariant(sameLocalPath(path.resolve(inputPath), canonicalPath), `${label} must not traverse a symbolic-link parent`);
  if (sourceRoot) invariant(!isInside(canonicalPath, sourceRoot), `${label} must be outside the source repository`);
  const handle = openSync(canonicalPath, "r");
  const digest = createHash("sha256");
  let before;
  let after;
  let bytes = 0;
  try {
    before = fstatSync(handle, { bigint: true });
    invariant(sameSnapshot(pathStat, before), `${label} changed before it was opened`);
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    while (true) {
      const length = readSync(handle, buffer, 0, buffer.byteLength, null);
      if (length === 0) break;
      bytes += length;
      invariant(bytes <= maximumBytes, `${label} exceeds its size limit`);
      digest.update(buffer.subarray(0, length));
    }
    after = fstatSync(handle, { bigint: true });
  } finally {
    closeSync(handle);
  }
  const finalStat = lstatSync(inputPath, { bigint: true });
  invariant(sameSnapshot(before, after) && sameSnapshot(after, finalStat)
    && sameLocalPath(realpathSync.native(inputPath), canonicalPath) && BigInt(bytes) === after.size,
  `${label} changed while it was verified`);
  return Object.freeze({ path: canonicalPath, sha256: digest.digest("hex"), bytes, stat: after });
}

function sameSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
    && left.mode === right.mode && left.nlink === right.nlink;
}

function sameLocalPath(left, right) {
  const a = path.resolve(left);
  const b = path.resolve(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function isInside(candidate, parent) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}
