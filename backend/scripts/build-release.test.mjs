import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  UNITED_PASS_RELEASE_ENVIRONMENT_SHA256,
  assertUnitedPassReleaseHost,
  createUnitedPassGitEnvironment,
  createUnitedPassGoEnvironment,
  hashProtectedTree,
  resolveProtectedGitIdentity,
  resolveProtectedModuleCacheIdentity,
  resolveProtectedNodeIdentity,
} from "./release-toolchain-identity.mjs";
import { removeExactPublishedOutput } from "./build-release.mjs";

const scriptsRoot = path.dirname(fileURLToPath(import.meta.url));
const builderPath = path.join(scriptsRoot, "build-release.mjs");
const signerPath = path.resolve(scriptsRoot, "..", "..", "_release", "create-united-pass-api-attestation.mjs");

test("United Pass formal builder and signer reject unsupported hosts before release work", () => {
  assert.throws(() => assertUnitedPassReleaseHost("win32", "x64"), /protected linux\/x64/u);
  assert.throws(() => assertUnitedPassReleaseHost("linux", "arm64"), /protected linux\/x64/u);
  assert.doesNotThrow(() => assertUnitedPassReleaseHost("linux", "x64"));
  const source = readFileSync(builderPath, "utf8");
  assert.match(source, /export async function buildRelease\(\) \{\s*assertUnitedPassReleaseHost\(\);/u);
  const signerSource = readFileSync(signerPath, "utf8");
  assert.match(signerSource, /\}\) \{\s*assertUnitedPassApiSignerHost\(\);\s*const nodeIdentity = resolveProtectedNodeIdentity/u);
  assert.ok(signerSource.indexOf("const nodeIdentity = resolveProtectedNodeIdentity")
    < signerSource.indexOf("validateProtectedPrivateKeyPath(privateKeyPath)"));
});

test("release Git and Go environments are explicit and do not inherit PATH or cache locations", () => {
  const isolation = {
    home: "/protected/capsule/home",
    xdgCache: "/protected/capsule/xdg-cache",
    xdgConfig: "/protected/capsule/xdg-config",
    xdgData: "/protected/capsule/xdg-data",
    temporary: "/protected/capsule/temp",
    goBuildCache: "/protected/capsule/go-build-cache",
    goPath: "/protected/capsule/go-path",
    gitTemplate: "/protected/capsule/git-template",
  };
  const git = createUnitedPassGitEnvironment("/protected/git-bin/git", isolation);
  const go = createUnitedPassGoEnvironment("/protected/go", "/protected/module-cache", isolation);
  assert.equal(git.PATH, "/protected/git-bin");
  assert.equal(git.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(git.GIT_CONFIG_GLOBAL, process.platform === "win32" ? "NUL" : "/dev/null");
  assert.equal(git.HOME, isolation.home);
  assert.equal(go.PATH, path.join("/protected/go", "bin"));
  assert.equal(go.GOCACHE, isolation.goBuildCache);
  assert.equal(go.GOMODCACHE, "/protected/module-cache");
  assert.equal(go.GOPATH, isolation.goPath);
  assert.equal(go.GOPROXY, "off");
  assert.equal(go.GOVCS, "*:off");
  assert.equal(go.HOME, isolation.home);
  for (const environment of [git, go]) {
    assert.equal(Object.hasOwn(environment, "ComSpec"), false);
    assert.equal(Object.hasOwn(environment, "SystemRoot"), false);
  }
  assert.match(UNITED_PASS_RELEASE_ENVIRONMENT_SHA256, /^[0-9a-f]{64}$/u);
});

test("formal builder invokes only absolute identities and binds every protected release input", () => {
  const source = readFileSync(builderPath, "utf8");
  assert.doesNotMatch(source, /execFileSync\(["'](?:git|go)["']/u);
  assert.doesNotMatch(source, /\.\.\.process\.env|for \(const name of \[[\s\S]*?process\.env\[name\]/u);
  for (const token of [
    "--git-executable",
    "--go-executable",
    "--go-toolchain-directory",
    "--module-cache-directory",
    "MOONSTONE_TRUSTED_NODE_SHA256",
    "MOONSTONE_TRUSTED_NODE_VERSION",
    "MOONSTONE_TRUSTED_GIT_SHA256",
    "MOONSTONE_TRUSTED_GIT_VERSION",
    "MOONSTONE_TRUSTED_GO_EXECUTABLE_SHA256",
    "MOONSTONE_TRUSTED_GO_TOOLCHAIN_SHA256",
    "MOONSTONE_TRUSTED_GO_MODULE_CACHE_SHA256",
    "MOONSTONE_TRUSTED_GO_VERSION",
    "moduleCacheSha256",
    "nodeExecutableSha256",
    "goToolchainSha256",
    "gitExecutableSha256",
    "UNITED_PASS_RELEASE_ENVIRONMENT_SHA256",
  ]) assert.equal(source.includes(token), true, `formal builder is missing ${token}`);
});

test("tool identity resolvers fail closed without CI pins before invoking a candidate", () => {
  assert.throws(() => resolveProtectedNodeIdentity({
    executablePath: process.execPath,
    expectedSha256: "",
    expectedVersion: process.version,
  }), /CI-pinned executable SHA-256/u);
  assert.throws(() => resolveProtectedGitIdentity({
    executablePath: path.resolve("missing", process.platform === "win32" ? "git.exe" : "git"),
    expectedSha256: "",
    expectedVersion: "2.49.0",
    environment: {},
  }), /CI-pinned SHA-256/u);
  assert.throws(() => resolveProtectedModuleCacheIdentity({
    directoryPath: path.resolve("missing-module-cache"),
    expectedSha256: "",
  }), /CI-pinned complete-tree SHA-256/u);
});

test("formal output is atomically published and exact-identity cleanup refuses a replacement", async () => {
  const source = readFileSync(builderPath, "utf8");
  assert.match(source, /\.united-pass-api-release-pending-/u);
  assert.match(source, /await rename\(pendingOutput, outputDirectory\)/u);
  assert.doesNotMatch(source, /await mkdir\(outputDirectory/u);

  const root = mkdtempSync(path.join(tmpdir(), "united-pass-output-cleanup-"));
  try {
    const exactOutput = path.join(root, "exact-output");
    mkdirSync(exactOutput);
    writeFileSync(path.join(exactOutput, "artifact"), "sealed\n", "utf8");
    chmodSync(path.join(exactOutput, "artifact"), 0o444);
    chmodSync(exactOutput, 0o555);
    const exactStat = lstatSync(exactOutput, { bigint: true });
    await removeExactPublishedOutput(exactOutput, root, {
      dev: exactStat.dev,
      ino: exactStat.ino,
      size: exactStat.size,
      mtimeNs: exactStat.mtimeNs,
      birthtimeNs: exactStat.birthtimeNs,
    });
    assert.equal(existsSync(exactOutput), false);

    const replacedOutput = path.join(root, "replaced-output");
    const preservedOutput = path.join(root, "preserved-original");
    mkdirSync(replacedOutput);
    const originalStat = lstatSync(replacedOutput, { bigint: true });
    const originalIdentity = {
      dev: originalStat.dev,
      ino: originalStat.ino,
      size: originalStat.size,
      mtimeNs: originalStat.mtimeNs,
      birthtimeNs: originalStat.birthtimeNs,
    };
    renameSync(replacedOutput, preservedOutput);
    mkdirSync(replacedOutput);
    const sentinel = path.join(replacedOutput, "must-survive");
    writeFileSync(sentinel, "replacement\n", "utf8");
    await assert.rejects(
      removeExactPublishedOutput(replacedOutput, root, originalIdentity),
      /refusing to clean a replaced formal United Pass release output/u,
    );
    assert.equal(readFileSync(sentinel, "utf8"), "replacement\n");
  } finally {
    makeWritable(root);
    rmSync(root, { recursive: true, force: true });
  }
});

test("complete protected-tree identity detects cache drift and linked files", () => {
  const root = mkdtempSync(path.join(tmpdir(), "united-pass-tree-identity-"));
  try {
    const cache = path.join(root, "cache");
    mkdirSync(cache);
    const module = path.join(cache, "module.zip");
    writeFileSync(module, "reviewed module bytes\n", "utf8");
    chmodSync(module, 0o444);
    chmodSync(cache, 0o555);
    const first = hashProtectedTree(cache, "test protected cache");
    assert.match(first.sha256, /^[0-9a-f]{64}$/u);
    assert.equal(first.fileCount, 1);

    chmodSync(cache, 0o700);
    chmodSync(module, 0o600);
    writeFileSync(module, "changed module bytes\n", "utf8");
    chmodSync(module, 0o444);
    chmodSync(cache, 0o555);
    assert.throws(() => resolveProtectedModuleCacheIdentity({
      directoryPath: cache,
      expectedSha256: first.sha256,
    }), /does not match its CI-pinned complete-tree SHA-256/u);

    chmodSync(cache, 0o700);
    const linked = path.join(cache, "linked.zip");
    linkSync(module, linked);
    chmodSync(cache, 0o555);
    assert.throws(() => hashProtectedTree(cache, "test protected cache"), /linked or non-regular file/u);
  } finally {
    makeWritable(root);
    rmSync(root, { recursive: true, force: true });
  }
});

function makeWritable(entryPath) {
  const metadata = lstatSync(entryPath);
  if (metadata.isDirectory()) {
    chmodSync(entryPath, 0o700);
    for (const name of readdirSync(entryPath)) makeWritable(path.join(entryPath, name));
  } else {
    chmodSync(entryPath, 0o600);
  }
}
