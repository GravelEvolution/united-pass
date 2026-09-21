import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  rmdir,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  UNITED_PASS_RELEASE_ENVIRONMENT_SHA256,
  assertUnitedPassReleaseHost,
  createUnitedPassGitEnvironment,
  createUnitedPassGoEnvironment,
  resolveProtectedGitIdentity,
  resolveProtectedGoIdentity,
  resolveProtectedModuleCacheIdentity,
  resolveProtectedNodeIdentity,
  runProtectedGit,
  runProtectedGo,
} from "./release-toolchain-identity.mjs";

const projectRoot = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const requestedOutputDirectory = optionValue("--output-directory");
const requestedGitExecutable = optionValue("--git-executable");
const requestedGoExecutable = optionValue("--go-executable");
const requestedGoToolchainDirectory = optionValue("--go-toolchain-directory");
const requestedModuleCacheDirectory = optionValue("--module-cache-directory");
const help = process.argv.includes("--help");

if (help) {
  console.log("Usage: node scripts/build-release.mjs --output-directory <absolute-new-directory> --git-executable <absolute-protected-git> --go-executable <absolute-protected-go> --go-toolchain-directory <absolute-read-only-go-root> --module-cache-directory <absolute-read-only-module-cache>");
} else if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildRelease();
}

export async function buildRelease() {
  assertUnitedPassReleaseHost();
  const nodeIdentity = resolveProtectedNodeIdentity({
    executablePath: process.execPath,
    expectedSha256: process.env.MOONSTONE_TRUSTED_NODE_SHA256,
    expectedVersion: process.env.MOONSTONE_TRUSTED_NODE_VERSION,
    sourceRoot: projectRoot,
  });
  for (const [option, value] of Object.entries({
    "--output-directory": requestedOutputDirectory,
    "--git-executable": requestedGitExecutable,
    "--go-executable": requestedGoExecutable,
    "--go-toolchain-directory": requestedGoToolchainDirectory,
    "--module-cache-directory": requestedModuleCacheDirectory,
  })) {
    invariant(typeof value === "string" && path.isAbsolute(value), `${option} must be an absolute path`);
  }
  const outputParentInput = path.dirname(path.resolve(requestedOutputDirectory));
  const outputParentStat = await lstat(outputParentInput, { bigint: true });
  invariant(outputParentStat.isDirectory() && !outputParentStat.isSymbolicLink(),
    "release output parent must be a real directory, not a symbolic link");
  const outputParent = await realpath(outputParentInput);
  const outputDirectory = path.join(outputParent, path.basename(path.resolve(requestedOutputDirectory)));
  invariant(isSafeBasename(path.basename(outputDirectory)), "release output basename is unsafe");
  invariant(!await pathExists(outputDirectory), "release output directory must not already exist");
  const capsuleRoot = await mkdtemp(path.join(outputParent, ".united-pass-api-source-"));
  const capsuleIdentity = directoryObjectIdentity(await lstat(capsuleRoot, { bigint: true }));
  const capsuleRepository = path.join(capsuleRoot, "repository");
  const stagingOutput = path.join(capsuleRoot, "staging-output");
  let result;
  let formalOutputIdentity = null;
  let buildError = null;
  try {
    const isolation = await createIsolationDirectories(capsuleRoot);
    const gitEnvironment = createUnitedPassGitEnvironment(requestedGitExecutable, isolation);
    const git = resolveProtectedGitIdentity({
      executablePath: requestedGitExecutable,
      expectedSha256: process.env.MOONSTONE_TRUSTED_GIT_SHA256,
      expectedVersion: process.env.MOONSTONE_TRUSTED_GIT_VERSION,
      environment: gitEnvironment,
      sourceRoot: projectRoot,
    });
    const repositoryRoot = await realpath(gitAt(git, projectRoot, "rev-parse", "--show-toplevel"));
    const canonicalProjectRoot = await realpath(projectRoot);
    invariant(isInside(canonicalProjectRoot, repositoryRoot), "United Pass project root is outside the integration repository");
    for (const [label, input] of [
      ["release Node executable", nodeIdentity.path],
      ["release Git executable", git.path],
      ["release Go executable", requestedGoExecutable],
      ["release Go toolchain", requestedGoToolchainDirectory],
      ["release Go module cache", requestedModuleCacheDirectory],
    ]) {
      invariant(!isInside(input, repositoryRoot), `United Pass ${label} must be outside the source repository`);
    }
    invariant(!isInside(outputDirectory, repositoryRoot), "release output directory must be outside the source repository");
    const moduleCache = resolveProtectedModuleCacheIdentity({
      directoryPath: requestedModuleCacheDirectory,
      expectedSha256: process.env.MOONSTONE_TRUSTED_GO_MODULE_CACHE_SHA256,
      sourceRoot: repositoryRoot,
    });
    const goEnvironment = createUnitedPassGoEnvironment(
      requestedGoToolchainDirectory,
      moduleCache.path,
      isolation,
    );
    const goIdentity = resolveProtectedGoIdentity({
      executablePath: requestedGoExecutable,
      toolchainDirectory: requestedGoToolchainDirectory,
      expectedExecutableSha256: process.env.MOONSTONE_TRUSTED_GO_EXECUTABLE_SHA256,
      expectedToolchainSha256: process.env.MOONSTONE_TRUSTED_GO_TOOLCHAIN_SHA256,
      expectedVersion: process.env.MOONSTONE_TRUSTED_GO_VERSION,
      environment: goEnvironment,
      sourceRoot: repositoryRoot,
    });
    const projectRelativePath = path.relative(repositoryRoot, canonicalProjectRoot);
    assertReviewedSourceSnapshot(git, repositoryRoot, null, null, "integration worktree");
    const sourceCommit = gitAt(git, repositoryRoot, "rev-parse", "--verify", "HEAD^{commit}");
    const sourceTree = gitAt(git, repositoryRoot, "rev-parse", "--verify", `${sourceCommit}^{tree}`);
    invariant(/^[0-9a-f]{40}$/u.test(sourceCommit)
      && gitAt(git, repositoryRoot, "cat-file", "-t", sourceCommit) === "commit",
    "release source commit is not a canonical SHA-1 commit object");
    invariant(/^[0-9a-f]{40}$/u.test(sourceTree)
      && gitAt(git, repositoryRoot, "cat-file", "-t", sourceTree) === "tree",
    "release source tree is not a canonical SHA-1 tree object");

    await mkdir(stagingOutput, { recursive: false, mode: 0o700 });
    runProtectedGit(git, outputParent, [
      "clone", "--local", "--no-hardlinks", "--no-checkout", "--no-tags", "--no-recurse-submodules",
      repositoryRoot, capsuleRepository,
    ], { allowLocalFile: true });
    gitAt(git, capsuleRepository, "checkout", "--detach", sourceCommit);
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "detached build capsule");
    const releaseProjectRoot = path.join(capsuleRepository, projectRelativePath);
    invariant((await lstat(releaseProjectRoot, { bigint: true })).isDirectory(), "United Pass project is missing from the detached build capsule");
    await sealSourceTree(releaseProjectRoot);
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "sealed detached build capsule");

    const expectedGoVersion = `go${/^go\s+(\S+)$/mu.exec(await readFile(path.join(releaseProjectRoot, "go.mod"), "utf8"))?.[1] ?? ""}`;
    const actualGoVersion = runProtectedGo(goIdentity, releaseProjectRoot, ["env", "GOVERSION"], { capture: true });
    invariant(actualGoVersion === expectedGoVersion, `release Go version must be exactly ${expectedGoVersion}`);
    const temporaryBinary = path.join(stagingOutput, ".united-pass-api.building");
    const artifactPath = path.join(stagingOutput, "united-pass-api");
    const recordPath = path.join(stagingOutput, "united-pass-api-build-record.json");
    const linkerFlags = [
      `-X main.buildSourceCommit=${sourceCommit}`,
      `-X main.buildSourceTree=${sourceTree}`,
      "-X main.buildProfile=release",
    ].join(" ");

    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "capsule before tests");
    runProtectedGo(goIdentity, releaseProjectRoot, ["test", "-count=1", "./..."]);
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "capsule before build");
    runProtectedGo(
      goIdentity,
      releaseProjectRoot,
      ["build",
      "-mod=readonly",
      "-trimpath",
      "-buildvcs=false",
      "-ldflags", linkerFlags,
      "-o", temporaryBinary,
      "./cmd/api"],
    );
    const buildInfoBytes = execFileSync(temporaryBinary, ["--build-info"], {
      cwd: releaseProjectRoot,
      env: goIdentity.environment,
      encoding: "buffer",
      maxBuffer: 4096,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000,
    });
    const buildInfo = parseExactBuildInfo(buildInfoBytes);
    invariant(buildInfo.sourceCommit === sourceCommit && buildInfo.sourceTree === sourceTree,
      "compiled API build info differs from the reviewed source objects");
    invariant(buildInfo.profile === "release" && buildInfo.goVersion === actualGoVersion
      && buildInfo.goos === "linux" && buildInfo.goarch === "amd64",
    "compiled API build info differs from the reviewed release target");
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "capsule after artifact execution");

    const artifactBytes = await readFile(temporaryBinary);
    const artifactSha256 = sha256(artifactBytes);
    await rename(temporaryBinary, artifactPath);
    await chmod(artifactPath, 0o555);
    await verifySealedFile(artifactPath, artifactBytes.byteLength, artifactSha256, "release API artifact");
    const record = {
      schemaVersion: 2,
      component: "united-pass-api",
      artifact: {
        basename: "united-pass-api",
        bytes: artifactBytes.byteLength,
        sha256: artifactSha256,
      },
      source: { commit: sourceCommit, tree: sourceTree },
      buildProfile: "release",
      buildProvenance: {
        sourceMode: "detached-local-clone-no-hardlinks",
        sourceReadOnly: true,
        ignoredFilesRejected: true,
        abnormalIndexEntriesRejected: true,
        dependencyNetwork: "off",
        dependencyCache: "external-read-only-ci-pinned-complete-tree",
        toolInvocation: "absolute-ci-pinned-executables",
        environmentIsolation: "fresh-private-home-xdg-build-cache-temp",
        buildInfoVerification: "direct-execution-before-key-mount",
      },
      dependencies: {
        moduleCacheSha256: moduleCache.sha256,
        moduleCacheFileCount: moduleCache.fileCount,
        moduleCacheBytes: moduleCache.bytes,
      },
      toolchain: {
        nodeVersion: nodeIdentity.version,
        nodeExecutableSha256: nodeIdentity.sha256,
        gitVersion: git.version,
        gitExecutableSha256: git.sha256,
        goVersion: goIdentity.version,
        goExecutableSha256: goIdentity.sha256,
        goToolchainSha256: goIdentity.toolchainSha256,
        goToolchainFileCount: goIdentity.toolchainFileCount,
        goToolchainBytes: goIdentity.toolchainBytes,
        platform: "linux",
        arch: "x64",
      },
      environment: {
        policy: "isolated-fresh-home-xdg-build-cache-temp-no-inherited-path",
        policySha256: UNITED_PASS_RELEASE_ENVIRONMENT_SHA256,
      },
      target: { goVersion: actualGoVersion, goos: "linux", goarch: "amd64", cgoEnabled: false },
      buildInfoOutputBase64: buildInfoBytes.toString("base64url"),
      buildInfoSha256: sha256(buildInfoBytes),
    };
    const recordBytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
    await writeFile(recordPath, recordBytes, { flag: "wx", mode: 0o444 });
    await chmod(recordPath, 0o444);
    await verifySealedFile(recordPath, recordBytes.byteLength, sha256(recordBytes), "release API build record");
    assertProtectedReleaseInputsStable({
      nodeIdentity,
      git,
      gitEnvironment,
      goIdentity,
      goEnvironment,
      moduleCache,
      repositoryRoot,
    });
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "capsule before output seal");
    await chmod(stagingOutput, 0o555);
    const stagingOutputStat = await lstat(stagingOutput, { bigint: true });
    invariant(stagingOutputStat.isDirectory() && !stagingOutputStat.isSymbolicLink()
      && (stagingOutputStat.mode & 0o222n) === 0n,
    "staged release output directory was not sealed read-only");
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "capsule before atomic output publication");

    const pendingOutput = await mkdtemp(path.join(outputParent, ".united-pass-api-release-pending-"));
    const pendingIdentity = directoryObjectIdentity(await lstat(pendingOutput, { bigint: true }));
    let pendingExists = true;
    try {
      const pendingArtifactPath = path.join(pendingOutput, path.basename(artifactPath));
      const pendingRecordPath = path.join(pendingOutput, path.basename(recordPath));
      await copyFile(artifactPath, pendingArtifactPath, fsConstants.COPYFILE_EXCL);
      await chmod(pendingArtifactPath, 0o555);
      await verifySealedFile(
        pendingArtifactPath,
        artifactBytes.byteLength,
        artifactSha256,
        "pending release API artifact",
      );
      await copyFile(recordPath, pendingRecordPath, fsConstants.COPYFILE_EXCL);
      await chmod(pendingRecordPath, 0o444);
      await verifySealedFile(
        pendingRecordPath,
        recordBytes.byteLength,
        sha256(recordBytes),
        "pending release API build record",
      );
      await chmod(pendingOutput, 0o555);
      const pendingStat = await lstat(pendingOutput, { bigint: true });
      invariant(pendingStat.isDirectory() && !pendingStat.isSymbolicLink()
        && (pendingStat.mode & 0o222n) === 0n,
      "pending release output directory was not sealed read-only");
      invariant(!await pathExists(outputDirectory), "release output directory appeared during the build");
      await rename(pendingOutput, outputDirectory);
      const publishedStat = await lstat(outputDirectory, { bigint: true });
      invariant(publishedStat.isDirectory() && !publishedStat.isSymbolicLink()
        && sameDirectoryObject(pendingStat, directoryObjectIdentity(publishedStat)),
      "formal release output identity changed during atomic publication");
      formalOutputIdentity = publishedDirectoryIdentity(publishedStat);
      pendingExists = false;
    } finally {
      if (pendingExists) {
        await removeOwnedReleaseTree(
          pendingOutput,
          outputParent,
          ".united-pass-api-release-pending-",
          pendingIdentity,
        );
      }
    }

    const finalArtifactPath = path.join(outputDirectory, path.basename(artifactPath));
    const finalRecordPath = path.join(outputDirectory, path.basename(recordPath));
    await verifySealedFile(finalArtifactPath, artifactBytes.byteLength, artifactSha256, "formal release API artifact");
    await verifySealedFile(finalRecordPath, recordBytes.byteLength, sha256(recordBytes), "formal release API build record");
    assertReviewedSourceSnapshot(git, capsuleRepository, sourceCommit, sourceTree, "capsule after atomic output publication");
    result = {
      artifactPath: finalArtifactPath,
      recordPath: finalRecordPath,
      artifactSha256,
      sourceCommit,
      sourceTree,
    };
  } catch (error) {
    buildError = error;
  }
  let capsuleCleanupError = null;
  try {
    await removeOwnedReleaseTree(
      capsuleRoot,
      outputParent,
      ".united-pass-api-source-",
      capsuleIdentity,
    );
  } catch (error) {
    capsuleCleanupError = error;
  }
  if (buildError || capsuleCleanupError) {
    let formalCleanupError = null;
    if (formalOutputIdentity !== null) {
      try {
        await removeExactPublishedOutput(outputDirectory, outputParent, formalOutputIdentity);
      } catch (error) {
        formalCleanupError = error;
      }
    }
    if (formalCleanupError) {
      throw new AggregateError(
        [buildError, capsuleCleanupError, formalCleanupError].filter(Boolean),
        "United Pass release failed and its exact published output could not be safely removed",
      );
    }
    throw buildError ?? capsuleCleanupError;
  }
  console.log(JSON.stringify(result));
}

async function verifySealedFile(filePath, expectedBytes, expectedSha256, label) {
  const before = await lstat(filePath, { bigint: true });
  invariant(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n && (before.mode & 0o222n) === 0n,
    `${label} is not a singly-linked read-only regular file`);
  const bytes = await readFile(filePath);
  const after = await lstat(filePath, { bigint: true });
  invariant(before.dev === after.dev && before.ino === after.ino && before.size === after.size
    && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs && before.mode === after.mode
    && before.nlink === after.nlink && before.size === BigInt(expectedBytes)
    && bytes.byteLength === expectedBytes && sha256(bytes) === expectedSha256,
  `${label} changed or did not match its recorded bytes`);
}

function assertReviewedSourceSnapshot(git, repositoryRoot, expectedCommit, expectedTree, label) {
  const status = gitAt(
    git,
    repositoryRoot,
    "status",
    "--porcelain=v2",
    "--untracked-files=all",
    "--ignored=matching",
    "--ignore-submodules=none",
    "--no-renames",
  );
  invariant(status === "", `${label} contains tracked, untracked or ignored files outside the reviewed commit`);
  const indexTags = gitAtRaw(git, repositoryRoot, "ls-files", "-v", "-z")
    .toString("utf8").split("\0").filter(Boolean);
  invariant(indexTags.every((entry) => entry.startsWith("H ")),
    `${label} contains skip-worktree, assume-unchanged or abnormal index entries`);
  if (expectedCommit !== null) {
    invariant(gitAt(git, repositoryRoot, "rev-parse", "--verify", "HEAD^{commit}") === expectedCommit
      && gitAt(git, repositoryRoot, "rev-parse", "--verify", `${expectedCommit}^{tree}`) === expectedTree,
    `${label} source objects differ from the reviewed commit and tree`);
  }
}

async function createIsolationDirectories(capsuleRoot) {
  const isolation = {
    home: path.join(capsuleRoot, "home"),
    xdgCache: path.join(capsuleRoot, "xdg-cache"),
    xdgConfig: path.join(capsuleRoot, "xdg-config"),
    xdgData: path.join(capsuleRoot, "xdg-data"),
    temporary: path.join(capsuleRoot, "temporary"),
    goBuildCache: path.join(capsuleRoot, "go-build-cache"),
    goPath: path.join(capsuleRoot, "go-path"),
    gitTemplate: path.join(capsuleRoot, "empty-git-template"),
  };
  for (const directory of Object.values(isolation)) {
    await mkdir(directory, { recursive: false, mode: 0o700 });
    await chmod(directory, 0o700);
  }
  await chmod(isolation.gitTemplate, 0o555);
  return Object.freeze(isolation);
}

function assertProtectedReleaseInputsStable({
  nodeIdentity,
  git,
  gitEnvironment,
  goIdentity,
  goEnvironment,
  moduleCache,
  repositoryRoot,
}) {
  const finalNode = resolveProtectedNodeIdentity({
    executablePath: nodeIdentity.path,
    expectedSha256: nodeIdentity.sha256,
    expectedVersion: nodeIdentity.version,
    sourceRoot: repositoryRoot,
  });
  const finalGit = resolveProtectedGitIdentity({
    executablePath: git.path,
    expectedSha256: git.sha256,
    expectedVersion: git.version,
    environment: gitEnvironment,
    sourceRoot: repositoryRoot,
  });
  const finalModuleCache = resolveProtectedModuleCacheIdentity({
    directoryPath: moduleCache.path,
    expectedSha256: moduleCache.sha256,
    sourceRoot: repositoryRoot,
  });
  const finalGo = resolveProtectedGoIdentity({
    executablePath: goIdentity.path,
    toolchainDirectory: goIdentity.toolchainPath,
    expectedExecutableSha256: goIdentity.sha256,
    expectedToolchainSha256: goIdentity.toolchainSha256,
    expectedVersion: goIdentity.version,
    environment: goEnvironment,
    sourceRoot: repositoryRoot,
  });
  invariant(finalNode.sha256 === nodeIdentity.sha256 && finalNode.version === nodeIdentity.version
    && finalGit.sha256 === git.sha256 && finalGit.version === git.version
    && finalModuleCache.fileCount === moduleCache.fileCount && finalModuleCache.bytes === moduleCache.bytes
    && finalGo.sha256 === goIdentity.sha256 && finalGo.toolchainFileCount === goIdentity.toolchainFileCount
    && finalGo.toolchainBytes === goIdentity.toolchainBytes,
  "United Pass protected release inputs changed during the build");
}

async function sealSourceTree(entryPath) {
  const entryStat = await lstat(entryPath, { bigint: true });
  invariant(!entryStat.isSymbolicLink(), `detached build capsule contains a symbolic link: ${entryPath}`);
  if (entryStat.isDirectory()) {
    const entries = await readdir(entryPath);
    entries.sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
    for (const entry of entries) await sealSourceTree(path.join(entryPath, entry));
    await chmod(entryPath, 0o555);
    return;
  }
  invariant(entryStat.isFile() && entryStat.nlink === 1n,
    `detached build capsule contains a non-regular or linked source entry: ${entryPath}`);
  await chmod(entryPath, (entryStat.mode & 0o111n) === 0n ? 0o444 : 0o555);
}

async function removeOwnedReleaseTree(root, expectedParent, prefix, expectedIdentity) {
  invariant(path.dirname(root) === expectedParent && path.basename(root).startsWith(prefix),
    "refusing to clean an unexpected United Pass release path");
  await quarantineAndRemoveReleaseTree({
    root,
    expectedParent,
    expectedIdentity,
    matches: sameDirectoryObject,
    label: "owned United Pass release tree",
  });
}

export async function removeExactPublishedOutput(root, expectedParent, expectedIdentity) {
  invariant(path.dirname(root) === expectedParent && isSafeBasename(path.basename(root)),
    "refusing to clean an unexpected formal United Pass release path");
  await quarantineAndRemoveReleaseTree({
    root,
    expectedParent,
    expectedIdentity,
    matches: samePublishedIdentity,
    label: "formal United Pass release output",
  });
}

async function quarantineAndRemoveReleaseTree({ root, expectedParent, expectedIdentity, matches, label }) {
  if (!await pathExists(root)) return;
  const rootStats = await lstat(root, { bigint: true });
  invariant(rootStats.isDirectory() && !rootStats.isSymbolicLink() && matches(rootStats, expectedIdentity),
    `refusing to clean a replaced ${label}`);
  const quarantineRoot = await mkdtemp(path.join(expectedParent, ".united-pass-api-cleanup-"));
  const quarantineIdentity = directoryObjectIdentity(await lstat(quarantineRoot, { bigint: true }));
  const quarantinedTree = path.join(quarantineRoot, "owned-tree");
  let moved = false;
  try {
    await rename(root, quarantinedTree);
    moved = true;
    const movedStats = await lstat(quarantinedTree, { bigint: true });
    if (!movedStats.isDirectory() || movedStats.isSymbolicLink() || !matches(movedStats, expectedIdentity)) {
      if (!await pathExists(root)) {
        await rename(quarantinedTree, root);
        moved = false;
      }
      throw new Error(`refusing to clean ${label} whose identity changed during quarantine`);
    }
    await makeDirectoriesWritable(quarantinedTree);
    const finalStats = await lstat(quarantinedTree, { bigint: true });
    invariant(finalStats.isDirectory() && !finalStats.isSymbolicLink()
      && matches(finalStats, expectedIdentity),
    `refusing to clean quarantined ${label} whose identity changed`);
    await rm(quarantinedTree, { force: true, recursive: true });
    moved = false;
  } finally {
    if (moved && await pathExists(quarantinedTree) && !await pathExists(root)) {
      const remaining = await lstat(quarantinedTree, { bigint: true });
      if (remaining.isDirectory() && !remaining.isSymbolicLink()
          && matches(remaining, expectedIdentity)) {
        await rename(quarantinedTree, root);
        moved = false;
      }
    }
    invariant(!moved, `exact ${label} remains quarantined at ${quarantinedTree}`);
    const quarantineStats = await lstat(quarantineRoot, { bigint: true });
    invariant(quarantineStats.isDirectory() && !quarantineStats.isSymbolicLink()
      && sameDirectoryObject(quarantineStats, quarantineIdentity),
    "refusing to clean a replaced United Pass release quarantine");
    invariant((await readdir(quarantineRoot)).length === 0,
      `refusing to remove a non-empty United Pass release quarantine: ${quarantineRoot}`);
    await rmdir(quarantineRoot);
  }
}

async function makeDirectoriesWritable(entryPath) {
  const entryStat = await lstat(entryPath, { bigint: true });
  if (!entryStat.isDirectory() || entryStat.isSymbolicLink()) return;
  await chmod(entryPath, 0o700);
  for (const entry of await readdir(entryPath)) await makeDirectoriesWritable(path.join(entryPath, entry));
}

async function pathExists(value) {
  try {
    await lstat(value, { bigint: true });
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function directoryObjectIdentity(stats) {
  return Object.freeze({ dev: stats.dev, ino: stats.ino, birthtimeNs: stats.birthtimeNs });
}

function sameDirectoryObject(stats, expected) {
  return stats.dev === expected.dev && stats.ino === expected.ino
    && stats.birthtimeNs === expected.birthtimeNs;
}

function publishedDirectoryIdentity(stats) {
  return Object.freeze({
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    mtimeNs: stats.mtimeNs,
    birthtimeNs: stats.birthtimeNs,
  });
}

function samePublishedIdentity(stats, expected) {
  return sameDirectoryObject(stats, expected) && stats.size === expected.size
    && stats.mtimeNs === expected.mtimeNs;
}

function parseExactBuildInfo(bytes) {
  invariant(bytes.byteLength >= 2 && bytes.byteLength <= 4096, "compiled API --build-info output size is invalid");
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error("compiled API --build-info output is invalid JSON", { cause: error });
  }
  const keys = Object.keys(value).sort();
  const expectedKeys = ["sourceCommit", "sourceTree", "profile", "goVersion", "goos", "goarch"].sort();
  invariant(JSON.stringify(keys) === JSON.stringify(expectedKeys), "compiled API --build-info fields are invalid");
  const exactBytes = Buffer.from(`${JSON.stringify({
    sourceCommit: value.sourceCommit,
    sourceTree: value.sourceTree,
    profile: value.profile,
    goVersion: value.goVersion,
    goos: value.goos,
    goarch: value.goarch,
  })}\n`, "utf8");
  invariant(bytes.equals(exactBytes), "compiled API --build-info output is not canonical");
  return value;
}

function gitAt(git, cwd, ...args) {
  return runProtectedGit(git, cwd, args).trim();
}

function gitAtRaw(git, cwd, ...args) {
  return runProtectedGit(git, cwd, args, { encoding: "buffer" });
}

function isInside(candidate, parent) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function isSafeBasename(value) {
  return typeof value === "string" && value !== "" && value !== "." && value !== ".."
    && ![...value].some((character) => character.charCodeAt(0) <= 0x1f || character.charCodeAt(0) === 0x7f
      || character === ":" || character === "/" || character === "\\")
    && !value.endsWith(".") && !value.endsWith(" ");
}

function optionValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? "" : process.argv[index + 1] ?? "";
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}
