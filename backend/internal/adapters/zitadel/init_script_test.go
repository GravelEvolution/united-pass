//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Static security regressions for the local ZITADEL initializer
//

package zitadel

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitScriptDelegatesToHardenedGoBootstrap(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "scripts", "zitadel-init.sh")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read ZITADEL init script: %v", err)
	}
	text := string(script)

	for _, forbidden := range []string{
		"curl ",
		"Authorization: Bearer",
		"TEST_PASSWORD",
		"TOTP_SECRET",
		"HTTP_PROXY",
		"HTTPS_PROXY",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("compatibility wrapper reintroduced security-sensitive bootstrap logic: %s", forbidden)
		}
	}
	for _, required := range []string{
		`set -euo pipefail`,
		`pwd -P`,
		`exec go run ./cmd/zitadel-bootstrap "$@"`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("initializer missing security invariant %q", required)
		}
	}
	if strings.Contains(text, "\r") {
		t.Fatal("ZITADEL compatibility wrapper must use LF line endings")
	}

	attributes, err := os.ReadFile(filepath.Join("..", "..", "..", ".gitattributes"))
	if err != nil {
		t.Fatalf("read backend gitattributes: %v", err)
	}
	if !strings.Contains(string(attributes), "*.sh text eol=lf") {
		t.Fatal("backend gitattributes does not pin shell scripts to LF")
	}
}

func TestLocalIntegrationMatrixVerifiesIntegrityAndResidueBeforeSuccess(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "scripts", "run-local-integration-matrix.ps1")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read local integration matrix: %v", err)
	}
	text := string(script)

	for _, forbidden := range []string{"IgnoreExitCode", "LOCAL_INTEGRATION_MATRIX_OK mode=$Mode\"\n}"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("local integration matrix contains a fail-open construct: %q", forbidden)
		}
	}
	for _, required := range []string{
		"AreAccessRulesProtected",
		"$acl.Owner",
		"ReparsePoint",
		"matrixKeySha256",
		"Open-ZitadelSnapshotLocks",
		"Get-LocalZitadelBoundaryEvidence",
		"zitadel-v2.71.18-loopback.exe",
		"zitadel-loopback-local.yaml",
		"Get-NetTCPConnection -State Listen -LocalPort 18185",
		"[Net.Dns]::GetHostAddresses(\"localhost\")",
		"[Net.IPAddress]::IsLoopback",
		"Get-CimInstance -ClassName Win32_Process",
		"expectedCommandLine",
		"--masterkeyFromEnv\\s+--tlsMode\\s+disabled",
		"zitadel-launch-attestation.json",
		"reject-preexisting-own-exact-zitadel-env-v1",
		"AttestationHash",
		"zitadel_dreamup_e2e",
		"UP_TEST_DISPOSABLE_RUN_TOKEN",
		"United Pass in-process HTTP route contract",
		`"./internal/adapters/httpapi", "./internal/bootstrap"`,
		"[IO.FileShare]::Read",
		"[IO.FileAttributes]::ReadOnly",
		"Assert-ZitadelEvidence -Evidence $zitadelEvidence",
		"DROP ROLE IF EXISTS $databaseRole;",
		`$residueLines[0] -ne "redis=0"`,
		`$residueLines[1] -ne "database=0"`,
		`$residueLines[2] -ne "role=0"`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("local integration matrix missing fail-closed invariant %q", required)
		}
	}

	residue := strings.LastIndex(text, `Write-Host "LOCAL_INTEGRATION_RESIDUE redis=0 database=0 role=0"`)
	cleanupGate := strings.LastIndex(text, `if ($cleanupFailures.Count -gt 0) {`)
	success := strings.LastIndex(text, `Write-Host "LOCAL_INTEGRATION_MATRIX_OK mode=$Mode"`)
	if residue < 0 || cleanupGate < residue || success < cleanupGate {
		t.Fatalf("success marker is not gated by residue verification and cleanup: residue=%d cleanup=%d success=%d", residue, cleanupGate, success)
	}
}

func TestNativeLoopbackLauncherAttestsCleanProviderEnvironment(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "..", "scripts", "start-zitadel-loopback-local.ps1")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read native ZITADEL launcher: %v", err)
	}
	text := string(script)
	for _, required := range []string{
		"Get-ChildItem Env:",
		"Refusing to launch local ZITADEL with pre-existing ZITADEL_* variables",
		"zitadel-launch-attestation.json",
		"Write-ZitadelLaunchAttestation -Process $zitadelProcess",
		"Assert-ZitadelLaunchAttestation -Process $zitadelProcess",
		"reject-preexisting-own-exact-zitadel-env-v1",
		"launcherSha256",
		"processStartTimeUtc",
		"[IO.FileAttributes]::ReadOnly",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("native ZITADEL launcher missing clean-launch invariant %q", required)
		}
	}
}

func TestNativeLoopbackLauncherRejectsInheritedProviderEnvironment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native ZITADEL launcher regression is Windows-specific")
	}
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("PowerShell 7 is unavailable")
	}
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "start-zitadel-loopback-local.ps1"))
	if err != nil {
		t.Fatalf("resolve native ZITADEL launcher: %v", err)
	}
	program := `
$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:UP_ZITADEL_LAUNCHER_TEST_PATH,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) { throw "launcher script did not parse" }
$functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Assert-CleanZitadelEnvironment"
}, $true)
if ($null -eq $functionAst) { throw "clean-environment guard was not found" }
Invoke-Expression $functionAst.Extent.Text
$rejected = $false
try {
    Assert-CleanZitadelEnvironment
}
catch {
    if ($_.Exception.Message -notlike "*ZITADEL_MATRIX_UNSAFE*" -or
        $_.Exception.Message -like "*do-not-print-this-value*") { throw }
    $rejected = $true
}
if (-not $rejected) { throw "inherited provider override was accepted" }
$env:ZITADEL_MATRIX_UNSAFE = $null
Assert-CleanZitadelEnvironment
`
	cmd := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", program)
	cmd.Env = append(os.Environ(),
		"UP_ZITADEL_LAUNCHER_TEST_PATH="+scriptPath,
		"ZITADEL_MATRIX_UNSAFE=do-not-print-this-value",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native ZITADEL environment-boundary regression failed: %v\n%s", err, output)
	}
}

func TestLocalIntegrationMatrixRejectsUnapprovedSecretOwner(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("ACL owner regression is Windows-specific")
	}
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("PowerShell 7 is unavailable")
	}

	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "run-local-integration-matrix.ps1"))
	if err != nil {
		t.Fatalf("resolve local integration matrix path: %v", err)
	}
	testProgram := `
$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:UP_MATRIX_SCRIPT_TEST_PATH,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "matrix script did not parse"
}
$functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Assert-ProtectedSecretAcl"
}, $true)
if ($null -eq $functionAst) {
    throw "Assert-ProtectedSecretAcl was not found"
}
Invoke-Expression $functionAst.Extent.Text

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$allowedSecretSids = @($currentIdentity.User.Value, "S-1-5-18", "S-1-5-32-544")
$approvedRules = @($allowedSecretSids | ForEach-Object {
    [pscustomobject]@{
        IsInherited = $false
        AccessControlType = [Security.AccessControl.AccessControlType]::Allow
        IdentityReference = [Security.Principal.SecurityIdentifier]::new($_)
    }
})
$script:testAcl = [pscustomobject]@{
    Owner = $currentIdentity.Name
    AreAccessRulesProtected = $true
    Access = $approvedRules
}
$unapprovedOwner = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-545")
function Get-Acl {
    param([string]$LiteralPath)
    return $script:testAcl
}

$null = Assert-ProtectedSecretAcl -Path "ignored" -Label "test secret"
$script:testAcl.Owner = $unapprovedOwner
$rejected = $false
try {
    Assert-ProtectedSecretAcl -Path "ignored" -Label "test secret"
}
catch {
    if ($_.Exception.Message -notlike "*owner*approved local principals*") {
        throw
    }
    $rejected = $true
}
if (-not $rejected) {
    throw "unapproved ACL owner was accepted"
}
`

	cmd := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", testProgram)
	cmd.Env = append(os.Environ(), "UP_MATRIX_SCRIPT_TEST_PATH="+scriptPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unapproved ACL owner regression failed: %v\n%s", err, output)
	}
}
