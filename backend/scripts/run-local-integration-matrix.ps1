#Requires -Version 7.2

[CmdletBinding()]
param(
    [ValidateSet("core", "full")]
    [string]$Mode = "full",

    [string]$ZitadelStateFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$backendRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$repositoryRoot = [IO.Path]::GetFullPath((Split-Path -Parent $backendRoot))
$dreamupRoot = Join-Path $repositoryRoot "dreamup"
$runToken = ([Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(6))).ToLowerInvariant()
$databaseRole = "up_it_$runToken"
$databaseName = "up_it_$runToken"
$databaseSchema = "up_it_schema_$runToken"
$redisPort = 16379
$redisDirectory = "/tmp/moonstone-up-it-$runToken"
$postgresProvisioned = $false
$redisProvisioned = $false
$matrixCompleted = $false
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$localCacheRoot = Join-Path $repositoryRoot ".git/local-integration-cache"
$localGoCache = Join-Path $localCacheRoot "go-build"
$localGoTemp = Join-Path $localCacheRoot "go-tmp"
$snapshotRoot = Join-Path $repositoryRoot ".git/local-integration-snapshots"
$snapshotDirectory = Join-Path $snapshotRoot $runToken
$snapshotDirectoryCreated = $false
$zitadelEvidence = $null
$currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowedSecretSids = @($currentUserSid, "S-1-5-18", "S-1-5-32-544")

$managedEnvironmentNames = @(
    "UP_TEST_DATABASE_URL",
    "UP_TEST_DATABASE_SCHEMA",
    "UP_TEST_REDIS_URL",
    "UP_TEST_REDIS_KEY_PREFIX",
    "UP_REDIS_KEY_PREFIX",
    "UP_TEST_ZITADEL_STATE_FILE",
    "UP_TEST_ZITADEL_BASE_URL",
    "UP_TEST_ZITADEL_KEY_FILE",
    "UP_TEST_ZITADEL_USER",
    "UP_TEST_ZITADEL_PASSWORD",
    "UP_TEST_ZITADEL_TOTP_SECRET",
    "UP_TEST_ZITADEL_PROJECT_ID",
    "UP_TEST_DISPOSABLE_RUN_TOKEN",
    "GOCACHE",
    "GOTMPDIR"
)
$savedEnvironment = @{}
foreach ($name in $managedEnvironmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function New-RandomHex {
    param([int]$ByteCount)

    return ([Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes($ByteCount))).ToLowerInvariant()
}

function Get-SHA256Hex {
    param([byte[]]$Bytes)

    return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}

function Assert-CommandAvailable {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "required command is unavailable: $Name"
    }
}

function Invoke-CheckedCommand {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory
    )

    Push-Location $WorkingDirectory
    try {
        & $FilePath @ArgumentList
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath exited with code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-WslScript {
    param(
        [string]$Script,
        [switch]$Quiet
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "wsl.exe"
    $startInfo.ArgumentList.Add("-e")
    $startInfo.ArgumentList.Add("bash")
    $startInfo.ArgumentList.Add("-s")
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "could not start WSL"
    }
    $process.StandardInput.Write($Script)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $process.Dispose()

    if (-not $Quiet) {
        if ($stdout) { Write-Host $stdout.TrimEnd() }
        if ($stderr) { Write-Warning $stderr.TrimEnd() }
    }
    if ($exitCode -ne 0) {
        throw "WSL script exited with code $exitCode"
    }
    return $stdout
}

function Assert-CanonicalRepositoryPath {
    param(
        [string]$Path,
        [string]$Label,
        [ValidateSet("Leaf", "Container")]
        [string]$PathType
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label path is empty"
    }
    $requested = [IO.Path]::GetFullPath($Path)
    $resolvedPath = (Resolve-Path -LiteralPath $requested -ErrorAction Stop).ProviderPath
    $resolved = [IO.Path]::GetFullPath($resolvedPath)
    if (-not $requested.Equals($resolved, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must use its canonical path"
    }

    $prefix = $repositoryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be stored inside the isolated integration repository"
    }

    $rootItem = Get-Item -LiteralPath $repositoryRoot -Force
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "isolated integration repository must not be a reparse point"
    }
    $relative = [IO.Path]::GetRelativePath($repositoryRoot, $resolved)
    $current = $repositoryRoot
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_ -ne "" })) {
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label path must not contain a symlink, junction, or reparse point"
        }
    }

    $resolvedItem = Get-Item -LiteralPath $resolved -Force
    if ($PathType -eq "Leaf" -and $resolvedItem.PSIsContainer) {
        throw "$Label must be a regular file"
    }
    if ($PathType -eq "Container" -and -not $resolvedItem.PSIsContainer) {
        throw "$Label must be a directory"
    }
    return $resolved
}

function Assert-ProtectedSecretAcl {
    param(
        [string]$Path,
        [string]$Label
    )

    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "$Label ACL must disable inheritance"
    }
    try {
        if ($acl.Owner -is [Security.Principal.SecurityIdentifier]) {
            $ownerSid = $acl.Owner.Value
        }
        elseif ($acl.Owner -is [Security.Principal.IdentityReference]) {
            $ownerSid = $acl.Owner.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        else {
            $ownerText = [string]$acl.Owner
            try {
                $ownerSid = [Security.Principal.SecurityIdentifier]::new($ownerText).Value
            }
            catch {
                $ownerSid = [Security.Principal.NTAccount]::new($ownerText).Translate(
                    [Security.Principal.SecurityIdentifier]
                ).Value
            }
        }
    }
    catch {
        throw "$Label ACL owner is unresolvable"
    }
    if ($ownerSid -notin $allowedSecretSids) {
        throw "$Label ACL owner is outside the approved local principals"
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $acl.Access) {
        if ($rule.IsInherited) {
            throw "$Label ACL must not contain inherited rules"
        }
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            throw "$Label ACL contains an unresolvable principal"
        }
        if ($sid -notin $allowedSecretSids) {
            throw "$Label ACL grants access outside the approved local principals"
        }
        [void]$seen.Add($sid)
    }
    foreach ($sid in $allowedSecretSids) {
        if (-not $seen.Contains($sid)) {
            throw "$Label ACL is missing an approved local principal"
        }
    }
}

function Read-ProtectedRepositoryFile {
    param(
        [string]$Path,
        [string]$Label,
        [long]$MaximumBytes = 1MB
    )

    $resolved = Assert-CanonicalRepositoryPath -Path $Path -Label $Label -PathType Leaf
    Assert-ProtectedSecretAcl -Path $resolved -Label $Label
    $stream = [IO.FileStream]::new(
        $resolved,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) {
            throw "$Label has an invalid size"
        }
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    $postReadPath = Assert-CanonicalRepositoryPath -Path $resolved -Label $Label -PathType Leaf
    Assert-ProtectedSecretAcl -Path $postReadPath -Label $Label
    if (-not $postReadPath.Equals($resolved, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label changed while it was read"
    }
    return [pscustomobject]@{
        Path  = $resolved
        Bytes = $bytes
        Hash  = Get-SHA256Hex -Bytes $bytes
    }
}

function Read-ZitadelState {
    param(
        [pscustomobject]$FileRecord,
        [string]$Label
    )

    try {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $jsonText = $utf8.GetString($FileRecord.Bytes)
        $state = $jsonText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "$Label is malformed or is not strict UTF-8 JSON"
    }
    if ($state -isnot [pscustomobject]) {
        throw "$Label must contain a JSON object"
    }
    foreach ($field in @("baseUrl", "keyFile", "user", "password", "totpSecret", "projectId")) {
        if ($null -eq $state.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace([string]$state.$field)) {
            throw "$Label is missing $field"
        }
    }

    $baseURL = [string]$state.baseUrl
    if ($baseURL -cnotmatch '^http://(?:127\.0\.0\.1|localhost):[1-9][0-9]{0,4}$') {
        throw "$Label endpoint must be a bare explicit loopback HTTP origin"
    }
    $baseUri = $null
    if (-not [Uri]::TryCreate($baseURL, [UriKind]::Absolute, [ref]$baseUri) -or
        $baseUri.Port -lt 1 -or $baseUri.Port -gt 65535 -or
        $baseUri.UserInfo -ne "" -or $baseUri.Query -ne "" -or $baseUri.Fragment -ne "" -or
        $baseUri.AbsolutePath -ne "/") {
        throw "$Label endpoint must be a bare explicit loopback HTTP origin"
    }
    if (-not [IO.Path]::IsPathFullyQualified([string]$state.keyFile)) {
        throw "$Label keyFile must be an absolute path inside the isolated repository"
    }
    return $state
}

function Get-LocalZitadelBoundaryEvidence {
    param(
        [string]$SourceStatePath,
        [pscustomobject]$State
    )

    $expectedStatePath = Join-Path $backendRoot ".zitadel\native\init-state.json"
    $resolvedStatePath = Assert-CanonicalRepositoryPath -Path $SourceStatePath -Label "ZITADEL source state" -PathType Leaf
    $resolvedExpectedStatePath = Assert-CanonicalRepositoryPath -Path $expectedStatePath -Label "expected local ZITADEL state" -PathType Leaf
    if (-not $resolvedStatePath.Equals($resolvedExpectedStatePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "full integration mode accepts only the repository-owned native ZITADEL state"
    }
    if ([string]$State.baseUrl -cnotin @("http://127.0.0.1:18185", "http://localhost:18185")) {
        throw "ZITADEL source state must target the fixed native loopback listener"
    }
    if ([string]$State.baseUrl -ceq "http://localhost:18185") {
        $localhostAddresses = @([Net.Dns]::GetHostAddresses("localhost"))
        if ($localhostAddresses.Count -eq 0 -or
            @($localhostAddresses | Where-Object { -not [Net.IPAddress]::IsLoopback($_) }).Count -ne 0) {
            throw "localhost must resolve exclusively to loopback addresses"
        }
    }

    $expectedKeyPath = Join-Path $backendRoot ".zitadel\native\sa-key.json"
    $resolvedKeyPath = Assert-CanonicalRepositoryPath -Path ([string]$State.keyFile) -Label "ZITADEL source service-account key" -PathType Leaf
    $resolvedExpectedKeyPath = Assert-CanonicalRepositoryPath -Path $expectedKeyPath -Label "expected local ZITADEL service-account key" -PathType Leaf
    if (-not $resolvedKeyPath.Equals($resolvedExpectedKeyPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "ZITADEL source state must use the repository-owned native service-account key"
    }

    $pidPath = Assert-CanonicalRepositoryPath -Path (Join-Path $backendRoot ".zitadel\native\zitadel.pid") -Label "local ZITADEL PID file" -PathType Leaf
    $binaryPath = Assert-CanonicalRepositoryPath -Path (Join-Path $backendRoot "bin\zitadel-v2.71.18-loopback.exe") -Label "local ZITADEL executable" -PathType Leaf
    $configPath = Assert-CanonicalRepositoryPath -Path (Join-Path $backendRoot "scripts\zitadel-loopback-local.yaml") -Label "local ZITADEL configuration" -PathType Leaf
    $launcherPath = Assert-CanonicalRepositoryPath -Path (Join-Path $backendRoot "scripts\start-zitadel-loopback-local.ps1") -Label "local ZITADEL launcher" -PathType Leaf
    $attestationRecord = Read-ProtectedRepositoryFile -Path (Join-Path $backendRoot ".zitadel\native\zitadel-launch-attestation.json") -Label "local ZITADEL launch attestation"
    if (-not ([IO.File]::GetAttributes($attestationRecord.Path) -band [IO.FileAttributes]::ReadOnly)) {
        throw "local ZITADEL launch attestation must be read-only"
    }
    try {
        $attestationText = [Text.UTF8Encoding]::new($false, $true).GetString($attestationRecord.Bytes)
        $attestation = $attestationText | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "local ZITADEL launch attestation is malformed"
    }
    $rawPID = [IO.File]::ReadAllText($pidPath).Trim()
    $processID = 0
    if (-not [int]::TryParse($rawPID, [ref]$processID) -or $processID -le 0) {
        throw "local ZITADEL PID file is invalid"
    }
    $process = Get-Process -Id $processID -ErrorAction Stop
    if ($process.HasExited) {
        throw "local ZITADEL process has exited"
    }
    $actualProcessPath = [IO.Path]::GetFullPath($process.Path)
    if (-not $actualProcessPath.Equals($binaryPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "fixed ZITADEL listener is not owned by the repository native executable"
    }
    $processRecord = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processID" -ErrorAction Stop
    $expectedCommandLine = '^"?' + [Regex]::Escape($binaryPath) + '"?\s+' +
        'start-from-setup\s+--config\s+"?' + [Regex]::Escape($configPath) + '"?\s+' +
        '--masterkeyFromEnv\s+--tlsMode\s+disabled\s*$'
    if ($null -eq $processRecord -or
        [string]$processRecord.CommandLine -cnotmatch $expectedCommandLine) {
        throw "local ZITADEL process was not started from the repository loopback configuration"
    }
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 18185 -ErrorAction Stop)
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne "127.0.0.1" -or $listeners[0].OwningProcess -ne $processID) {
        throw "fixed ZITADEL port is not exclusively owned by the native loopback process"
    }
    $binaryHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $launcherHash = (Get-FileHash -LiteralPath $launcherPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($binaryHash -cnotmatch '^[0-9a-f]{64}$') {
        throw "local ZITADEL executable digest is invalid"
    }
    if ($configHash -cnotmatch '^[0-9a-f]{64}$') {
        throw "local ZITADEL configuration digest is invalid"
    }
    if ($launcherHash -cnotmatch '^[0-9a-f]{64}$') {
        throw "local ZITADEL launcher digest is invalid"
    }
    if ($attestation.formatVersion -ne 1 -or
        [int]$attestation.pid -ne $processID -or
        [string]$attestation.processStartTimeUtc -cne $process.StartTime.ToUniversalTime().ToString('O') -or
        [string]$attestation.binaryPath -cne $binaryPath -or
        [string]$attestation.binarySha256 -cne $binaryHash -or
        [string]$attestation.configPath -cne $configPath -or
        [string]$attestation.configSha256 -cne $configHash -or
        [string]$attestation.launcherSha256 -cne $launcherHash -or
        [string]$attestation.environmentPolicy -cne 'reject-preexisting-own-exact-zitadel-env-v1' -or
        [string]$attestation.databaseBoundary -cne 'zitadel_dreamup_e2e@zitadel_dreamup_e2e:15433') {
        throw "local ZITADEL launch attestation does not bind the clean launcher to this process"
    }
    $databaseBoundary = Invoke-WslScript -Quiet -Script @'
set -euo pipefail
runuser -u postgres -- psql -p 15433 -Atqc 'SHOW port; SHOW listen_addresses;'
runuser -u postgres -- psql -p 15433 -Atqc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'zitadel_dreamup_e2e'"
runuser -u postgres -- psql -p 15433 -Atqc "SELECT rolsuper::int::text || rolcreatedb::int::text || rolcreaterole::int::text || rolreplication::int::text || rolbypassrls::int::text FROM pg_roles WHERE rolname = 'zitadel_dreamup_e2e'"
'@
    $databaseBoundaryLines = @($databaseBoundary -split "`r?`n" | Where-Object { $_ -ne "" })
    if ($databaseBoundaryLines.Count -ne 4 -or
        $databaseBoundaryLines[0] -ne "15433" -or
        $databaseBoundaryLines[1] -ne "localhost" -or
        $databaseBoundaryLines[2] -ne "zitadel_dreamup_e2e" -or
        $databaseBoundaryLines[3] -ne "00000") {
        throw "local ZITADEL database is outside the repository isolation boundary"
    }
    return [pscustomobject]@{
        ProcessID  = $processID
        BinaryPath = $binaryPath
        BinaryHash = $binaryHash
        ConfigPath = $configPath
        ConfigHash = $configHash
        LauncherPath = $launcherPath
        LauncherHash = $launcherHash
        AttestationPath = $attestationRecord.Path
        AttestationHash = $attestationRecord.Hash
        StatePath  = $resolvedStatePath
        KeyPath    = $resolvedKeyPath
    }
}

function Assert-LocalZitadelBoundaryEvidence {
    param([pscustomobject]$Evidence)

    $stateRecord = Read-ProtectedRepositoryFile -Path $Evidence.StatePath -Label "ZITADEL source state"
    $state = Read-ZitadelState -FileRecord $stateRecord -Label "ZITADEL source state"
    $current = Get-LocalZitadelBoundaryEvidence -SourceStatePath $Evidence.StatePath -State $state
    if ($current.ProcessID -ne $Evidence.ProcessID -or
        $current.BinaryPath -cne $Evidence.BinaryPath -or
        $current.BinaryHash -cne $Evidence.BinaryHash -or
        $current.ConfigPath -cne $Evidence.ConfigPath -or
        $current.ConfigHash -cne $Evidence.ConfigHash -or
        $current.LauncherPath -cne $Evidence.LauncherPath -or
        $current.LauncherHash -cne $Evidence.LauncherHash -or
        $current.AttestationPath -cne $Evidence.AttestationPath -or
        $current.AttestationHash -cne $Evidence.AttestationHash -or
        $current.StatePath -cne $Evidence.StatePath -or
        $current.KeyPath -cne $Evidence.KeyPath) {
        throw "local ZITADEL process boundary changed during the integration matrix"
    }
}

function Protect-LocalSecretPath {
    param(
        [string]$Path,
        [switch]$Directory
    )

    $grants = if ($Directory) {
        @(
            "*${currentUserSid}:(OI)(CI)(F)",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-32-544:(OI)(CI)(F)"
        )
    }
    else {
        @(
            "*${currentUserSid}:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)"
        )
    }
    & icacls.exe $Path "/inheritance:r" "/grant:r" @grants *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "could not protect local integration snapshot ACL"
    }
}

function Write-ImmutableSnapshotFile {
    param(
        [string]$Path,
        [byte[]]$Bytes,
        [string]$Label
    )

    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
    Protect-LocalSecretPath -Path $Path
    [IO.File]::SetAttributes($Path, [IO.File]::GetAttributes($Path) -bor [IO.FileAttributes]::ReadOnly)
    $record = Read-ProtectedRepositoryFile -Path $Path -Label $Label
    if (-not ($record.Hash).Equals((Get-SHA256Hex -Bytes $Bytes), [StringComparison]::Ordinal)) {
        throw "$Label digest mismatch after creation"
    }
    return $record
}

function Initialize-ZitadelSnapshot {
    param([string]$SourceStatePath)

    if ([string]::IsNullOrWhiteSpace($SourceStatePath)) {
        throw "full integration mode requires -ZitadelStateFile; ZITADEL tests may not be silently skipped"
    }
    $sourceStateRecord = Read-ProtectedRepositoryFile -Path $SourceStatePath -Label "ZITADEL source state"
    $sourceState = Read-ZitadelState -FileRecord $sourceStateRecord -Label "ZITADEL source state"
    $localBoundary = Get-LocalZitadelBoundaryEvidence -SourceStatePath $sourceStateRecord.Path -State $sourceState
    $sourceKeyRecord = Read-ProtectedRepositoryFile -Path ([string]$sourceState.keyFile) -Label "ZITADEL source service-account key"

    $sourceStateRecheck = Read-ProtectedRepositoryFile -Path $sourceStateRecord.Path -Label "ZITADEL source state"
    if ($sourceStateRecheck.Hash -ne $sourceStateRecord.Hash) {
        throw "ZITADEL source state changed during snapshot creation"
    }
    $sourceKeyRecheck = Read-ProtectedRepositoryFile -Path $sourceKeyRecord.Path -Label "ZITADEL source service-account key"
    if ($sourceKeyRecheck.Hash -ne $sourceKeyRecord.Hash) {
        throw "ZITADEL source service-account key changed during snapshot creation"
    }

    [void](New-Item -ItemType Directory -Force -Path $snapshotRoot)
    [void](New-Item -ItemType Directory -Path $snapshotDirectory)
    $script:snapshotDirectoryCreated = $true
    Protect-LocalSecretPath -Path $snapshotDirectory -Directory
    [void](Assert-CanonicalRepositoryPath -Path $snapshotDirectory -Label "ZITADEL snapshot directory" -PathType Container)
    Assert-ProtectedSecretAcl -Path $snapshotDirectory -Label "ZITADEL snapshot directory"

    $snapshotKeyPath = Join-Path $snapshotDirectory "service-account-key.snapshot.json"
    $snapshotKeyRecord = Write-ImmutableSnapshotFile -Path $snapshotKeyPath -Bytes $sourceKeyRecord.Bytes -Label "ZITADEL snapshot service-account key"
    $snapshotStateObject = [ordered]@{
        baseUrl         = [string]$sourceState.baseUrl
        keyFile         = $snapshotKeyRecord.Path
        user            = [string]$sourceState.user
        password        = [string]$sourceState.password
        totpSecret      = [string]$sourceState.totpSecret
        projectId       = [string]$sourceState.projectId
        matrixKeySha256 = $snapshotKeyRecord.Hash
    }
    $snapshotStateBytes = [Text.UTF8Encoding]::new($false).GetBytes(($snapshotStateObject | ConvertTo-Json -Compress -Depth 4))
    $snapshotStatePath = Join-Path $snapshotDirectory "init-state.snapshot.json"
    $snapshotStateRecord = Write-ImmutableSnapshotFile -Path $snapshotStatePath -Bytes $snapshotStateBytes -Label "ZITADEL snapshot state"

    $evidence = [pscustomobject]@{
        SourceStatePath   = $sourceStateRecord.Path
        SourceStateHash   = $sourceStateRecord.Hash
        SourceKeyPath     = $sourceKeyRecord.Path
        SourceKeyHash     = $sourceKeyRecord.Hash
        SnapshotStatePath = $snapshotStateRecord.Path
        SnapshotStateHash = $snapshotStateRecord.Hash
        SnapshotKeyPath   = $snapshotKeyRecord.Path
        SnapshotKeyHash   = $snapshotKeyRecord.Hash
        BaseURL           = [string]$sourceState.baseUrl
        LocalBoundary     = $localBoundary
    }
    Assert-ZitadelEvidence -Evidence $evidence
    return $evidence
}

function Assert-ZitadelEvidence {
    param([pscustomobject]$Evidence)

    Assert-LocalZitadelBoundaryEvidence -Evidence $Evidence.LocalBoundary

    $sourceStateRecord = Read-ProtectedRepositoryFile -Path $Evidence.SourceStatePath -Label "ZITADEL source state"
    $sourceKeyRecord = Read-ProtectedRepositoryFile -Path $Evidence.SourceKeyPath -Label "ZITADEL source service-account key"
    $snapshotStateRecord = Read-ProtectedRepositoryFile -Path $Evidence.SnapshotStatePath -Label "ZITADEL snapshot state"
    $snapshotKeyRecord = Read-ProtectedRepositoryFile -Path $Evidence.SnapshotKeyPath -Label "ZITADEL snapshot service-account key"

    if ($sourceStateRecord.Hash -ne $Evidence.SourceStateHash -or
        $sourceKeyRecord.Hash -ne $Evidence.SourceKeyHash -or
        $snapshotStateRecord.Hash -ne $Evidence.SnapshotStateHash -or
        $snapshotKeyRecord.Hash -ne $Evidence.SnapshotKeyHash) {
        throw "ZITADEL state/key digest changed during the integration matrix"
    }
    foreach ($snapshotPath in @($Evidence.SnapshotStatePath, $Evidence.SnapshotKeyPath)) {
        if (-not ([IO.File]::GetAttributes($snapshotPath) -band [IO.FileAttributes]::ReadOnly)) {
            throw "ZITADEL snapshot lost its read-only attribute"
        }
    }

    $sourceState = Read-ZitadelState -FileRecord $sourceStateRecord -Label "ZITADEL source state"
    $snapshotState = Read-ZitadelState -FileRecord $snapshotStateRecord -Label "ZITADEL snapshot state"
    $sourceKeyPath = Assert-CanonicalRepositoryPath -Path ([string]$sourceState.keyFile) -Label "ZITADEL source service-account key" -PathType Leaf
    $snapshotKeyPath = Assert-CanonicalRepositoryPath -Path ([string]$snapshotState.keyFile) -Label "ZITADEL snapshot service-account key" -PathType Leaf
    if (-not $sourceKeyPath.Equals($Evidence.SourceKeyPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not $snapshotKeyPath.Equals($Evidence.SnapshotKeyPath, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$snapshotState.matrixKeySha256 -ne $Evidence.SnapshotKeyHash -or
        [string]$snapshotState.baseUrl -cne $Evidence.BaseURL) {
        throw "ZITADEL state/key snapshot binding is invalid"
    }
}

function Open-ZitadelSnapshotLocks {
    param([pscustomobject]$Evidence)

    Assert-ZitadelEvidence -Evidence $Evidence
    $locks = [Collections.Generic.List[IO.FileStream]]::new()
    try {
        foreach ($path in @($Evidence.SnapshotStatePath, $Evidence.SnapshotKeyPath)) {
            $locks.Add([IO.FileStream]::new(
                $path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            ))
        }
        Assert-ZitadelEvidence -Evidence $Evidence
        return $locks
    }
    catch {
        foreach ($lock in $locks) { $lock.Dispose() }
        throw
    }
}

function Remove-ZitadelSnapshot {
    if (-not $snapshotDirectoryCreated -or -not (Test-Path -LiteralPath $snapshotDirectory)) {
        return
    }
    [void](Assert-CanonicalRepositoryPath -Path $snapshotDirectory -Label "ZITADEL snapshot directory" -PathType Container)
    foreach ($path in @(
        (Join-Path $snapshotDirectory "init-state.snapshot.json"),
        (Join-Path $snapshotDirectory "service-account-key.snapshot.json")
    )) {
        if (Test-Path -LiteralPath $path) {
            [void](Assert-CanonicalRepositoryPath -Path $path -Label "ZITADEL snapshot cleanup file" -PathType Leaf)
            [IO.File]::SetAttributes($path, [IO.FileAttributes]::Normal)
            Remove-Item -LiteralPath $path -Force
        }
    }
    if (@(Get-ChildItem -LiteralPath $snapshotDirectory -Force).Count -ne 0) {
        throw "ZITADEL snapshot directory contains unexpected residue"
    }
    Remove-Item -LiteralPath $snapshotDirectory -Force
    if (Test-Path -LiteralPath $snapshotDirectory) {
        throw "ZITADEL snapshot directory was not removed"
    }
}

function Clear-ManagedEnvironment {
    foreach ($name in $managedEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}

function Restore-ManagedEnvironment {
    foreach ($name in $managedEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
    }
}

Assert-CommandAvailable "go"
Assert-CommandAvailable "node"
Assert-CommandAvailable "npm"
Assert-CommandAvailable "wsl.exe"
Assert-CommandAvailable "icacls.exe"
if ($Mode -eq "full") {
    Assert-CommandAvailable "Get-NetTCPConnection"
    Assert-CommandAvailable "Get-FileHash"
    Assert-CommandAvailable "Get-CimInstance"
}

$postgresPassword = New-RandomHex -ByteCount 32
$redisPassword = New-RandomHex -ByteCount 32

try {
    Clear-ManagedEnvironment
    [void](New-Item -ItemType Directory -Force -Path $localGoCache)
    [void](New-Item -ItemType Directory -Force -Path $localGoTemp)
    [Environment]::SetEnvironmentVariable("GOCACHE", $localGoCache, "Process")
    [Environment]::SetEnvironmentVariable("GOTMPDIR", $localGoTemp, "Process")

    if ($Mode -eq "full") {
        $zitadelEvidence = Initialize-ZitadelSnapshot -SourceStatePath $ZitadelStateFile
    }

    $boundaryOutput = Invoke-WslScript -Quiet -Script @'
set -euo pipefail
command -v psql >/dev/null
command -v redis-server >/dev/null
command -v redis-cli >/dev/null
runuser -u postgres -- psql -p 15433 -Atqc 'SHOW port; SHOW listen_addresses;'
df -Pk /var/lib/postgresql | awk 'NR == 2 { print $4 }'
if (echo >/dev/tcp/127.0.0.1/16379) >/dev/null 2>&1; then
  exit 23
fi
'@
    $boundaryLines = @($boundaryOutput -split "`r?`n" | Where-Object { $_ -ne "" })
    if ($boundaryLines.Count -ne 3 -or $boundaryLines[0] -ne "15433" -or $boundaryLines[1] -ne "localhost") {
        throw "PostgreSQL boundary check failed; expected localhost:15433 only"
    }
    $postgresFreeKilobytes = 0L
    if (-not [long]::TryParse($boundaryLines[2], [ref]$postgresFreeKilobytes) -or $postgresFreeKilobytes -lt 524288) {
        throw "PostgreSQL integration volume requires at least 512 MiB free"
    }

    $resourceBoundaryOutput = Invoke-WslScript -Quiet -Script @"
set -euo pipefail
runuser -u postgres -- psql -p 15433 -Atqc "SELECT count(*) FROM pg_database WHERE datname = '$databaseName'"
runuser -u postgres -- psql -p 15433 -Atqc "SELECT count(*) FROM pg_roles WHERE rolname = '$databaseRole'"
if [[ -e '$redisDirectory' ]]; then printf '1\n'; else printf '0\n'; fi
"@
    $resourceBoundaryLines = @($resourceBoundaryOutput -split "`r?`n" | Where-Object { $_ -ne "" })
    if ($resourceBoundaryLines.Count -ne 3 -or $resourceBoundaryLines[0] -ne "0" -or
        $resourceBoundaryLines[1] -ne "0" -or $resourceBoundaryLines[2] -ne "0") {
        throw "disposable integration resource collision detected"
    }

    $createDatabaseSql = @"
CREATE ROLE $databaseRole WITH LOGIN PASSWORD '$postgresPassword' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20;
CREATE DATABASE $databaseName WITH OWNER $databaseRole ENCODING 'UTF8' TEMPLATE template0;
REVOKE CONNECT ON DATABASE $databaseName FROM PUBLIC;
GRANT CONNECT ON DATABASE $databaseName TO $databaseRole;
"@
    $postgresProvisioned = $true
    [void](Invoke-WslScript -Quiet -Script @"
set -euo pipefail
runuser -u postgres -- psql -p 15433 -v ON_ERROR_STOP=1 <<'SQL'
$createDatabaseSql
SQL
"@)

    $redisProvisioned = $true
    [void](Invoke-WslScript -Quiet -Script @"
set -euo pipefail
install -d -m 700 '$redisDirectory'
cat >'$redisDirectory/redis.conf' <<'REDIS_CONFIG'
bind 127.0.0.1
protected-mode yes
port $redisPort
daemonize yes
pidfile $redisDirectory/redis.pid
logfile $redisDirectory/redis.log
dir $redisDirectory
save ""
appendonly no
databases 16
requirepass $redisPassword
rename-command FLUSHALL ""
rename-command FLUSHDB ""
REDIS_CONFIG
chmod 600 '$redisDirectory/redis.conf'
redis-server '$redisDirectory/redis.conf'
for attempt in {1..50}; do
  if REDISCLI_AUTH='$redisPassword' redis-cli -h 127.0.0.1 -p $redisPort ping 2>/dev/null | grep -qx PONG; then
    exit 0
  fi
  sleep 0.1
done
exit 1
"@)

    $databaseUrl = "postgres://${databaseRole}:${postgresPassword}@127.0.0.1:15433/${databaseName}?sslmode=disable"
    $redisUrl = "redis://:${redisPassword}@127.0.0.1:${redisPort}/15"
    [Environment]::SetEnvironmentVariable("UP_TEST_DATABASE_URL", $databaseUrl, "Process")
    [Environment]::SetEnvironmentVariable("UP_TEST_DATABASE_SCHEMA", $databaseSchema, "Process")
    [Environment]::SetEnvironmentVariable("UP_TEST_REDIS_URL", $redisUrl, "Process")
    [Environment]::SetEnvironmentVariable("UP_TEST_REDIS_KEY_PREFIX", "up:local-it:${runToken}:", "Process")
    [Environment]::SetEnvironmentVariable("UP_TEST_DISPOSABLE_RUN_TOKEN", $runToken, "Process")

    $totalSteps = if ($Mode -eq "full") { 6 } else { 5 }
    Write-Host "[1/$totalSteps] United Pass in-process HTTP route contract"
    Invoke-CheckedCommand -FilePath "go" -ArgumentList @("test", "-count=1", "-timeout=30m", "-skip", "^TestFakeProviderWithDatabaseServesCurrentUser$", "./internal/adapters/httpapi", "./internal/bootstrap") -WorkingDirectory $backendRoot

    Write-Host "[2/$totalSteps] United Pass PostgreSQL integration"
    Invoke-CheckedCommand -FilePath "go" -ArgumentList @("test", "-count=1", "-timeout=30m", "-tags", "integration", "./internal/adapters/postgres/...") -WorkingDirectory $backendRoot

    Write-Host "[3/$totalSteps] United Pass Redis integration"
    Invoke-CheckedCommand -FilePath "go" -ArgumentList @("test", "-count=1", "-timeout=15m", "-tags", "integration", "./internal/adapters/redis/...") -WorkingDirectory $backendRoot

    Write-Host "[4/$totalSteps] United Pass PostgreSQL + Redis bootstrap seam"
    Invoke-CheckedCommand -FilePath "go" -ArgumentList @("test", "-count=1", "-timeout=10m", "./internal/bootstrap", "-run", "^TestFakeProviderWithDatabaseServesCurrentUser$") -WorkingDirectory $backendRoot

    Write-Host "[5/$totalSteps] DreamUP Miniflare D1 + R2 worker integration"
    Invoke-CheckedCommand -FilePath "npm" -ArgumentList @("run", "test:worker") -WorkingDirectory $dreamupRoot

    if ($Mode -eq "full") {
        [Environment]::SetEnvironmentVariable("UP_TEST_ZITADEL_STATE_FILE", $zitadelEvidence.SnapshotStatePath, "Process")
        Assert-ZitadelEvidence -Evidence $zitadelEvidence
        Write-Host "[6/6] United Pass native loopback ZITADEL + disposable PostgreSQL integration"
        $snapshotLocks = Open-ZitadelSnapshotLocks -Evidence $zitadelEvidence
        try {
            Invoke-CheckedCommand -FilePath "go" -ArgumentList @("test", "-count=1", "-timeout=15m", "-tags", "integration", "./internal/adapters/zitadel/...") -WorkingDirectory $backendRoot
        }
        finally {
            foreach ($lock in $snapshotLocks) { $lock.Dispose() }
        }
        Assert-ZitadelEvidence -Evidence $zitadelEvidence
    }

    $matrixCompleted = $true
}
catch {
    $primaryFailure = $_
}
finally {
    if ($null -ne $zitadelEvidence) {
        try {
            Assert-ZitadelEvidence -Evidence $zitadelEvidence
        }
        catch {
            $cleanupFailures.Add("ZITADEL post-run integrity verification")
        }
    }

    if ($redisProvisioned) {
        try {
            [void](Invoke-WslScript -Quiet -Script @"
set -euo pipefail
pid=''
if [[ -f '$redisDirectory/redis.pid' ]]; then
  pid="`$(cat '$redisDirectory/redis.pid')"
  REDISCLI_AUTH='$redisPassword' redis-cli -h 127.0.0.1 -p $redisPort shutdown nosave >/dev/null
  for attempt in {1..50}; do
    if ! kill -0 "`$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "`$pid" 2>/dev/null; then
    exit 31
  fi
fi
rm -f -- '$redisDirectory/redis.conf' '$redisDirectory/redis.pid' '$redisDirectory/redis.log'
if [[ -d '$redisDirectory' ]]; then
  rmdir -- '$redisDirectory'
fi
"@)
        }
        catch {
            $cleanupFailures.Add("Redis cleanup")
        }
    }

    if ($postgresProvisioned) {
        try {
            [void](Invoke-WslScript -Quiet -Script @"
set -euo pipefail
db_exists="`$(runuser -u postgres -- psql -p 15433 -Atqc "SELECT count(*) FROM pg_database WHERE datname = '$databaseName'")"
if [[ "`$db_exists" == '1' ]]; then
  runuser -u postgres -- psql -p 15433 -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER DATABASE $databaseName CONNECTION LIMIT 0;
REVOKE CONNECT ON DATABASE $databaseName FROM PUBLIC;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$databaseName' AND pid <> pg_backend_pid();
DROP DATABASE $databaseName;
SQL
fi
runuser -u postgres -- psql -p 15433 -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS $databaseRole;
SQL
"@)
        }
        catch {
            $cleanupFailures.Add("PostgreSQL cleanup")
        }
    }

    try {
        $residueOutput = Invoke-WslScript -Quiet -Script @"
set -euo pipefail
redis_count=0
if (echo >/dev/tcp/127.0.0.1/$redisPort) >/dev/null 2>&1; then
  redis_count=1
fi
db_count="`$(runuser -u postgres -- psql -p 15433 -Atqc "SELECT count(*) FROM pg_database WHERE datname = '$databaseName'")"
role_count="`$(runuser -u postgres -- psql -p 15433 -Atqc "SELECT count(*) FROM pg_roles WHERE rolname = '$databaseRole'")"
redis_dir_count=0
if [[ -e '$redisDirectory' ]]; then
  redis_dir_count=1
fi
printf 'redis=%s\ndatabase=%s\nrole=%s\nredis_dir=%s\n' "`$redis_count" "`$db_count" "`$role_count" "`$redis_dir_count"
[[ "`$redis_count" == '0' && "`$db_count" == '0' && "`$role_count" == '0' && "`$redis_dir_count" == '0' ]]
"@
        $residueLines = @($residueOutput -split "`r?`n" | Where-Object { $_ -ne "" })
        if ($residueLines.Count -ne 4 -or
            $residueLines[0] -ne "redis=0" -or
            $residueLines[1] -ne "database=0" -or
            $residueLines[2] -ne "role=0" -or
            $residueLines[3] -ne "redis_dir=0") {
            throw "local integration residue verification returned an invalid result"
        }
        Write-Host "LOCAL_INTEGRATION_RESIDUE redis=0 database=0 role=0"
    }
    catch {
        $cleanupFailures.Add("resource residue verification")
    }

    try {
        Remove-ZitadelSnapshot
    }
    catch {
        $cleanupFailures.Add("ZITADEL snapshot cleanup")
    }

    try {
        Restore-ManagedEnvironment
    }
    catch {
        $cleanupFailures.Add("process environment restoration")
    }
}

if ($null -ne $primaryFailure) {
    if ($cleanupFailures.Count -gt 0) {
        throw [Exception]::new(
            "local integration matrix failed and cleanup verification also failed: $($cleanupFailures -join ', ')",
            $primaryFailure.Exception
        )
    }
    throw $primaryFailure
}
if ($cleanupFailures.Count -gt 0) {
    throw "local integration cleanup failed: $($cleanupFailures -join ', ')"
}
if (-not $matrixCompleted) {
    throw "local integration matrix did not complete"
}

Write-Host "LOCAL_INTEGRATION_MATRIX_OK mode=$Mode"
