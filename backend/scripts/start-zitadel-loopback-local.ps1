[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$stateRoot = Join-Path $repoRoot '.zitadel\native'
$secretFile = Join-Path $stateRoot 'secrets.json'
$initKeyFile = Join-Path $stateRoot 'init-sa.json'
$configFile = Join-Path $PSScriptRoot 'zitadel-loopback-local.yaml'
$databaseBootstrapFile = Join-Path $PSScriptRoot 'setup-zitadel-loopback-db.sh'
$zitadelBinary = Join-Path $repoRoot 'bin\zitadel-v2.71.18-loopback.exe'
$mailpitBinary = Join-Path $repoRoot '.zitadel\mailpit-v1.31.0\mailpit.exe'
$mailpitDatabase = Join-Path $stateRoot 'mailpit.db'
$mailpitPidFile = Join-Path $stateRoot 'mailpit.pid'
$zitadelPidFile = Join-Path $stateRoot 'zitadel.pid'
$zitadelAttestationFile = Join-Path $stateRoot 'zitadel-launch-attestation.json'
$mailpitStdout = Join-Path $stateRoot 'mailpit.stdout.log'
$mailpitStderr = Join-Path $stateRoot 'mailpit.stderr.log'
$zitadelStdout = Join-Path $stateRoot 'zitadel.stdout.log'
$zitadelStderr = Join-Path $stateRoot 'zitadel.stderr.log'
$zitadelInitStdout = Join-Path $stateRoot 'zitadel.init.stdout.log'
$zitadelInitStderr = Join-Path $stateRoot 'zitadel.init.stderr.log'

$zitadelPort = 18185
$mailpitHTTPPort = 18186
$mailpitSMTPPort = 11026
$postgresPort = 15433
$databaseName = 'zitadel_dreamup_e2e'
$databaseRole = 'zitadel_dreamup_e2e'

function New-HexSecret {
    param([Parameter(Mandatory)][ValidateRange(16, 128)][int]$Bytes)

    $buffer = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [System.Convert]::ToHexString($buffer).ToLowerInvariant()
}

function New-BootstrapPassword {
    return 'Aa1!' + (New-HexSecret -Bytes 30)
}

function Protect-SecretFile {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grants = @(
        ('*{0}:(F)' -f $currentSid),
        '*S-1-5-18:(F)',
        '*S-1-5-32-544:(F)'
    )
    $icaclsOutput = & icacls.exe $LiteralPath '/inheritance:r' '/grant:r' @grants 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict local secret ACL: $($icaclsOutput -join ' ')"
    }
}

function Get-SHA256Hex {
    param([Parameter(Mandatory)][string]$LiteralPath)

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-CleanZitadelEnvironment {
    $preexisting = @(Get-ChildItem Env: | Where-Object { $_.Name -like 'ZITADEL_*' })
    if ($preexisting.Count -ne 0) {
        $names = ($preexisting.Name | Sort-Object) -join ', '
        throw "Refusing to launch local ZITADEL with pre-existing ZITADEL_* variables: $names"
    }
}

function Assert-ZitadelLaunchAttestation {
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)

    if (-not (Test-Path -LiteralPath $zitadelAttestationFile -PathType Leaf)) {
        throw 'The running local ZITADEL process has no clean-launch attestation; stop it locally and start it again with this script'
    }
    $item = Get-Item -LiteralPath $zitadelAttestationFile -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The local ZITADEL launch attestation must not be a reparse point'
    }
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReadOnly)) {
        throw 'The local ZITADEL launch attestation must be read-only'
    }
    Protect-SecretFile -LiteralPath $zitadelAttestationFile
    try {
        $attestation = Get-Content -LiteralPath $zitadelAttestationFile -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw 'The local ZITADEL launch attestation is malformed'
    }
    $expectedBinaryPath = [IO.Path]::GetFullPath($zitadelBinary)
    $expectedConfigPath = [IO.Path]::GetFullPath($configFile)
    $expectedStartTime = $Process.StartTime.ToUniversalTime().ToString('O')
    if ($attestation.formatVersion -ne 1 -or
        [int]$attestation.pid -ne $Process.Id -or
        [string]$attestation.processStartTimeUtc -cne $expectedStartTime -or
        [string]$attestation.binaryPath -cne $expectedBinaryPath -or
        [string]$attestation.binarySha256 -cne (Get-SHA256Hex -LiteralPath $zitadelBinary) -or
        [string]$attestation.configPath -cne $expectedConfigPath -or
        [string]$attestation.configSha256 -cne (Get-SHA256Hex -LiteralPath $configFile) -or
        [string]$attestation.launcherSha256 -cne (Get-SHA256Hex -LiteralPath $PSCommandPath) -or
        [string]$attestation.environmentPolicy -cne 'reject-preexisting-own-exact-zitadel-env-v1' -or
        [string]$attestation.databaseBoundary -cne 'zitadel_dreamup_e2e@zitadel_dreamup_e2e:15433') {
        throw 'The local ZITADEL launch attestation does not match the running process and repository configuration'
    }
}

function Write-ZitadelLaunchAttestation {
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)

    if (Test-Path -LiteralPath $zitadelAttestationFile) {
        $existing = Get-Item -LiteralPath $zitadelAttestationFile -Force
        if ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Refusing to replace a reparse-point ZITADEL launch attestation'
        }
        [IO.File]::SetAttributes($zitadelAttestationFile, [IO.FileAttributes]::Normal)
        Remove-Item -LiteralPath $zitadelAttestationFile -Force
    }
    $attestation = [ordered]@{
        formatVersion       = 1
        pid                 = $Process.Id
        processStartTimeUtc = $Process.StartTime.ToUniversalTime().ToString('O')
        binaryPath          = [IO.Path]::GetFullPath($zitadelBinary)
        binarySha256        = Get-SHA256Hex -LiteralPath $zitadelBinary
        configPath          = [IO.Path]::GetFullPath($configFile)
        configSha256        = Get-SHA256Hex -LiteralPath $configFile
        launcherSha256      = Get-SHA256Hex -LiteralPath $PSCommandPath
        environmentPolicy   = 'reject-preexisting-own-exact-zitadel-env-v1'
        databaseBoundary    = 'zitadel_dreamup_e2e@zitadel_dreamup_e2e:15433'
    }
    $json = $attestation | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($zitadelAttestationFile, $json, [Text.UTF8Encoding]::new($false))
    Protect-SecretFile -LiteralPath $zitadelAttestationFile
    [IO.File]::SetAttributes(
        $zitadelAttestationFile,
        [IO.File]::GetAttributes($zitadelAttestationFile) -bor [IO.FileAttributes]::ReadOnly
    )
    Assert-ZitadelLaunchAttestation -Process $Process
}

function Convert-ToWslPath {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($root.Length -ne 3 -or $root[1] -ne ':') {
        throw "Only local drive paths can be converted to WSL paths: $fullPath"
    }
    $drive = [char]::ToLowerInvariant($root[0])
    $suffix = $fullPath.Substring(3).Replace('\', '/')
    return "/mnt/$drive/$suffix"
}

function Get-ExpectedProcess {
    param(
        [Parameter(Mandatory)][string]$PidFile,
        [Parameter(Mandatory)][string]$ExpectedExecutable
    )

    if (-not (Test-Path -LiteralPath $PidFile)) {
        return $null
    }
    $rawPid = [System.IO.File]::ReadAllText($PidFile).Trim()
    $parsedPid = 0
    if (-not [int]::TryParse($rawPid, [ref]$parsedPid)) {
        return $null
    }
    $process = Get-Process -Id $parsedPid -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $null
    }
    $actualPath = [System.IO.Path]::GetFullPath($process.Path)
    $expectedPath = [System.IO.Path]::GetFullPath($ExpectedExecutable)
    if (-not $actualPath.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "PID $parsedPid belongs to a different executable: $actualPath"
    }
    return $process
}

function Assert-PortFree {
    param([Parameter(Mandatory)][int]$Port)

    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        $description = ($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) pid=$($_.OwningProcess)" }) -join ', '
        throw "Port $Port is already in use: $description"
    }
}

function Assert-LoopbackListener {
    param(
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][int]$ProcessId
    )

    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) {
        throw "No listener appeared on port $Port"
    }
    foreach ($listener in $listeners) {
        if ($listener.OwningProcess -ne $ProcessId -or $listener.LocalAddress -ne '127.0.0.1') {
            throw "Unsafe listener on port ${Port}: $($listener.LocalAddress), pid=$($listener.OwningProcess)"
        }
    }
}

foreach ($required in @($configFile, $databaseBootstrapFile, $zitadelBinary, $mailpitBinary)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required local artifact is missing: $required"
    }
}

Assert-CleanZitadelEnvironment

New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stateRoot 'notifications') | Out-Null

if (-not (Test-Path -LiteralPath $secretFile)) {
    $secretState = [ordered]@{
        formatVersion = 4
        masterKey = (New-HexSecret -Bytes 16)
        databasePassword = (New-HexSecret -Bytes 32)
        bootstrapAdminPassword = (New-BootstrapPassword)
    }
    $json = $secretState | ConvertTo-Json -Depth 3
    [System.IO.File]::WriteAllText($secretFile, $json, [System.Text.UTF8Encoding]::new($false))
    Protect-SecretFile -LiteralPath $secretFile
}

$secrets = Get-Content -LiteralPath $secretFile -Raw | ConvertFrom-Json
if ($secrets.formatVersion -in @(1, 2, 3) -and
    $secrets.masterKey -match '^[0-9a-f]{32}$' -and
    $secrets.databasePassword -match '^[0-9a-f]{64}$' -and
    $secrets.bootstrapAdminPassword -match '^.{16,72}$') {
    $bootstrapAdminPassword = [string]$secrets.bootstrapAdminPassword
    if ($bootstrapAdminPassword -notmatch '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{16,72}$') {
        $bootstrapAdminPassword = New-BootstrapPassword
    }
    $secretState = [ordered]@{
        formatVersion = 4
        masterKey = [string]$secrets.masterKey
        databasePassword = [string]$secrets.databasePassword
        bootstrapAdminPassword = $bootstrapAdminPassword
    }
    $json = $secretState | ConvertTo-Json -Depth 3
    [System.IO.File]::WriteAllText($secretFile, $json, [System.Text.UTF8Encoding]::new($false))
    Protect-SecretFile -LiteralPath $secretFile
    $secrets = Get-Content -LiteralPath $secretFile -Raw | ConvertFrom-Json
}
if ($secrets.formatVersion -ne 4 -or
    $secrets.masterKey -notmatch '^[0-9a-f]{32}$' -or
    $secrets.databasePassword -notmatch '^[0-9a-f]{64}$' -or
    $secrets.bootstrapAdminPassword -notmatch '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{16,72}$') {
    throw 'The local ZITADEL secret file is malformed'
}
Protect-SecretFile -LiteralPath $secretFile

$wslSecretFile = Convert-ToWslPath -LiteralPath $secretFile
$wslDatabaseBootstrapFile = Convert-ToWslPath -LiteralPath $databaseBootstrapFile
$dbResult = & wsl.exe -d Ubuntu -- bash $wslDatabaseBootstrapFile $wslSecretFile 2>&1
if ($LASTEXITCODE -ne 0 -or ($dbResult -join "`n") -notmatch 'ZITADEL_DB_READY') {
    throw "Failed to prepare the isolated local ZITADEL database: $($dbResult -join ' ')"
}

$mailpitProcess = Get-ExpectedProcess -PidFile $mailpitPidFile -ExpectedExecutable $mailpitBinary
if ($null -eq $mailpitProcess) {
    Assert-PortFree -Port $mailpitHTTPPort
    Assert-PortFree -Port $mailpitSMTPPort
    $mailpitArgs = @(
        '--listen', "127.0.0.1:$mailpitHTTPPort",
        '--smtp', "127.0.0.1:$mailpitSMTPPort",
        '--database', $mailpitDatabase,
        '--quiet'
    )
    $mailpitProcess = Start-Process -FilePath $mailpitBinary -ArgumentList $mailpitArgs `
        -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $mailpitStdout -RedirectStandardError $mailpitStderr
    [System.IO.File]::WriteAllText($mailpitPidFile, [string]$mailpitProcess.Id)
    Start-Sleep -Milliseconds 750
}
Assert-LoopbackListener -Port $mailpitHTTPPort -ProcessId $mailpitProcess.Id
Assert-LoopbackListener -Port $mailpitSMTPPort -ProcessId $mailpitProcess.Id

$zitadelProcess = Get-ExpectedProcess -PidFile $zitadelPidFile -ExpectedExecutable $zitadelBinary
if ($null -eq $zitadelProcess) {
    Assert-PortFree -Port $zitadelPort
    if (Test-Path -LiteralPath $zitadelPidFile) {
        Remove-Item -LiteralPath $zitadelPidFile -Force
    }
    $zitadelEnvironment = [ordered]@{
        ZITADEL_MASTERKEY = [string]$secrets.masterKey
        ZITADEL_DATABASE_POSTGRES_USER_PASSWORD = [string]$secrets.databasePassword
        ZITADEL_FIRSTINSTANCE_INSTANCENAME = 'DreamUP Local E2E'
        ZITADEL_FIRSTINSTANCE_DEFAULTLANGUAGE = 'zh'
        ZITADEL_FIRSTINSTANCE_ORG_NAME = 'DreamUP Local E2E'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME = 'local-admin'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_FIRSTNAME = 'DreamUP'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_LASTNAME = 'Local Admin'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_DISPLAYNAME = 'DreamUP Local Admin'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_ADDRESS = 'local-admin@dreamup.local'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_VERIFIED = 'true'
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD = [string]$secrets.bootstrapAdminPassword
        ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED = 'false'
        ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME = 'up-init-sa'
        ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME = 'United Pass local initializer'
        ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINEKEY_TYPE = '1'
        ZITADEL_FIRSTINSTANCE_MACHINEKEYPATH = $initKeyFile
    }
    foreach ($entry in $zitadelEnvironment.GetEnumerator()) {
        [System.Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    try {
        $zitadelInitArgs = @(
            'init',
            'zitadel',
            '--config', $configFile
        )
        $zitadelInitProcess = Start-Process -FilePath $zitadelBinary -ArgumentList $zitadelInitArgs `
            -WorkingDirectory $repoRoot -WindowStyle Hidden -Wait -PassThru `
            -RedirectStandardOutput $zitadelInitStdout -RedirectStandardError $zitadelInitStderr
        if ($zitadelInitProcess.ExitCode -ne 0) {
            throw "ZITADEL internal database initialization failed with code $($zitadelInitProcess.ExitCode); inspect $zitadelInitStderr"
        }
        $zitadelArgs = @(
            'start-from-setup',
            '--config', $configFile,
            '--masterkeyFromEnv',
            '--tlsMode', 'disabled'
        )
        $zitadelProcess = Start-Process -FilePath $zitadelBinary -ArgumentList $zitadelArgs `
            -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $zitadelStdout -RedirectStandardError $zitadelStderr
        [System.IO.File]::WriteAllText($zitadelPidFile, [string]$zitadelProcess.Id)
        try {
            Write-ZitadelLaunchAttestation -Process $zitadelProcess
        }
        catch {
            Stop-Process -Id $zitadelProcess.Id -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $zitadelPidFile -Force -ErrorAction SilentlyContinue
            throw
        }
    }
    finally {
        foreach ($key in $zitadelEnvironment.Keys) {
            [System.Environment]::SetEnvironmentVariable($key, $null, 'Process')
        }
    }
}

Assert-ZitadelLaunchAttestation -Process $zitadelProcess

$ready = $false
for ($attempt = 0; $attempt -lt 240; $attempt++) {
    if ($zitadelProcess.HasExited) {
        throw "ZITADEL exited during startup with code $($zitadelProcess.ExitCode); inspect $zitadelStderr"
    }
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$zitadelPort/debug/ready" -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    }
    catch {
        Start-Sleep -Milliseconds 500
    }
}
if (-not $ready) {
    throw "ZITADEL did not become ready; inspect $zitadelStderr"
}

Assert-LoopbackListener -Port $zitadelPort -ProcessId $zitadelProcess.Id
if (-not (Test-Path -LiteralPath $initKeyFile -PathType Leaf)) {
    throw 'ZITADEL became ready without producing the local initializer key'
}
Protect-SecretFile -LiteralPath $initKeyFile

[pscustomobject]@{
    ZitadelPID = $zitadelProcess.Id
    ZitadelURL = "http://127.0.0.1:$zitadelPort"
    MailpitPID = $mailpitProcess.Id
    MailpitURL = "http://127.0.0.1:$mailpitHTTPPort"
    SMTP = "127.0.0.1:$mailpitSMTPPort"
    Database = "$databaseName@$($databaseRole):$postgresPort"
    ListenerBoundary = '127.0.0.1 only'
} | Format-List
