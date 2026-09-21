param(
    [Parameter(Mandatory = $true)]
    [string]$RedisUrl,
    [string]$GoExe = "go"
)

$ErrorActionPreference = "Stop"
$previousRedisUrl = $env:UP_TEST_REDIS_URL
$previousRedisPrefix = $env:UP_TEST_REDIS_KEY_PREFIX
$previousRunToken = $env:UP_TEST_DISPOSABLE_RUN_TOKEN
$tokenBytes = New-Object byte[] 6
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
$runToken = -join ($tokenBytes | ForEach-Object { $_.ToString("x2") })
$env:UP_TEST_REDIS_URL = $RedisUrl
$env:UP_TEST_DISPOSABLE_RUN_TOKEN = $runToken
$env:UP_TEST_REDIS_KEY_PREFIX = "up:local-it:$runToken`:"

try {
    & $GoExe test -race -count=1 ./internal/riskdefense ./internal/registration
    if ($LASTEXITCODE -ne 0) { throw "risk/registration abuse matrix failed" }

    & $GoExe test -race -count=1 ./internal/adapters/httpapi -run 'Test(TrustedClientIP|ClientNetwork|Registration)'
    if ($LASTEXITCODE -ne 0) { throw "HTTP abuse matrix failed" }

    $listed = & $GoExe test -tags=integration ./internal/adapters/redis -list 'TestIntegration_(Registration|RiskStoreRegistration)'
    if ($LASTEXITCODE -ne 0 -or -not ($listed | Select-String '^TestIntegration_')) { throw "Redis abuse matrix selected zero tests" }

    & $GoExe test -race -tags=integration -count=1 ./internal/adapters/redis -run 'TestIntegration_(Registration|RiskStoreRegistration)'
    if ($LASTEXITCODE -ne 0) { throw "Redis abuse matrix failed" }
}
finally {
    $env:UP_TEST_REDIS_URL = $previousRedisUrl
    $env:UP_TEST_REDIS_KEY_PREFIX = $previousRedisPrefix
    $env:UP_TEST_DISPOSABLE_RUN_TOKEN = $previousRunToken
}
