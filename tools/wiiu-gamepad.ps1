param(
    [ValidateRange(1, 3600)][int]$Seconds = 600,
    [ValidateSet(36, 40, 44, 48, 149, 153, 157, 161, 165)][int]$Channel = 161,
    [switch]$Scan,
    [switch]$Build
)
# Windows PowerShell 5.1 wraps redirected native stderr in NativeCommandError.
# AP diagnostics intentionally use stderr; judge native calls by their exit code.
$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..') -ErrorAction Stop).Path
$binary = Join-Path $repoRoot 'build\Release\ap_wiiu.exe'
$taskEnv = @{
    DEVOURER_VID = '0x0bda'; DEVOURER_PID = '0x8812'
    DEVOURER_CHANNEL = "$Channel"; DEVOURER_TX_WITH_RX = 'thread'
    DEVOURER_BCN_TU = '25'; DEVOURER_WIIU_ROT = 'ptk3'
    DEVOURER_LOG_LEVEL = 'warn'; DEVOURER_EVENTS = 'off'
    DEVOURER_WIIU_CONFIG = (Join-Path $repoRoot 'secrets\vanilla-config.xml')
    DEVOURER_WIIU_BSSID = $null; DEVOURER_WIIU_PSK = $null
    DEVOURER_WIIU_SSID = $null; DEVOURER_WIIU_STD_OUI = $null
    DEVOURER_WIIU_IE_TAIL = $null
}
$savedEnv = @{}
Push-Location -LiteralPath $repoRoot -ErrorAction Stop
try {
    if ($Build) {
        & cmake --build build --config Release --target ap_wiiu
        if ($LASTEXITCODE -ne 0) { throw 'ap_wiiu build failed' }
    }
    if (-not (Test-Path -LiteralPath $binary)) { throw 'Build first: use -Build' }
    foreach ($key in $taskEnv.Keys) {
        $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $taskEnv[$key], 'Process')
    }
    if ($Scan) {
        & $binary --scan $Seconds
    } else {
        Write-Host 'Keep the real Wii U console OFF and the VM OFF. Power on the GamePad.'
        Write-Host 'Cemu input API: DSUController; IP 127.0.0.1; port 26760; Controller 1.'
        Write-Host 'Prototype: buttons, sticks and touch. Video/audio/motion are pending.'
        & $binary $Seconds
    }
    $runResult = $LASTEXITCODE
} finally {
    foreach ($key in $savedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], 'Process')
    }
    Pop-Location
}
exit $runResult
