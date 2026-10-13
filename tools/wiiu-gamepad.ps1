param(
    [ValidateRange(1, 3600)][int]$Seconds = 600,
    [ValidateSet(36, 40, 44, 48, 149, 153, 157, 161, 165)][int]$Channel = 161,
    [switch]$Scan,
    [switch]$Build,
    [ValidateSet('None', 'TestPattern', 'Cemu')][string]$Video = 'None',
    [ValidateSet('6M', '24M')][string]$DataRate = '24M',
    [switch]$AckRetries
)
# Windows PowerShell 5.1 wraps redirected native stderr in NativeCommandError.
# AP diagnostics intentionally use stderr; judge native calls by their exit code.
$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..') -ErrorAction Stop).Path
$target = if ($Video -eq 'None') { 'ap_wiiu' } else { 'ap_wiiu_video' }
$binary = Join-Path $repoRoot "build\Release\$target.exe"
$taskEnv = @{
    DEVOURER_VID = '0x0bda'; DEVOURER_PID = '0x8812'
    DEVOURER_CHANNEL = "$Channel"; DEVOURER_TX_WITH_RX = 'thread'
    DEVOURER_BCN_TU = '25'; DEVOURER_WIIU_ROT = 'ptk3'
    DEVOURER_LOG_LEVEL = 'warn'; DEVOURER_EVENTS = 'off'
    DEVOURER_WIIU_CONFIG = (Join-Path $repoRoot 'secrets\vanilla-config.xml')
    DEVOURER_WIIU_BSSID = $null; DEVOURER_WIIU_PSK = $null
    DEVOURER_WIIU_SSID = $null; DEVOURER_WIIU_STD_OUI = $null
    DEVOURER_WIIU_IE_TAIL = $null
    DEVOURER_WIIU_VIDEO = $(if ($Video -eq 'None') { '0' } else { '1' })
    DEVOURER_WIIU_DATA_RATE = $DataRate
    DEVOURER_WIIU_NOACK = $(if ($AckRetries) { '0' } else { '1' })
    DEVOURER_TX_USB_AGG = $(if ($Video -eq 'None') { '0' } else { '32' })
    DEVOURER_TX_RETRY_LIMIT = $(if ($Video -ne 'None' -and $AckRetries) { '3' } else { '0' })
}
$savedEnv = @{}
$encoderProcess = $null
Push-Location -LiteralPath $repoRoot -ErrorAction Stop
try {
    if ($Build) {
        & cmake --build build --config Release --target $target
        if ($LASTEXITCODE -ne 0) { throw 'ap_wiiu build failed' }
    }
    if (-not (Test-Path -LiteralPath $binary)) { throw 'Build first: use -Build' }
    if (Get-Process ap_wiiu,ap_wiiu_video -ErrorAction SilentlyContinue) {
        throw 'Another GamePad bridge is running. Stop it with Ctrl+C first.'
    }
    foreach ($key in $taskEnv.Keys) {
        $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $taskEnv[$key], 'Process')
    }
    if ($Scan) {
        & $binary --scan $Seconds
    } else {
        Write-Host 'Keep the real Wii U console OFF and the VM OFF. Power on the GamePad.'
        Write-Host 'Cemu input API: DSUController; IP 127.0.0.1; port 26760; Controller 1.'
        if ($Video -ne 'None') {
            $encoderBinary = Join-Path $repoRoot 'build\wiiu\wiiu-video.exe'
            if (-not (Test-Path -LiteralPath $encoderBinary)) {
                throw 'Build the encoder first: .\tools\build-wiiu-video.ps1'
            }
            $encoderArgs = @('--seconds', "$Seconds")
            if ($Video -eq 'TestPattern') { $encoderArgs += '--test-pattern' }
            $encoderProcess = Start-Process -FilePath $encoderBinary -ArgumentList $encoderArgs -PassThru -WindowStyle Hidden `
                -RedirectStandardError (Join-Path $repoRoot 'build\wiiu\video-encoder.log') `
                -RedirectStandardOutput (Join-Path $repoRoot 'build\wiiu\video-encoder.stdout.log')
            Write-Host "Video source: $Video; silent audio; motion pending."
        } else {
            Write-Host 'Input only: buttons, sticks and touch. Video/audio/motion are pending.'
        }
        & $binary $Seconds
    }
    $runResult = $LASTEXITCODE
} finally {
    if ($encoderProcess -and -not $encoderProcess.HasExited) {
        Stop-Process -Id $encoderProcess.Id -ErrorAction SilentlyContinue
    }
    foreach ($key in $savedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], 'Process')
    }
    Pop-Location
}
exit $runResult
