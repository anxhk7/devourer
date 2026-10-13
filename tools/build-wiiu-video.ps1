param([switch]$RebuildEncoder)
# The patched encoder is intentionally separate from the 64-bit MSVC bridge.
$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..') -ErrorAction Stop).Path
$bash = 'C:\Program Files\Git\bin\bash.exe'
$compiler = 'C:\MinGW\bin\g++.exe'
$revision = '7f1eb42e818519efe339aac77260d0b0e884e6dd'
if (-not (Test-Path -LiteralPath $bash) -or -not (Test-Path -LiteralPath $compiler)) {
    throw 'This build uses Git for Windows and the 32-bit MinGW compiler in C:\MinGW\bin.'
}
Push-Location -LiteralPath $repoRoot
$buildResult = 0
try {
    New-Item -ItemType Directory -Path build\wiiu -Force -ErrorAction Stop | Out-Null
    if (-not (Test-Path -LiteralPath build\wiiu\x264\.git)) {
        & git clone https://github.com/opencma/drc-x264.git build/wiiu/x264
        if ($LASTEXITCODE -ne 0) { throw 'Could not fetch the patched x264 source.' }
        & git -C build/wiiu/x264 checkout --detach $revision
        if ($LASTEXITCODE -ne 0) { throw 'Could not select the pinned encoder revision.' }
    }
    $actual = & git -C build/wiiu/x264 rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $actual -ne $revision) { throw 'Encoder checkout is not at the pinned revision.' }
    if (-not (Test-Path -LiteralPath build\wiiu\yasm.exe)) {
        Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/yasm/yasm/releases/download/v1.3.0/yasm-1.3.0-win64.exe' -OutFile build/wiiu/yasm.exe -ErrorAction Stop
    }
    $assemblerHash = (Get-FileHash -LiteralPath build\wiiu\yasm.exe -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($assemblerHash -ne 'D160B1D97266F3F28A71B4420A0AD2CD088A7977C2DD3B25AF155652D8D8D91F') {
        throw 'Unexpected Yasm executable checksum.'
    }
    # The upstream foreach emits one huge command that Windows truncates.
    # Run the same compiler dependency command one source at a time instead.
    $makefile = Join-Path $repoRoot 'build\wiiu\x264\Makefile'
    $makeText = [System.IO.File]::ReadAllText($makefile)
    $oldDepend = '$(foreach SRC, $(addprefix $(SRCPATH)/, $(SRCS) $(SRCCLI) $(SRCSO)), $(CC) $(CFLAGS) $(SRC) $(DEPMT) $(SRC:$(SRCPATH)/%.c=%.o) $(DEPMM) 1>> .depend;)'
    $newDepend = 'for src in $(addprefix $(SRCPATH)/, $(SRCS) $(SRCCLI) $(SRCSO)); do $(CC) $(CFLAGS) "$$src" $(DEPMT) "$${src%.c}.o" $(DEPMM) >> .depend || exit; done'
    if ($makeText.Contains($oldDepend)) {
        [System.IO.File]::WriteAllText($makefile, $makeText.Replace($oldDepend, $newDepend))
    } elseif (-not $makeText.Contains($newDepend)) { throw 'Unknown upstream dependency recipe.' }
    $hasAssembly = (Test-Path -LiteralPath build\wiiu\x264\config.mak) -and
        ([System.IO.File]::ReadAllText((Join-Path $repoRoot 'build\wiiu\x264\config.mak')) -match '(?m)^AS=yasm\r?$')
    if ($RebuildEncoder -or -not $hasAssembly -or -not (Test-Path -LiteralPath build\wiiu\x264\libx264.a)) {
        & $bash --noprofile --norc -c 'export PATH=$PWD/build/wiiu:/c/MinGW/bin:$PATH; cd build/wiiu/x264 && ./configure --disable-cli --disable-opencl --enable-static --enable-win32thread --disable-avs --disable-swscale --disable-lavf --disable-ffms --disable-gpac --host=i686-w64-mingw32 && mingw32-make SHELL=C:/Progra~1/Git/bin/bash.exe clean && mingw32-make SHELL=C:/Progra~1/Git/bin/bash.exe -j4'
        if ($LASTEXITCODE -ne 0) { throw 'Patched x264 build failed.' }
    }
    & $compiler -O2 -std=c++14 -static -I build/wiiu/x264 tools/wiiu-video.cpp build/wiiu/x264/libx264.a -lws2_32 -lgdi32 -luser32 -lwinmm -o build/wiiu/wiiu-video.exe
    if ($LASTEXITCODE -ne 0) { throw 'Video companion build failed.' }
    & build/wiiu/wiiu-video.exe --self-test --seconds 15
    if ($LASTEXITCODE -ne 0) { throw 'Video encoder self-test failed.' }
    & cmake --build build --config Release --target ap_wiiu_video
    if ($LASTEXITCODE -ne 0) { throw 'Video bridge build failed.' }
} catch {
    Write-Error $_
    $buildResult = 1
} finally { Pop-Location }
exit $buildResult
