# 构建脚本: 定位 MSVC (cl.exe) + nvcc, 编译 pgp_gpu_miner.exe
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1
# 说明: cl.exe 通过 INCLUDE/LIB 环境变量找头文件和库(vcvars 的最小等价物);
#       cudart 静态链接,产物不依赖 CUDA 运行时 DLL
$ErrorActionPreference = 'Stop'

# ---- 定位 cl.exe ----
$roots = @("${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools", "$env:ProgramFiles\Microsoft Visual Studio\2022") |
  Where-Object { Test-Path $_ }
if (-not $roots) { Write-Error "未找到 Visual Studio/BuildTools 2022"; exit 1 }
$cl = $null
foreach ($root in $roots) {
  $cand = Get-ChildItem -Path $root -Recurse -Filter cl.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
  if ($cand) { $cl = $cand.FullName; break }
}
if (-not $cl) { Write-Error "未找到 cl.exe (需要 MSVC v143 x64 组件)"; exit 1 }
$binDir = Split-Path $cl                          # ...\VC\Tools\MSVC\<ver>\bin\Hostx64\x64
$msvcVer = Split-Path (Split-Path $binDir)        # ...\VC\Tools\MSVC\<ver>
Write-Host "cl.exe : $cl"

# ---- 定位 Windows SDK ----
$sdkRoot = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\Include" -Directory -ErrorAction SilentlyContinue |
  Sort-Object Name -Descending | Select-Object -First 1
if ($sdkRoot) { Write-Host "WinSDK : $($sdkRoot.FullName)" } else { Write-Error "未找到 Windows SDK"; exit 1 }

# ---- 定位 nvcc ----
# 优先级: $env:CUDA_ROOT > 系统安装目录 > PATH
$nvcc = $null
if ($env:CUDA_ROOT -and (Test-Path (Join-Path $env:CUDA_ROOT 'bin\nvcc.exe'))) {
  $nvcc = Join-Path $env:CUDA_ROOT 'bin\nvcc.exe'
} else {
  $cudaRoots = Get-ChildItem "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA" -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending
  foreach ($r in $cudaRoots) {
    $p = Join-Path $r.FullName 'bin\nvcc.exe'
    if (Test-Path $p) { $nvcc = $p; break }
  }
  if (-not $nvcc) {
    $cmd = Get-Command nvcc -ErrorAction SilentlyContinue
    if ($cmd) { $nvcc = $cmd.Source }
  }
}
if (-not $nvcc) { Write-Error "未找到 nvcc (设置 CUDA_ROOT 或安装 CUDA Toolkit)"; exit 1 }
Write-Host "nvcc   : $nvcc"

# ---- 环境(cl 最小环境) ----
$env:PATH = "$binDir;$env:PATH"
$env:INCLUDE = "$msvcVer\include;$($sdkRoot.FullName)\ucrt;$($sdkRoot.FullName)\um\shared;$($sdkRoot.FullName)\um\um;$($sdkRoot.FullName)\um\winrt"
$env:LIB = "$msvcVer\lib\x64;$($sdkRoot.FullName)\ucrt\x64;$($sdkRoot.FullName)\um\x64"
# rc.exe / mt.exe 需要 SDK bin
$sdkBin = Get-ChildItem (Join-Path (Split-Path $sdkRoot.FullName) 'bin') -Directory -ErrorAction SilentlyContinue |
  Sort-Object Name -Descending | Select-Object -First 1
if ($sdkBin -and (Test-Path (Join-Path $sdkBin.FullName 'x64\rc.exe'))) {
  $env:PATH += ";$(Join-Path $sdkBin.FullName 'x64')"
}

# ---- 编译 ----
Push-Location $PSScriptRoot
try {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  & $nvcc -O3 -arch=sm_75 -cudart static -o pgp_gpu_miner.exe miner.cu -lbcrypt
  if ($LASTEXITCODE -ne 0) { Write-Error "nvcc 编译失败 (exit $LASTEXITCODE)"; exit $LASTEXITCODE }
  $sw.Stop()
  Write-Host ("OK: pgp_gpu_miner.exe  ({0:n1}s)" -f $sw.Elapsed.TotalSeconds)
} finally { Pop-Location }
