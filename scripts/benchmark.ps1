param([int]$Seconds=600,[int]$PacketsPerSecond=1000)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$qt=Join-Path $projectRoot '.tools\Qt'
if (Test-Path -LiteralPath $qt) { $env:PATH=(Join-Path $qt 'bin')+';'+$env:PATH; $env:QT_PLUGIN_PATH=Join-Path $qt 'plugins' }
$env:QT_QPA_FONTDIR=Join-Path $env:WINDIR 'Fonts'
$evidence=Join-Path $projectRoot 'output\evidence'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
& (Join-Path $projectRoot 'build\msvc-release\etherscope_benchmark.exe') 1000000 summary | Tee-Object -FilePath (Join-Path $evidence 'core-benchmark.json')
if ($LASTEXITCODE -ne 0) { throw 'Core benchmark failed.' }
$version=[regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'CMakeLists.txt') -Raw),'project\(EtherScope VERSION ([0-9.]+)').Groups[1].Value
& (Join-Path $projectRoot 'build\msvc-release\ui_benchmark.exe') -platform offscreen --seconds $Seconds --pps $PacketsPerSecond --output (Join-Path $evidence "ui-pipeline-${Seconds}s-$version.json")
if ($LASTEXITCODE -ne 0) { throw 'Synthetic UI benchmark failed. Inspect its JSON output.' }
