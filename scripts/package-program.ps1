param([string]$QtRoot,[string]$MsvcRuntimeRoot,[string]$InnoCompiler)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'source-path.ps1')
$sourceRoot=Get-EtherScopeSourceRoot $projectRoot
if ($QtRoot -and $QtRoot.StartsWith($projectRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {$QtRoot=$sourceRoot+$QtRoot.Substring($projectRoot.Length)}
$projectRoot=$sourceRoot
if (-not $QtRoot) {$QtRoot=Join-Path $projectRoot '.tools\Qt'}
$version=[regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'CMakeLists.txt') -Raw),'project\(EtherScope VERSION ([0-9.]+)').Groups[1].Value
if (-not $version) {throw 'Version missing.'}
$exe=Join-Path $projectRoot 'build\msvc-release\EtherScope.exe'
$deploy=Join-Path $QtRoot 'bin\windeployqt.exe'
foreach ($path in @($exe,$deploy)) {if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw "Missing: $path"}}
if (-not $MsvcRuntimeRoot) {
    $redist=Join-Path $projectRoot '.tools\msvc\VC\Redist\MSVC'
    $MsvcRuntimeRoot=Get-ChildItem -LiteralPath $redist -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | ForEach-Object {Join-Path $_.FullName 'x64\Microsoft.VC143.CRT'} |
        Where-Object {Test-Path -LiteralPath $_} | Select-Object -First 1
}
if (-not $MsvcRuntimeRoot -and $env:VCToolsRedistDir) {$MsvcRuntimeRoot=Join-Path $env:VCToolsRedistDir 'x64\Microsoft.VC143.CRT'}
if (-not $MsvcRuntimeRoot) {throw 'MSVC runtime missing.'}
$stage=Join-Path $projectRoot ('.tools\program-release\'+[guid]::NewGuid().ToString('N'))
$package=Join-Path $stage "EtherScope-$version"
$app=Join-Path $package 'app'
New-Item -ItemType Directory -Path $app -Force | Out-Null
Copy-Item -LiteralPath $exe -Destination $app
$previousPath=$env:PATH
try {
    $env:PATH=(Join-Path $QtRoot 'bin')+';'+$previousPath
    & $deploy --release --no-plugins --skip-plugin-types generic --no-translations --no-compiler-runtime --no-opengl-sw --no-system-dxc-compiler --dir $app (Join-Path $app 'EtherScope.exe')
    if ($LASTEXITCODE -ne 0) {throw 'Qt deployment failed.'}
} finally {$env:PATH=$previousPath}
$platforms=Join-Path $app 'platforms'
New-Item -ItemType Directory -Path $platforms | Out-Null
Copy-Item -LiteralPath (Join-Path $QtRoot 'plugins\platforms\qwindows.dll') -Destination $platforms
foreach ($name in @('msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll','vcruntime140.dll','vcruntime140_1.dll')) {
    Copy-Item -LiteralPath (Join-Path $MsvcRuntimeRoot $name) -Destination $app
}
@'
[Paths]
Prefix=.
Plugins=.
'@ | Set-Content -LiteralPath (Join-Path $app 'qt.conf') -Encoding ascii
$licenses=Join-Path $app 'licenses'
New-Item -ItemType Directory -Path $licenses | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination (Join-Path $licenses 'EtherScope-MIT.txt')
foreach ($name in @('GPL-3.0.txt','LGPL-3.0.txt','Inno-Setup.txt')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ('docs\licenses\'+$name)) -Destination $licenses
}
Copy-Item -LiteralPath (Join-Path $QtRoot 'sbom\qtbase-6.8.3.spdx.json') -Destination (Join-Path $licenses 'Qt-6.8.3.spdx.json')
$output=Join-Path $projectRoot 'output'
$release=Join-Path $output "EtherScope-$version"
New-Item -ItemType Directory -Path $release -Force | Out-Null
if (-not $InnoCompiler) {$InnoCompiler=Join-Path $projectRoot '.tools\InnoSetup\tools\ISCC.exe'}
if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {throw 'Pass -InnoCompiler with ISCC.exe.'}
& $InnoCompiler ("/DAppVersion="+$version) ("/DPayloadDirectory="+$app) ("/DReleaseDirectory="+$release) (Join-Path $PSScriptRoot 'installer.iss')
if ($LASTEXITCODE -ne 0) {throw 'Installer build failed.'}
$installer=Join-Path $release "EtherScope-Setup-$version-x64.exe"
if ((Get-Item -LiteralPath $installer).Length -gt 20MB) {throw 'Installer exceeds 20 MiB.'}
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'npcap-download.json') -Raw | ConvertFrom-Json
$bundle=Join-Path $stage "release\EtherScope-$version"
New-Item -ItemType Directory -Path $bundle -Force | Out-Null
Copy-Item -LiteralPath $installer -Destination $bundle
$archive=Join-Path $output "EtherScope-$version-windows-x64.zip"
Compress-Archive -LiteralPath $bundle -DestinationPath $archive -Force
[ordered]@{directory=$bundle;payload=$app;archive=$archive;installer=$installer;version=$version;driver_download_url=$manifest.url} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'program-package.json') -Encoding UTF8
Get-Item -LiteralPath $archive,$installer | Select-Object FullName,Length
