param([switch]$Test,[switch]$Clean,[string]$QtRoot,[string]$NpcapSdkRoot,[string]$MsvcSetup,[string[]]$Targets)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'source-path.ps1')
$buildRoot = Get-EtherScopeSourceRoot $projectRoot
try {
    if (-not $MsvcSetup) {
        $portable = Join-Path $buildRoot '.tools\msvc\setup_x64.bat'
        if (Test-Path -LiteralPath $portable) { $MsvcSetup = $portable }
        else {
            $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
            if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install MSVC 2022 x64 build tools or pass -MsvcSetup.' }
            $vsRoot = & $vswhere -version '[17.0,18.0)' -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if (-not $vsRoot) { throw 'MSVC 2022 x64 tools are not installed.' }
            $MsvcSetup = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
        }
    }
    $environmentLines = & cmd.exe /d /c ('call "{0}" >nul && set' -f $MsvcSetup)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to initialize MSVC.' }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1],$Matches[2],'Process') }
    }
    if (-not $QtRoot) {
        if (Test-Path -LiteralPath (Join-Path $buildRoot '.tools\Qt\lib\cmake\Qt6')) { $QtRoot = Join-Path $buildRoot '.tools\Qt' }
        elseif ($env:Qt6_DIR) { $QtRoot = (Resolve-Path (Join-Path $env:Qt6_DIR '..\..\..')).Path }
        else { throw 'Pass -QtRoot with the Qt 6.8.3 msvc2022_64 directory.' }
    }
    if (-not $NpcapSdkRoot) { $NpcapSdkRoot = Join-Path $buildRoot '.tools\npcap-sdk' }
    $cmake = Join-Path $buildRoot '.tools\cmake\bin\cmake.exe'
    if (-not (Test-Path -LiteralPath $cmake)) { $cmake = (Get-Command cmake -ErrorAction Stop).Source }
    $buildDir = Join-Path $buildRoot 'build\msvc-release'
    & $cmake -S $buildRoot -B $buildDir -G 'NMake Makefiles' -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$QtRoot" "-DNPCAP_SDK_DIR=$NpcapSdkRoot"
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
    $buildOptions=@('--build',$buildDir)
    if ($Clean) { $buildOptions+='--clean-first' }
    if ($Targets) { $buildOptions+='--target';$buildOptions+=$Targets }
    & $cmake @buildOptions
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    if ($Test) {
        $env:PATH = (Join-Path $QtRoot 'bin') + ';' + $env:PATH
        $env:QT_PLUGIN_PATH = Join-Path $QtRoot 'plugins'
        $env:QT_QPA_FONTDIR = Join-Path $env:WINDIR 'Fonts'
        $evidence = Join-Path $buildRoot 'output\evidence'
        New-Item -ItemType Directory -Path $evidence -Force | Out-Null
        $env:ETHERSCOPE_SCREENSHOTS = Join-Path $evidence 'screenshots'
        $ctest = Join-Path (Split-Path -Parent $cmake) 'ctest.exe'
        & $ctest --test-dir $buildDir --output-on-failure --output-junit (Join-Path $evidence 'ctest.xml')
        if (Test-Path -LiteralPath (Join-Path $buildDir 'ui-tests.xml')) { Copy-Item -LiteralPath (Join-Path $buildDir 'ui-tests.xml') -Destination (Join-Path $evidence 'ui-tests.xml') -Force }
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    }
} catch { throw }
