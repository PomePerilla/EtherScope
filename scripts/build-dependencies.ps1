param([string]$MsvcSetup,[string]$Perl)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'source-path.ps1')
$sourceRoot=Get-EtherScopeSourceRoot $projectRoot
if (-not $MsvcSetup) { $MsvcSetup=Join-Path $sourceRoot '.tools/msvc/setup_x64.bat' }
if (Test-Path -LiteralPath $MsvcSetup) {
    $lines=& cmd.exe /d /c ('call "{0}" >nul && set' -f $MsvcSetup)
    if ($LASTEXITCODE) {throw 'MSVC initialization failed.'}
    foreach($line in $lines) {if($line -match '^([^=]+)=(.*)$'){[Environment]::SetEnvironmentVariable($Matches[1],$Matches[2],'Process')}}
}
python (Join-Path $sourceRoot 'scripts/fetch-dependencies.py') --perl
if($LASTEXITCODE){throw 'Dependency download failed.'}
$cache=Join-Path $sourceRoot '.tools/dependencies'
$install=Join-Path $cache 'install'
if(-not $Perl){$Perl=Join-Path $cache 'perl/perl/bin/perl.exe'}
$cmake=Join-Path $sourceRoot '.tools/cmake/bin/cmake.exe'
if(-not(Test-Path -LiteralPath $cmake)){$cmake=(Get-Command cmake -ErrorAction Stop).Source}
if(-not(Test-Path -LiteralPath (Join-Path $install 'lib/libcrypto.lib'))){
    Push-Location (Join-Path $cache 'openssl-3.5.9')
    try {
        & $Perl Configure VC-WIN64A no-shared no-tests no-asm no-module no-engine "--prefix=$install" '--libdir=lib'
        if($LASTEXITCODE){throw 'OpenSSL configuration failed.'}
        & nmake build_libs
        if($LASTEXITCODE){throw 'OpenSSL build failed.'}
        & nmake install_dev
        if($LASTEXITCODE){throw 'OpenSSL installation failed.'}
    } finally {Pop-Location}
}
& $cmake -S (Join-Path $cache 'nghttp2-1.70.0') -B (Join-Path $cache 'nghttp2-build') -G 'NMake Makefiles' -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$install" -DENABLE_LIB_ONLY=ON -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DENABLE_DOC=OFF
if($LASTEXITCODE){throw 'nghttp2 configuration failed.'}
& $cmake --build (Join-Path $cache 'nghttp2-build') --target install
if($LASTEXITCODE){throw 'nghttp2 build failed.'}
Write-Output $install
