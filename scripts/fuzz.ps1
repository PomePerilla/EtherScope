param([ValidateRange(1,1800)][int]$Seconds=120)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'source-path.ps1')
$sourceRoot=Get-EtherScopeSourceRoot $projectRoot
$setup=Join-Path $sourceRoot '.tools/msvc/setup_x64.bat'
$lines=& cmd.exe /d /c ('call "{0}" >nul && set' -f $setup)
if($LASTEXITCODE){throw 'MSVC initialization failed.'}
foreach($line in $lines){if($line -match '^([^=]+)=(.*)$'){[Environment]::SetEnvironmentVariable($Matches[1],$Matches[2],'Process')}}
$cmake=Join-Path $sourceRoot '.tools/cmake/bin/cmake.exe'
$build=Join-Path $sourceRoot 'build/fuzz'
& $cmake -S $sourceRoot -B $build -G 'NMake Makefiles' -DCMAKE_BUILD_TYPE=RelWithDebInfo -DETHERSCOPE_BUILD_GUI=OFF -DETHERSCOPE_BUILD_FUZZERS=ON
if($LASTEXITCODE){throw 'Fuzz configuration failed.'}
& $cmake --build $build --target packet_fuzzer stream_fuzzer application_fuzzer file_fuzzer make_fuzz_corpus
if($LASTEXITCODE){throw 'Fuzz build failed.'}
& (Join-Path $build 'make_fuzz_corpus.exe') (Join-Path $build 'packet-corpus')
& (Join-Path $build 'make_fuzz_corpus.exe') (Join-Path $build 'stream-corpus') --stream
python (Join-Path $sourceRoot 'tests/make_application_corpus.py') (Join-Path $build 'application-corpus')
New-Item -ItemType Directory -Path (Join-Path $build 'file-corpus'),(Join-Path $build 'failures') -Force | Out-Null
Copy-Item -Path (Join-Path $sourceRoot 'samples/*.pcap') -Destination (Join-Path $build 'file-corpus')
python (Join-Path $sourceRoot 'tests/capture_fixtures.py') (Join-Path $build 'file-corpus')
foreach($target in @('packet','stream','application','file')){
    & (Join-Path $build "$($target)_fuzzer.exe") (Join-Path $build "$target-corpus") -max_len=65535 -timeout=5 -rss_limit_mb=512 "-max_total_time=$Seconds" "-artifact_prefix=$build/failures/$target-" *> (Join-Path $build "$target-fuzz.log")
    if($LASTEXITCODE){throw "$target fuzz failed. See $build/$target-fuzz.log"}
    Get-Content (Join-Path $build "$target-fuzz.log") -Tail 1
}
