$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$version = [regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'CMakeLists.txt') -Raw),
    'project\(EtherScope VERSION ([0-9.]+)').Groups[1].Value
if (-not $version) { throw 'Version missing.' }

$paths = @('.github/workflows/ci.yml', '.gitattributes', '.gitignore', 'CMakeLists.txt', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
    'docs/licenses/GPL-3.0.txt', 'docs/licenses/LGPL-3.0.txt', 'samples/README.md',
    'samples/synthetic-protocols.pcap', 'samples/synthetic-ipv6.pcap')
foreach ($folder in @('src', 'tests', 'scripts')) {
    foreach ($item in Get-ChildItem -LiteralPath (Join-Path $projectRoot $folder) -Recurse -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Linked path: $($item.FullName)" }
        if ($item.PSIsContainer) { continue }
        if ($item.Extension -notin @('.cpp', '.h', '.in', '.xpm', '.ps1', '.py', '.iss', '.json')) {
            throw "Unexpected source file: $($item.FullName)"
        }
        $paths += $item.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
    }
}
[Array]::Sort($paths, [StringComparer]::Ordinal)
foreach ($path in $paths) {
    $item = Get-Item -LiteralPath (Join-Path $projectRoot $path)
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Invalid file: $path" }
}

Add-Type -AssemblyName System.IO.Compression
$output = Join-Path $projectRoot 'output'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$archivePath = Join-Path $output "EtherScope-$version-sourcecode.zip"
$temporary = $archivePath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
try {
    $file = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew)
    try {
        $archive = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($path in $paths) {
                $entry = $archive.CreateEntry("EtherScope-$version/$path", [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $inputStream = [IO.File]::OpenRead((Join-Path $projectRoot $path))
                try {
                    $entryStream = $entry.Open()
                    try { $inputStream.CopyTo($entryStream) } finally { $entryStream.Dispose() }
                } finally { $inputStream.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $file.Dispose() }
    Move-Item -LiteralPath $temporary -Destination $archivePath -Force
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
$sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
($sha256 + '  ' + [IO.Path]::GetFileName($archivePath)) |
    Set-Content -LiteralPath ($archivePath + '.sha256') -Encoding ascii
[ordered]@{version=$version;files=$paths.Count;archive=$archivePath;sha256=$sha256;bytes=(Get-Item -LiteralPath $archivePath).Length} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'source-package.json') -Encoding UTF8
Get-Item -LiteralPath $archivePath | Select-Object FullName,Length
