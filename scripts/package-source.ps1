$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$version = [regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'CMakeLists.txt') -Raw),
    'project\(EtherScope VERSION ([0-9.]+)').Groups[1].Value
if (-not $version) { throw 'Version missing.' }

$paths = @('.github/workflows/ci.yml', '.clang-format', '.gitattributes', '.gitignore', 'CMakeLists.txt', 'README.md', 'README.zh-CN.md', 'README.zh-TW.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
    'docs/licenses/GPL-3.0.txt', 'docs/licenses/LGPL-3.0.txt', 'docs/licenses/Inno-Setup.txt', 'docs/licenses/OpenSSL.txt', 'docs/licenses/nghttp2.txt',
    'docs/部署说明.md', 'docs/视觉设计规范.md', 'docs/视觉改版验证.md', 'docs/交互工作区.md', 'docs/交互工作区验证.md', 'docs/分析刷新与安装验收.md', 'docs/检索与排查工作区.md', 'docs/课程要求核对.md', 'samples/README.md',
    'docs/实现说明.md', 'docs/IPv6解析.md', 'docs/性能结果.md', 'docs/验证记录.md',
    'docs/检索与课程验收.md',
    'samples/synthetic-protocols.pcap', 'samples/synthetic-ipv6.pcap')
foreach ($folder in @('src', 'tests', 'scripts')) {
    foreach ($item in Get-ChildItem -LiteralPath (Join-Path $projectRoot $folder) -Recurse -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Linked path: $($item.FullName)" }
        if ($item.PSIsContainer) { continue }
        if ($item.Extension -eq '.pyc' -and $item.Directory.Name -eq '__pycache__') { continue }
        $relativePath = $item.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
        $iconAsset = $relativePath.StartsWith('src/ui/icons/', [StringComparison]::Ordinal) -and
            $item.Extension -in @('.png', '.svg', '.ico')
        if (-not $iconAsset -and $item.Extension -notin @('.cpp', '.h', '.inc', '.in', '.xpm', '.ps1', '.py', '.iss', '.isl', '.json')) {
            throw "Unexpected source file: $($item.FullName)"
        }
        $paths += $relativePath
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
