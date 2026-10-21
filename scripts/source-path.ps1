function Get-EtherScopeSourceRoot([string]$ProjectRoot) {
    # MSVC resource object paths must leave room below the Windows path limit.
    if ($ProjectRoot -notmatch '[^\x00-\x7F]' -and $ProjectRoot.Length -le 96) { return $ProjectRoot }

    # Preserve existing build caches created through the original junction.
    $legacy = Join-Path $env:TEMP 'EtherScope-20261012-source'
    if (Test-Path -LiteralPath $legacy) {
        $item = Get-Item -LiteralPath $legacy
        if ($item.LinkType -eq 'Junction' -and $item.Target -eq $ProjectRoot) { return $legacy }
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ProjectRoot.ToLowerInvariant()))
        $key = ([BitConverter]::ToString($digest)).Replace('-', '').Substring(0, 16)
    } finally { $sha.Dispose() }
    $junction = Join-Path $env:TEMP ('EtherScope-source-' + $key)
    if (Test-Path -LiteralPath $junction) {
        $item = Get-Item -LiteralPath $junction
        if ($item.LinkType -ne 'Junction' -or $item.Target -ne $ProjectRoot) {
            throw 'The temporary build junction belongs to another directory.'
        }
    } else { New-Item -ItemType Junction -Path $junction -Target $ProjectRoot | Out-Null }
    return $junction
}
