<#
.SYNOPSIS
Offline text/log sanitizer with interactive category selection.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string[]]$Categories,

    [switch]$SaveMap
)

$ErrorActionPreference = 'Stop'

$Patterns = [ordered]@{
    url          = 'https?://[^\s"''<>]+'
    email        = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    windows_user = '\b[A-Za-z0-9_-]+\\[A-Za-z0-9._$-]+\b'
    ipv4         = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    mac          = '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
    ipv6         = '\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b'
    domain       = '\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|co|uk|local|internal|corp|cloud|dev|app|be|tr|eu)\b'
    hostname     = '\b(?:DESKTOP|LAPTOP|SRV|SERVER|DC|WIN|PC|HOST)-[A-Za-z0-9-]+\b'
    guid         = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    hash         = '\b[a-fA-F0-9]{32,64}\b'
}

function Get-FakeValue {
    param([string]$Category, [int]$Index)

    switch ($Category) {
        'url'          { "https://example$Index.com/path" }
        'email'        { "john.smith$Index@example.com" }
        'windows_user' { "DOMAIN\john.smith$Index" }
        'ipv4'         { "10.10.$([math]::Floor($Index / 254)).$(($Index % 254) + 1)" }
        'ipv6'         { "fd00::$Index" }
        'domain'       { "example$Index.com" }
        'hostname'     { 'HOST-{0:0000}' -f $Index }
        'mac'          { '00:11:22:33:44:{0:x2}' -f ($Index % 255) }
        'guid'         { '00000000-0000-0000-0000-{0:000000000000}' -f $Index }
        'hash'         { '{0:x64}' -f $Index }
    }
}

function Get-Findings {
    param([string]$Text)

    $findings = [ordered]@{}
    foreach ($category in $Patterns.Keys) {
        $values = [regex]::Matches($Text, $Patterns[$category], 'IgnoreCase') |
            ForEach-Object { $_.Value } |
            Sort-Object -Unique

        if ($values.Count -gt 0) {
            $findings[$category] = @($values)
        }
    }

    return $findings
}

function Select-Categories {
    param([hashtable]$Findings)

    $selected = New-Object System.Collections.Generic.HashSet[string]
    Write-Host "`nDetected potentially sensitive values:`n"

    foreach ($category in $Findings.Keys) {
        $values = @($Findings[$category])
        $examples = ($values | Select-Object -First 5) -join ', '
        Write-Host "[$category] $($values.Count) unique value(s)"
        Write-Host "  Examples: $examples"

        $answer = Read-Host "Randomize $category? [y/N]"
        if ($answer -match '^(y|yes)$') {
            [void]$selected.Add($category)
        }
        Write-Host ''
    }

    return $selected
}

if (-not $OutputPath) {
    $OutputPath = "$InputPath.sanitized.txt"
}

$text = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8
$findings = Get-Findings -Text $text

if ($findings.Count -eq 0) {
    Write-Host 'No obvious sensitive values detected.'
    exit 0
}

if ($Categories -and $Categories.Count -gt 0) {
    if ($Categories.Count -eq 1 -and $Categories[0].ToLowerInvariant() -eq 'all') {
        $selected = [System.Collections.Generic.HashSet[string]]::new([string[]]$findings.Keys)
    }
    else {
        $selected = [System.Collections.Generic.HashSet[string]]::new([string[]]($Categories | Where-Object { $findings.Contains($_) }))
    }
}
else {
    $selected = Select-Categories -Findings $findings
}

if ($selected.Count -eq 0) {
    Write-Host 'No categories selected. Nothing changed.'
    exit 0
}

$mapping = [ordered]@{}
foreach ($category in $Patterns.Keys) {
    if (-not $selected.Contains($category)) { continue }
    $index = 1
    foreach ($value in @($findings[$category])) {
        if (-not $mapping.Contains($value)) {
            $mapping[$value] = Get-FakeValue -Category $category -Index $index
        }
        $index++
    }
}

foreach ($entry in ($mapping.GetEnumerator() | Sort-Object { $_.Key.Length } -Descending)) {
    $text = $text.Replace($entry.Key, $entry.Value)
}

Set-Content -LiteralPath $OutputPath -Value $text -Encoding UTF8
Write-Host "`nSanitized file written to: $OutputPath"

if ($SaveMap) {
    $mapPath = "$OutputPath.map.json"
    $mapping | ConvertTo-Json | Set-Content -LiteralPath $mapPath -Encoding UTF8
    Write-Host "Replacement map written to: $mapPath"
}
