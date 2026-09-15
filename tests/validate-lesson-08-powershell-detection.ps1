[CmdletBinding()]
param(
    [ValidateSet('Match', 'NonMatch')]
    [string]$Case = 'Match',
    [ValidateRange(5, 60)]
    [int]$WaitSeconds = 15
)

$ErrorActionPreference = 'Stop'
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$matchingMarker = 'SOC-LAB-LESSON8-T1059-001'
$nonmatchingMarker = 'SOC-LAB-LESSON8-CONTROL-001'
$marker = if ($Case -eq 'Match') { $matchingMarker } else { $nonmatchingMarker }
$powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

if (-not (Test-Path -LiteralPath $powershellPath)) {
    throw "Windows PowerShell was not found at $powershellPath"
}

if (-not (Get-WinEvent -ListLog $sysmonLog -ErrorAction SilentlyContinue)) {
    throw "Sysmon Operational log is unavailable: $sysmonLog"
}

$startedAt = Get-Date
$command = "Write-Output '$marker'"
& $powershellPath -NoProfile -NonInteractive -Command $command | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "The controlled PowerShell command exited with code $LASTEXITCODE"
}

$deadline = (Get-Date).AddSeconds($WaitSeconds)
$matchingEvents = @()

do {
    Start-Sleep -Seconds 1
    $matchingEvents = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = $sysmonLog
            Id        = 1
            StartTime = $startedAt.AddSeconds(-2)
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match [regex]::Escape($marker) -and
            $_.Message -match '(?i)\\powershell\.exe'
        }
    )
} until ($matchingEvents.Count -gt 0 -or (Get-Date) -ge $deadline)

Write-Output "Validation case: $Case"
Write-Output "Marker: $marker"

if ($matchingEvents.Count -eq 0) {
    throw "No matching local Sysmon Event ID 1 appeared within $WaitSeconds seconds."
}

Write-Output 'Local Sysmon validation: PASS'
$matchingEvents |
    Select-Object -First 1 TimeCreated, Id, RecordId, ProviderName |
    Format-List

if ($Case -eq 'Match') {
    Write-Output 'Expected Wazuh result: rule 100100 generates an alert.'
} else {
    Write-Output 'Expected Wazuh result: rule 100100 does not generate an alert.'
}

Write-Output "Search Wazuh Threat Hunting for: $marker"
