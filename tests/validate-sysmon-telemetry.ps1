[CmdletBinding()]
param(
    [string]$Marker = 'SOC-LAB-LESSON4-VALIDATION',
    [string]$OutputPath = "$env:USERPROFILE\Documents\soc-lab-lesson4-validation.txt",
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$startedAt = Get-Date

if (-not (Get-WinEvent -ListLog $sysmonLog -ErrorAction SilentlyContinue)) {
    throw "Sysmon Operational log is unavailable: $sysmonLog"
}

Set-Content -LiteralPath $OutputPath -Value $Marker -Encoding utf8

$findstr = Join-Path $env:SystemRoot 'System32\findstr.exe'
& $findstr /I "/C:$Marker" $OutputPath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "The marker could not be read from $OutputPath"
}

$deadline = (Get-Date).AddSeconds(15)
$matchingEvents = @()
do {
    Start-Sleep -Seconds 1
    $matchingEvents = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = $sysmonLog
            Id        = 1, 11
            StartTime = $startedAt.AddSeconds(-2)
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match [regex]::Escape($Marker) -or
            $_.Message -match [regex]::Escape($OutputPath)
        }
    )
} until ($matchingEvents.Count -gt 0 -or (Get-Date) -ge $deadline)

Write-Output "Validation marker: $Marker"
Write-Output "Marker file: $OutputPath"

if ($matchingEvents.Count -gt 0) {
    Write-Output 'Local Sysmon validation: PASS'
    $matchingEvents |
        Select-Object TimeCreated, Id, ProviderName |
        Format-Table -AutoSize
} else {
    Write-Warning 'No matching local Sysmon event appeared within 15 seconds.'
}

Write-Output 'Next: search Wazuh Threat Hunting for the marker and confirm agent SOC-WIN11.'

if ($Cleanup) {
    Remove-Item -LiteralPath $OutputPath -Force
    Write-Output 'Marker file removed.'
}
