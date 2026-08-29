[CmdletBinding()]
param(
    [string]$ConfigPath = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
)

$ErrorActionPreference = 'Stop'
$sysmonChannel = 'Microsoft-Windows-Sysmon/Operational'
$backupPath = "$ConfigPath.pre-sysmon.bak"

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Wazuh agent configuration not found: $ConfigPath"
}

if (-not (Test-Path -LiteralPath $backupPath)) {
    Copy-Item -LiteralPath $ConfigPath -Destination $backupPath
}

[xml]$document = Get-Content -LiteralPath $ConfigPath -Raw
$existingEntry = @($document.ossec_config.localfile) | Where-Object {
    $_.location -eq $sysmonChannel -and $_.log_format -eq 'eventchannel'
}

if ($existingEntry) {
    Write-Output 'Sysmon event-channel collection is already configured.'
    exit 0
}

$localfile = $document.CreateElement('localfile')
$location = $document.CreateElement('location')
$location.InnerText = $sysmonChannel
$logFormat = $document.CreateElement('log_format')
$logFormat.InnerText = 'eventchannel'

[void]$localfile.AppendChild($location)
[void]$localfile.AppendChild($logFormat)
[void]$document.ossec_config.AppendChild($localfile)
$document.Save($ConfigPath)

Write-Output "Configured Wazuh to collect $sysmonChannel."
Write-Output "Original configuration backup: $backupPath"
