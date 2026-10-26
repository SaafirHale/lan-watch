# Read-only dump of the OS IPv4 neighbor (ARP) cache for one interface.
# Sends no packets. Usage: neighbors.ps1 -InterfaceIndex <n>
param([Parameter(Mandatory = $true)][int]$InterfaceIndex)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$rows = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ ip = $_.IPAddress; mac = $_.LinkLayerAddress; state = "$($_.State)" }
})
ConvertTo-Json -InputObject $rows -Depth 3 -Compress
