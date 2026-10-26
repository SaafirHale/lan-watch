# Read-only snapshot of local network configuration. Sends no packets.
# Output: one JSON object on stdout (UTF-8).
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$adapters = @(Get-NetAdapter | ForEach-Object {
    [ordered]@{
        alias       = $_.Name
        index       = [int]$_.ifIndex
        description = $_.InterfaceDescription
        status      = "$($_.Status)"
        mac         = $_.MacAddress
        virtual     = [bool]$_.Virtual
    }
})

$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ index = [int]$_.InterfaceIndex; ip = $_.IPAddress; prefix = [int]$_.PrefixLength }
})

$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{
        index  = [int]$_.InterfaceIndex
        nexthop = $_.NextHop
        metric = [int]$_.RouteMetric + [int]$_.InterfaceMetric
    }
})

$profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ index = [int]$_.InterfaceIndex; name = $_.Name; category = "$($_.NetworkCategory)" }
})

$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ index = [int]$_.InterfaceIndex; servers = @($_.ServerAddresses) }
})

$services = @(Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(csc_|vpnagent|acumbrellaagent|umbrella)' -or $_.DisplayName -match 'Umbrella|AnyConnect|Secure Client' } |
    ForEach-Object { [ordered]@{ name = $_.Name; display = $_.DisplayName; status = "$($_.Status)" } })

[ordered]@{
    adapters  = $adapters
    addresses = $addresses
    routes    = $routes
    profiles  = $profiles
    dns       = $dns
    services  = $services
} | ConvertTo-Json -Depth 5 -Compress
