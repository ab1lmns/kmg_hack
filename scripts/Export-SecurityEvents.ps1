# Read-only, bounded Security Event Log export for a dedicated event reader.
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-24)
$ids = 4624,4625,4771,4776
try {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=$start} `
        -MaxEvents 2000 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
    else { throw }
}
$rows = foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        if ($node.Name) { $data[$node.Name] = [string]$node.'#text' }
    }
    [pscustomobject]@{
        id = $event.Id
        time = $event.TimeCreated.ToUniversalTime().ToString('o')
        record_id = $event.RecordId
        data = $data
    }
}
[pscustomobject]@{
    target_host = $env:COMPUTERNAME
    exported_at = (Get-Date).ToUniversalTime().ToString('o')
    truncated = ($events.Count -ge 2000)
    events = @($rows)
} | ConvertTo-Json -Depth 5 -Compress
