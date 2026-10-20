# Collect and validate USB telemetry on one Windows host.
# This is a diagnostic/inventory helper, NOT a real-time USB event agent.
# It answers: do 6416, USBSTOR, disk/volume mapping, and Sysmon fields exist?
# The event.dataset=usb.inventory rows can supply the volume-letter fallback used by
# scripts/enrich_usb_attribution.py. A real-time collector/EDR is preferred.
# Output contains real hostnames and USB serials. real_logs/ is gitignored.
# Run as Administrator for the Security log and full inventory.
$ErrorActionPreference = 'Continue'
$hostName = $env:COMPUTERNAME
$outDir = Join-Path $PSScriptRoot '..\real_logs'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir ("usb_telemetry_{0}.jsonl" -f $hostName)
$summaryPath = Join-Path $outDir 'usb_telemetry_summary.json'

function Write-Ev($obj) {
    ($obj | ConvertTo-Json -Depth 6 -Compress) | Add-Content -Path $out -Encoding UTF8
}

function Iso-Ms($dateTime) {
    return $dateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Output 'WARNING: not running as Administrator; Security 6416 and some inventory may be unavailable.'
}

$summary = [ordered]@{
    host = $hostName
    collected_utc = (Get-Date).ToUniversalTime().ToString('o')
    admin = $isAdmin
    usbstor_classes = 0
    usb_disks = 0
    volume_mappings = 0
    security_6416_sampled = 0
    sysmon_present = $false
    sysmon_11_sampled = 0
    sysmon_1_sampled = 0
}

# 1. USBSTOR registry inventory: serial + friendly name.
$usbstor = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue)
$summary.usbstor_classes = $usbstor.Count
foreach ($classKey in $usbstor) {
    foreach ($instance in @(Get-ChildItem $classKey.PSPath -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty $instance.PSPath -ErrorAction SilentlyContinue
        Write-Ev ([ordered]@{
            '@timestamp' = Iso-Ms (Get-Date)
            event = @{ dataset = 'registry.usbstor' }
            host = @{ name = $hostName }
            usb = @{
                serial_number = $instance.PSChildName
                device_class = 'USBSTOR'
                vendor = $props.ProviderName
                product = $props.FriendlyName
            }
        })
    }
}

# 2. USB disk -> partition -> logical volume mapping.
$disks = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceType -eq 'USB' -or $_.PNPDeviceID -match 'USBSTOR' })
$summary.usb_disks = $disks.Count
foreach ($disk in $disks) {
    $parts = @(Get-CimAssociatedInstance -InputObject $disk -ResultClassName Win32_DiskPartition -ErrorAction SilentlyContinue)
    foreach ($part in $parts) {
        $volumes = @(Get-CimAssociatedInstance -InputObject $part -ResultClassName Win32_LogicalDisk -ErrorAction SilentlyContinue)
        foreach ($volume in $volumes) {
            $summary.volume_mappings++
            Write-Ev ([ordered]@{
                '@timestamp' = Iso-Ms (Get-Date)
                event = @{ dataset = 'usb.inventory' }
                host = @{ name = $hostName }
                usb = @{
                    serial_number = ([string]$disk.SerialNumber).Trim()
                    device_id = $disk.PNPDeviceID
                    device_class = 'USBSTOR'
                    product = $disk.Model
                    volume_letter = $volume.DeviceID
                }
            })
        }
    }
}

# 3. Security 6416 sample. 6416 is a connect/recognition event, not removal.
$security6416 = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 6416
} -MaxEvents 50 -ErrorAction SilentlyContinue)
$summary.security_6416_sampled = $security6416.Count
if ($security6416.Count -eq 0) {
    Write-Output 'Security 6416: none found. Enable Audit PnP Activity and connect a test device.'
}
foreach ($event in $security6416) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
    $className = [string]$data['ClassName']
    $usbClass = if ($className -match '(?i)hid') { 'HID' }
                elseif ($className -match '(?i)disk|usbstor') { 'USBSTOR' }
                else { $className }
    $deviceId = [string]$data['DeviceId']
    # 6416 USBSTOR DeviceId tails carry an instance suffix ("...&0"); strip it
    # so the serial joins inventory serials (live-validation fix).
    $serial = if ($deviceId) { (($deviceId -split '\\')[-1] -replace '&\d+$','') } else { $null }
    Write-Ev ([ordered]@{
        '@timestamp' = Iso-Ms $event.TimeCreated
        event = @{
            code = '6416'
            action = 'usb_device_connect'
            dataset = 'security.6416'
        }
        host = @{ name = $hostName }
        user = @{ name = $data['SubjectUserName'] }
        usb = @{
            device_id = $deviceId
            device_class = $usbClass
            serial_number = $serial
            product = $data['DeviceDescription']
        }
    })
}

# 4. Sysmon field sample (not device connects).
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
try {
    $null = Get-WinEvent -ListLog $sysmonLog -ErrorAction Stop
    $summary.sysmon_present = $true
    $e11 = @(Get-WinEvent -FilterHashtable @{
        LogName = $sysmonLog; Id = 11; StartTime = (Get-Date).AddHours(-1)
    } -MaxEvents 5 -ErrorAction SilentlyContinue)
    $e1 = @(Get-WinEvent -FilterHashtable @{
        LogName = $sysmonLog; Id = 1; StartTime = (Get-Date).AddHours(-1)
    } -MaxEvents 5 -ErrorAction SilentlyContinue)
    $summary.sysmon_11_sampled = $e11.Count
    $summary.sysmon_1_sampled = $e1.Count
    foreach ($event in $e11) {
        $xml = [xml]$event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
        Write-Ev ([ordered]@{
            '@timestamp' = Iso-Ms $event.TimeCreated
            event = @{ code = '11'; action = 'file_created'; dataset = 'sysmon.11' }
            host = @{ name = $hostName }
            user = @{ name = $data['User'] }
            file = @{ path = $data['TargetFilename'] }
            process = @{ name = $data['Image'] }
        })
    }
    foreach ($event in $e1) {
        $xml = [xml]$event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) { $data[$item.Name] = $item.'#text' }
        Write-Ev ([ordered]@{
            '@timestamp' = Iso-Ms $event.TimeCreated
            event = @{ code = '1'; action = 'process_started'; dataset = 'sysmon.1' }
            host = @{ name = $hostName }
            user = @{ name = $data['User'] }
            process = @{
                name = $data['Image']
                entity_id = $data['ProcessGuid']
                command_line = $data['CommandLine']
            }
        })
    }
}
catch {
    $summary.sysmon_present = $false
    Write-Output 'Sysmon channel is not registered; no Sysmon samples written.'
}

($summary | ConvertTo-Json -Compress) | Set-Content -Path $summaryPath -Encoding UTF8
Write-Output ("Wrote {0}" -f $out)
Write-Output ("Summary: USBSTOR classes={0}, USB disks={1}, volume mappings={2}, 6416={3}, Sysmon={4}" -f `
    $summary.usbstor_classes, $summary.usb_disks, $summary.volume_mappings, `
    $summary.security_6416_sampled, $summary.sysmon_present)
Write-Output 'Do not publish real_logs/; it contains real hostnames and serials.'
