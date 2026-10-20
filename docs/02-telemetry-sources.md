# 2. Telemetry Sources

You need three kinds of evidence: **device connection**, **file creation**, and **process start**. No single Windows source provides all three with a USB serial attached to the file.

## Source matrix

| Evidence | Source | What it gives | What it does not give |
|---|---|---|---|
| USB device connect | Security 6416 (Audit PNP Activity) | Device instance path, class name, description, subject | Drive letter; disconnect event; reliable HID serial |
| USB device connect/remove | EDR | Device serial, class, often volume/session context | Varies by vendor and policy |
| File create | Sysmon EID 11 | `TargetFilename`, process, user, host | USB serial or volume letter |
| Process start | Sysmon EID 1 | Process name, command line, `ProcessGuid`, user, host | USB context |
| Device inventory | USBSTOR registry | Serial, friendly name, device class | Real-time events; volume letter |
| Volume mapping | Disk/partition/volume inventory or WMI | Serial/disk to drive letter | Change events without a watcher |

## 2.1 Security 6416 — device connection

### Enable

The policy is **Audit PNP Activity**. In auditpol the subcategory is **Plug and Play Events** under **Detailed Tracking**:

```bat
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /get /subcategory:"Plug and Play Events"
```

If the command fails with “parameter is incorrect,” list the localized subcategory names and use the local name:

```bat
auditpol /list /subcategory:*
```

Group Policy path: *Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking → Audit PNP Activity*.

The subcategory has no failure events; success auditing is enough.

### What 6416 contains

Typical fields:

- `DeviceId` — device instance path, e.g. `USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0\090100000000` or `HID\VID_046D&PID_C31C\...`
- `DeviceDescription` / `DeviceName`
- `ClassId`, `ClassName` — e.g. `DiskDrive`, `HIDClass`
- `VendorIds`, `CompatibleIds`
- `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`
- `Computer`, `TimeCreated`

### What 6416 does not contain

- **No drive letter.** `E:` must come from a disk/volume inventory, a collector, or an EDR.
- **No disconnect event.** 6416 is “a new external device was recognized.” Device removal comes from the EDR or the Kernel-PnP/Device Management channel; IDs vary by Windows build.
- **No guaranteed HID serial.** HID keyboards/mice often have no unique serial or a generic instance path. Use device instance path/EDR asset ID if the serial is missing.
- **No file or process detail.** Correlate with Sysmon/EDR events by host and time.

6416 does cover HID devices (for example, “HID Keyboard Device”), contrary to a common assumption that only storage is audited.

### Normalize the action

6416 is a connect event:

```spl
index=usb_monitoring event.code=6416
| eval event_action="usb_device_connect"
| eval usb_class=case(match(ClassName,"(?i)hid"),"HID",
                      match(ClassName,"(?i)disk|usbstor"),"USBSTOR",
                      true(),ClassName)
| eval usb_serial=coalesce('usb.serial_number', mvindex(split(DeviceId,"\\"),-1))
```

The `usb_class` normalization is essential: the HID rule must not treat a storage connect as a keyboard.

## 2.2 Sysmon — file and process evidence

Install Sysmon with at least:

- **EID 11** (FileCreate): `file.path` / `TargetFilename`, process, user, host. This is the core file-copy evidence.
- **EID 1** (ProcessCreate): `process.name`, `process.command_line`, `process.entity_id`/`ProcessGuid`. This supports the HID shell stage and ransomware grouping.

Sysmon does **not** log USB device connects, regardless of the configuration. Do not try to replace 6416 with Sysmon event IDs such as 2003/2006; those are not Sysmon device-connect events.

### FileCreate scope — include-only configs silently drop evidence

Many hardened Sysmon configs (e.g. SwiftOnSecurity) are include-only for FileCreate. If your config does not include the paths you care about, EID 11 simply never fires there — the detections go blind with no error. During live validation, `.csv` files on `E:` were never logged until explicit includes were added. Merge rules like these into your config and review them for production:

```xml
<RuleGroup name="USB lab FileCreate" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">usb_test</TargetFilename>
    <TargetFilename condition="end with">.locked</TargetFilename>
  </FileCreate>
</RuleGroup>
```

Production hosts need their own reviewed include set — do not copy lab includes verbatim.

### File-create fields

| Splunk field (JSON key) | Meaning |
|---|---|
| `file.path` | Full target path, e.g. `E:\finance\report.xlsx` |
| `file.name` | Base name |
| `file.extension` | Extension without the dot |
| `process.name` | Writer process |
| `process.entity_id` | Process GUID used for grouping |
| `user` / `user.name` | Account context |
| `host` / `host.name` | Endpoint |

The drive letter for attribution is derived from `file.path`; it is not a separate Sysmon field.

## 2.3 USBSTOR registry — inventory and serial

`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` lists storage device classes and instance IDs. The instance ID usually contains the serial. Use it to:

- validate that a serial observed on a connect event is a real storage device;
- build a storage-device allowlist/CMDB join;
- confirm the device class.

It is inventory, not an event stream. It does not tell you when a device connected or which drive letter it received.

## 2.4 Volume letter mapping

The USBSTOR serial and the file path live in different event families. To bridge them, map the USB disk/serial to its volume letter:

- PowerShell: `Get-Disk` → `Get-Partition` → `Get-Volume`.
- WMI/CIM: `Win32_DiskDrive` → `Win32_DiskPartition` → `Win32_LogicalDisk`.
- EDR: use the vendor's device/volume fields if available.

Run the mapping when a device connects and store the result on the connect event. Without this step, the attribution job cannot bind a file on `E:` to a serial.

The collector in `scripts/collect_usb_telemetry.ps1` shows the inventory/mapping queries and writes `event.dataset=usb.inventory` rows with `usb.serial_number` + `usb.volume_letter`. The attribution job uses the latest host+serial mapping as a fallback when a connect event lacks a letter. That is a snapshot, not proof of the letter at connect time: if Windows reassigns letters, the mapping can be stale. Prefer a real-time collector or EDR for production, and treat the inventory fallback as a bootstrap/diagnostic path.

The collector is a diagnostic/inventory helper, not a real-time USB event agent. A production collector must watch device/volume changes and emit a normalized connect with the letter, or the EDR must supply it.

## 2.5 EDR alternative

If your EDR already emits **device serial and volume letter on file events**, use them directly and skip the attribution job. Keep the same normalized field names so the SPL/dashboard do not change. Verify the EDR's serial quality for HID and storage before relying on it.

## 2.6 Normalized event schema

Produce JSON events with these fields. The `usb_normalize` Splunk macro aliases dotted JSON keys to simple field names.

```json
{
  "@timestamp": "2026-10-19T10:30:00.000Z",
  "event": {"code": "6416", "action": "usb_device_connect"},
  "host": {"name": "FIN-WS-01"},
  "user": {"name": "user.f.nouri"},
  "usb": {
    "serial_number": "090100000000",
    "volume_letter": "E:",
    "device_class": "USBSTOR",
    "device_id": "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0\\090100000000"
  }
}
```

For a file event:

```json
{
  "@timestamp": "2026-10-19T10:32:00.000Z",
  "event": {"code": "11", "action": "file_created"},
  "host": {"name": "FIN-WS-01"},
  "user": {"name": "user.f.nouri"},
  "file": {"path": "E:\\finance\\report.xlsx", "name": "report.xlsx", "extension": "xlsx"},
  "process": {"name": "explorer.exe", "entity_id": "..."}
}
```

For a process event:

```json
{
  "@timestamp": "2026-10-19T10:33:00.000Z",
  "event": {"code": "1", "action": "process_started"},
  "host": {"name": "FIN-WS-01"},
  "user": {"name": "user.f.nouri"},
  "process": {"name": "powershell.exe", "entity_id": "..."}
}
```

## 2.7 Collection and forwarding

- **Splunk Universal Forwarder**: monitor a JSONL spool directory written by the collector/EDR integration. See [Splunk ingestion](03-splunk-ingestion.md).
- **HEC**: send JSON events directly from the collector/EDR to `/services/collector/event` with `sourcetype=usb_monitoring_json`.
- Keep event time in `@timestamp` (UTC). Do not let Splunk assign ingestion time to late events.
- Redact or restrict the index: file paths and names can contain personal/regulated data.

## 2.8 Removal gap and session accuracy

6416 has no removal event. If you only use 6416:

- a session stays open until a new connect on the same host+letter or the attribution lookback ends;
- a file copied to the same drive letter after an unplug may be attributed to the old device.

Mitigate with:

- EDR removal telemetry;
- a Kernel-PnP/Device Management removal watcher (event IDs vary by build);
- a short session lookback and reconnect handling in `scripts/enrich_usb_attribution.py`;
- treating attribution as evidence for triage, not proof of physical custody.

## 2.9 Validate the sources before building detections

```spl
index=usb_monitoring earliest=-24h
| stats count min(_time) as first max(_time) as last by sourcetype, event.code
```

```spl
index=usb_monitoring earliest=-24h event.code=6416
| stats count by ClassName, DeviceId
| sort - count
```

```spl
index=usb_monitoring earliest=-24h event.code=11
| stats count dc(host) as hosts by file.extension
| sort - count
```

If 6416 is absent, fix the audit policy before continuing. If `usb.volume_letter` is absent, solve the volume mapping; the attribution job cannot invent it.

Continue with [Splunk ingestion](03-splunk-ingestion.md).
