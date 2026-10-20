# 4. Field Mapping and Normalization

The detections use a small normalized vocabulary. Map your source fields into it before writing SPL.

## 4.1 Field map

| Normalized field | Security 6416 | Sysmon | EDR / collector | Notes |
|---|---|---|---|---|
| `event.code` | `6416` (connect) | `11` (file create), `1` (process start) | vendor-specific | Keep the numeric code; use `event.action` as a human label |
| `event.action` | `usb_device_connect` | `file_created`, `process_started` | normalize | Optional if `event.code` is reliable |
| `host` / `host.name` | `Computer` | `Computer` | hostname | Splunk’s `host` is usually set by the forwarder |
| `user` / `user.name` | `SubjectUserName` | `User` | user | Normalize domain\user if needed |
| `usb.serial_number` | parse `DeviceId` or registry | — | device serial | Not on file events |
| `usb.volume_letter` | **not present** | — | volume/disk inventory | Must come from collector/EDR |
| `usb.device_class` | normalize `ClassName`/`DeviceId` | — | device class | `USBSTOR` or `HID` |
| `usb.device_id` | `DeviceId` | — | device instance path | Useful when HID serial is missing |
| `file.path` | — | `TargetFilename` | file path | Derive letter from the first two characters |
| `file.name` | — | extract from path | file name | Lowercase a copy for case-insensitive matching |
| `file.extension` | — | extract from path | extension | Lowercase a copy |
| `process.name` | — | EID 1 `Image` | process | Lowercase for shell matching |
| `process.entity_id` | — | `ProcessGuid` | process GUID | Grouping key for ransomware staging |
| `process.command_line` | — | EID 1 | command line | Triage only; not a required detection condition |

## 4.2 Security 6416 normalization

6416 gives a device instance path and class, not a drive letter or a disconnect:

```spl
index=usb_monitoring event.code=6416
| eval usb_serial=coalesce('usb.serial_number', mvindex(split(DeviceId,"\\"),-1))
| eval usb_class=case(match(ClassName,"(?i)hid"),"HID",
                      match(ClassName,"(?i)disk|usbstor"),"USBSTOR",
                      true(),ClassName)
| eval event_action="usb_device_connect"
```

- `DeviceId` for storage usually ends with the serial; for HID it may be a generic instance path.
- If the last path segment is not a serial, use `usb.device_id` or an EDR asset ID as the allowlist key.
- 6416 does **not** provide a disconnect. Get removal from EDR or the Kernel-PnP/Device Management channel; event IDs vary by Windows build.

## 4.3 Volume letter

The file path gives the letter on the file event:

```spl
| eval file_letter=upper(substr(file_path,1,2))
```

The connect event must carry the same letter from a collector or EDR. A disk-volume inventory maps a USB disk/serial to its logical drive:

- `Get-Disk` → `Get-Partition` → `Get-Volume`;
- `Win32_DiskDrive` → `Win32_DiskPartition` → `Win32_LogicalDisk`;
- EDR device/volume fields.

If the connect event has a serial but no letter, the attribution job falls back to the latest `event.dataset=usb.inventory` row for that host+serial (written by the sample collector). Treat that as a bootstrap/diagnostic fallback: a stale inventory can map the wrong letter after Windows reassigns drive letters. Prefer a real-time collector/EDR.

Do not guess “removable” from a drive letter. `C:` is normally fixed, but a mounted VHD or a reassigned letter proves that the letter alone is not evidence. The attribution lookup attaches a serial only when an actual USB session matches the time window.

## 4.4 Case, path, and timezone rules

- Windows paths and extensions are case-insensitive. Lowercase a copy for matching:
  ```spl
  | eval file_ext_l=lower(file_ext), file_name_l=lower(file_name), file_path_l=lower(file_path)
  ```
- Keep the original values for investigation and display.
- Store all event times in UTC. Splunk `strftime` uses the search user’s timezone; run hour-based searches as a UTC user or translate the bounds explicitly.
- Normalize `DOMAIN\user` and `user@domain` to one identity before grouping.
- Do not use ingestion time for USB sessions; late events must keep endpoint time.

## 4.5 HID field quality

6416 covers HID devices, but the serial may be:

- empty;
- a generic instance path;
- shared across identical devices.

Before enabling the HID rule:

1. Connect a known keyboard and search:
   ```spl
   index=usb_monitoring event.code=6416 ClassName="*HID*" earliest=-24h
   | table _time host DeviceId ClassName usb.serial_number
   ```
2. Check whether `DeviceId`/serial is stable across reconnects.
3. If it is not stable, use `usb.device_id` or an EDR asset ID for the allowlist and exception list.
4. If you cannot identify devices reliably, keep the HID rule disabled rather than muting every keyboard.

## 4.6 EDR mapping

If you use CrowdStrike, SentinelOne, Elastic Defend, or another EDR, keep the normalized names and map the vendor fields:

- device serial → `usb.serial_number`
- volume/drive → `usb.volume_letter`
- device class → `usb.device_class`
- file path/name → `file.path` / `file.name`
- process GUID → `process.entity_id`

If the EDR already puts the serial on file events, you can skip the attribution job. If it does not, use the job in [USB session attribution](05-usb-session-attribution.md).

## 4.7 Field quality checks

```spl
index=usb_monitoring earliest=-24h
| `usb_normalize`
| stats count as events,
        dc(host) as hosts,
        dc(usb_serial) as serials,
        dc(usb_letter) as letters,
        dc(file_path) as files
```

```spl
index=usb_monitoring earliest=-24h event.code=11
| `usb_normalize`
| stats count by file_ext
| sort - count
```

If `usb_letter` is empty for every connect, stop here: the attribution job will not produce useful rows. Fix the collector/EDR volume mapping first.

Continue with [USB session attribution](05-usb-session-attribution.md).
