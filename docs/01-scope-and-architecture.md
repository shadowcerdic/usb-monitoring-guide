# 1. Scope and Architecture

## Purpose

Build a USB monitoring and DLP dashboard in Splunk that answers four operational questions:

1. Who copied a cluster of sensitive-named files to removable media?
2. Who copied source code to removable media outside business hours?
3. Is a process mass-creating `.locked` files on a fixed disk (possible ransomware staging)?
4. Did an unregistered HID device connect and a shell start immediately afterwards?

The guide is for SOC engineers, detection engineers, and Splunk administrators who already have endpoint telemetry and want a working dashboard, not a simulated dataset.

## What this guide produces

- A Splunk index and sourcetype for normalized USB/file/process events.
- A scheduled attribution job that writes `usb_file_attribution.csv`, mapping file-create events to USB serials through a host + volume-letter + time join.
- Four SPL detections in `detections/splunk/`.
- An importable Splunk dashboard, `splunk/USB_Monitoring_Dashboard.xml`.
- An allowlist and tuning process.
- A secondary Elastic appendix with KQL/EQL translations.

## Data flow

```text
Endpoint telemetry                       Splunk
------------------                       ------
Security 6416 (PnP audit) ─┐
Sysmon EID 1 / 11 ─────────┼─► UF / HEC ─► index=usb_monitoring
USBSTOR + volume inventory ─┤              sourcetype=usb_monitoring_json
EDR (optional enrichment) ─┘                       │
                                                   ▼
                                  scripts/enrich_usb_attribution.py
                                                   │
                                                   ▼
                                  splunk/lookups/usb_file_attribution.csv
                                                   │
                        ┌──────────────────────────┴──────────────────┐
                        ▼                                             ▼
               detections/splunk/*.spl                     USB_Monitoring_Dashboard.xml
```

## Design decisions to make before deployment

| Decision | Recommended default | Why |
|---|---|---|
| Index | `usb_monitoring` | Keeps USB telemetry separate for access control and retention |
| Sourcetype | `usb_monitoring_json` | One parser for collector/EDR JSON events |
| Timezone | UTC in ingestion and analysis | Avoids day-boundary errors; Iran is UTC+3:30 with no DST |
| Event timestamp | The endpoint event time, not ingestion time | Late-forwarded events must land in the right window |
| Serial attribution | Scheduled lookup job | File events do not carry a serial |
| File fields | Sysmon EID 11 (`file.path`, `file.name`) | Standard, widely deployed |
| Process fields | Sysmon EID 1 (`process.name`, `process.entity_id`) | Needed for ransomware grouping and HID shell detection |
| USB connect source | Security 6416 + a volume-letter source | 6416 does not contain a drive letter |
| USB removal source | EDR or Kernel-PnP/Device Management | 6416 is connect-only |
| HID source | 6416/EDR, validated for serial quality | HID serials are often missing/non-unique |
| Retention | 90 days raw, 1 year summaries | Balance investigation needs and cost |
| Access | Dedicated index role | File names can contain personal/regulated data |

## Prerequisites

### Windows endpoints

- **Audit PNP Activity** enabled. In auditpol the subcategory is **Plug and Play Events** under **Detailed Tracking**:
  ```bat
  auditpol /set /subcategory:"Plug and Play Events" /success:enable
  ```
  Verify the localized name on your build:
  ```bat
  auditpol /list /subcategory:*
  ```
  Group Policy path: *Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking → Audit PNP Activity*.
- **Sysmon** installed with file-create (EID 11) and process-create (EID 1) enabled. Sysmon does **not** log USB device connects.
- A source for **volume letters**: an EDR that enriches device events, the collector in `scripts/`, or a disk-volume inventory. 6416 gives a device instance path, not `E:`.
- Administrative rights to run the collector and to verify the audit policy.

### Splunk

- A Splunk 9.x search head/indexer environment.
- Permission to create an index and an app.
- A Universal Forwarder or HEC token for endpoint events.
- A REST token for the enrichment job; store it in a credential store, not in the repository.
- A role that can read `usb_monitoring`, run scheduled searches, and write lookups.

### People/process

- An owner for the detections and dashboard.
- An allowlist approver (IT/data owner).
- An alert triage/IR process. The dashboard is not a blocking control.

## Deployment order

1. Telemetry and field mapping.
2. Index, props, and field normalization.
3. Attribution job and lookup.
4. Detections in alert-only mode.
5. Dashboard.
6. Allowlist.
7. Tuning and on-call handoff.
8. Validation and review.

Continue with [telemetry sources](02-telemetry-sources.md).

## Non-goals

- Content inspection or DLP classification of file contents.
- Blocking USB devices or enforcing device-control policy.
- Replacing physical security or endpoint DLP.
- Monitoring devices without authorization. Use the guide only on systems you own or are explicitly authorized to monitor.
