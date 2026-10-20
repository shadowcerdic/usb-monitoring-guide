# USB Monitoring & DLP Dashboards — Step-by-Step Guide

This repository is an implementation guide for building USB monitoring and data-loss-prevention dashboards in **Splunk**, with an optional Elastic appendix. It does **not** ship a synthetic dataset, an offline detector, or a demo environment. You connect it to telemetry from your own Windows estate.

The guide covers the full chain: Windows audit policy and Sysmon prerequisites, Splunk ingestion and field mapping, USB session attribution, four detection searches, the dashboard, allowlist management, tuning, and validation.

> **Persian summary:** [docs/fa/README.fa.md](docs/fa/README.fa.md)

## What you will build

- A Splunk index `usb_monitoring` fed by Windows Security 6416, Sysmon EID 1/11, and an EDR or a small collector for USB volume letters.
- A scheduled attribution job that joins file-creation events to USBSTOR sessions on **host + volume letter + time**, producing `usb_file_attribution.csv`.
- Four detections:
  - mass sensitive-name copy to removable media (T1052)
  - off-hours source-code copy to removable media (T1052)
  - ransomware-style `.locked` staging on a fixed disk (T1486)
  - HID connect followed by a shell (T1200 / T1059.001)
- A Splunk dashboard for USB activity, attributed file copies, HID connects, and locked files.
- Allowlist, tuning, and validation runbooks.
- An Elastic appendix with KQL/EQL translations.

## Architecture

```text
Windows endpoints
  Security 6416 (Audit PnP Activity)  ─┐
  Sysmon EID 1 / 11                  ─┼─► Splunk Universal Forwarder or HEC
  USBSTOR / disk-volume inventory    ─┤        │
  EDR (serial/volume enrichment)     ─┘        ▼
                                      index=usb_monitoring
                                      sourcetype=usb_monitoring_json
                                                │
                                                ▼
                         scripts/enrich_usb_attribution.py (scheduled)
                                                │
                                                ▼
                         splunk/lookups/usb_file_attribution.csv
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          ▼                                           ▼
                 detections/splunk/*.spl                     USB dashboard
                          │                                           │
                          └────────────► alerts / triage ◄────────────┘
```

## Reality checks that shape the design

1. **Security 6416 has no drive letter.** It gives a device instance path/class, not `E:`. A collector, EDR, or disk-volume inventory must supply the volume letter.
2. **6416 is a connect event, not a disconnect event.** Removal telemetry comes from the EDR or Kernel-PnP/Device Management; IDs vary by Windows build. The attribution job tolerates missing disconnects, but it will over-extend a session until the next connect or the lookback boundary.
3. **6416 does cover HID devices** when Audit PnP Activity is enabled, but HID serial numbers are often absent or non-unique. An allowlist keyed only on `usb.serial_number` may not work; use device instance path or an EDR asset ID where needed.
4. **Sysmon does not log device connects.** It provides file-create (EID 11) and process-create (EID 1) events, which the guide uses.
5. **File-create events do not carry a USB serial.** The serial is attached to the connect event. Attribution is a join on host + volume letter + time.
6. **If your EDR already puts device serial and volume on file events, skip the attribution job** and feed those fields directly.

## Step-by-step path

| Step | Chapter | Outcome |
|---|---|---|
| 1 | [Scope and architecture](docs/01-scope-and-architecture.md) | Agreed data sources, index, timezone, roles |
| 2 | [Telemetry sources](docs/02-telemetry-sources.md) | 6416, Sysmon, USBSTOR inventory, volume mapping |
| 3 | [Splunk ingestion](docs/03-splunk-ingestion.md) | Index, props, UF/HEC, timestamp and field extraction |
| 4 | [Field mapping](docs/04-field-mapping.md) | Normalized fields and the `usb_normalize` macro |
| 5 | [USB session attribution](docs/05-usb-session-attribution.md) | Scheduled lookup covering file↔device joins |
| 6 | [Detections](docs/06-detections.md) | Four SPL detections and triage notes |
| 7 | [Dashboards](docs/07-dashboards.md) | Imported XML, panels, time range |
| 8 | [Allowlist](docs/08-allowlist.md) | HID/storage allowlist and review process |
| 9 | [Tuning and operations](docs/09-tuning-and-operations.md) | Alert-only phase, thresholds, job health |
| 10 | [Validation](docs/10-validation.md) | Real-telemetry test cases and success criteria |

## Quick start

1. Read [scope and architecture](docs/01-scope-and-architecture.md) and decide where each field comes from. If you cannot source `usb.volume_letter`, stop and solve that first.
2. Enable **Audit PnP Activity** and Sysmon EID 1/11 on the endpoints you are authorized to monitor. See [telemetry sources](docs/02-telemetry-sources.md).
3. Create the `usb_monitoring` index and install the configs in [splunk/](splunk/): `props.conf`, `transforms.conf`, `macros.conf`, and `indexes.conf`.
4. Confirm events and fields arrive:
   ```spl
   index=usb_monitoring earliest=-24h
   | stats count by sourcetype, event.code
   ```
5. Configure `scripts/enrich_usb_attribution.py` with a Splunk REST token and run it once manually. It writes `splunk/lookups/usb_file_attribution.csv`.
6. Deploy it every 5–15 minutes and monitor its output/freshness.
7. Save the four searches in [detections/splunk/](detections/splunk/) as scheduled searches in alert-only mode.
8. Import [splunk/USB_Monitoring_Dashboard.xml](splunk/USB_Monitoring_Dashboard.xml) and confirm the panels use your index, lookup, and macro.
9. Build and test the allowlist with the real serials your fleet emits. Never allowlist example serials.
10. Follow [the tuning runbook](docs/09-tuning-and-operations.md) before connecting anything to on-call.

## Repository map

```text
README.md
docs/
  01-scope-and-architecture.md
  02-telemetry-sources.md
  03-splunk-ingestion.md
  04-field-mapping.md
  05-usb-session-attribution.md
  06-detections.md
  07-dashboards.md
  08-allowlist.md
  09-tuning-and-operations.md
  10-validation.md
  fa/README.fa.md
detections/
  splunk/*.spl
  README.md
splunk/
  USB_Monitoring_Dashboard.xml
  indexes.conf
  props.conf
  transforms.conf
  macros.conf
  lookups/usb_allowlist.example.csv
  README.md
scripts/
  collect_usb_telemetry.ps1
  enrich_usb_attribution.py
appendix/
  elastic/README.md
  elastic/*.kql, *.eql
```

## What is not included

- No synthetic events, sample dataset, offline verifier, or demo SIEM.
- No live Splunk cluster was used to validate the searches in this repository. The SPL and XML are structured for Splunk 9.x; validate them in alert-only mode on your search head.
- No vendor-specific EDR parser. The field map shows the normalized names to produce.
- No content inspection or endpoint blocking. This guide is monitoring and detection, not a substitute for a USB device-control policy.

## Safety and privacy

USB file names and paths can contain personal or regulated data. Restrict the `usb_monitoring` index to the analysts who need it, set retention deliberately, and avoid publishing raw telemetry. Run the collection and test cases only on systems and devices you are authorized to monitor.

## License

MIT. See [LICENSE](LICENSE).
