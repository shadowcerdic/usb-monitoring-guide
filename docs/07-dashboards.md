# 7. Dashboards

`splunk/USB_Monitoring_Dashboard.xml` is a simple XML dashboard for investigation and daily monitoring. It is not a detection by itself; the SPL searches in `detections/splunk/` are the detections.

## 7.1 What the dashboard shows

| Panel | Question it answers |
|---|---|
| Events | Is USB telemetry arriving? |
| USB storage connects | Which hosts saw storage devices? |
| Attributed removable file creates | Which file copies were tied to a USB serial? |
| HID connects | Which hosts saw HID devices? |
| Fixed-disk `.locked` files | Is a mass-locking event in progress? |
| Events over time | When did activity spike? |
| Connects by host | Which endpoints are involved? |
| Top USB serials | Which devices are used most, and by whom? |
| Attributed files by user | Who copied files to USB? |
| Locked files by process | Which process is creating `.locked` files? |

The dashboard intentionally does not display raw serials as “good” or “bad”; the allowlist is a separate lookup and process.

## 7.2 Import

1. Confirm the index, macro, lookup, and allowlist are installed (see [Splunk ingestion](03-splunk-ingestion.md)).
2. In Splunk: **Settings → User Interface → Views → Import**, or copy the XML to:
   ```text
   $SPLUNK_HOME/etc/apps/usb_monitoring/local/data/ui/views/USB_Monitoring_Dashboard.xml
   ```
3. Open the dashboard in the `usb_monitoring` app context.
4. If the panels are empty, check the time range, index permissions, and whether the lookup file exists.

The XML uses a relative time range (`-30d@d` to `now`) so it works with live data. Change it to the investigation range you need.

## 7.3 Panel dependencies

- **Attributed removable file creates** requires `usb_file_attribution.csv` and a fresh attribution job.
- **Top USB serials** uses `usb_serial` from the lookup/connect events.
- **Fixed-disk `.locked`** uses Sysmon EID 11 and `file.extension`.
- **HID connects** requires 6416 + normalized `usb_class`; if you do not have HID telemetry, remove the panel rather than showing a misleading zero.
- The dashboard uses the `usb_normalize` macro. If you rename fields, update the macro or the queries.

## 7.4 Time range and timezone

- The default relative range is a starting point, not a compliance retention policy.
- The dashboard displays `_time` in the Splunk user’s timezone. For UTC-only investigations, use a UTC user or add a note to the dashboard.
- The off-hours detection’s hour bounds must match the timezone decision; see [detections](06-detections.md).

## 7.5 Troubleshooting

| Symptom | Check |
|---|---|
| No events | Index/sourcetype, forwarder, token, time range, `_time` extraction |
| Fields missing | `KV_MODE=json`, `props.conf`, field names; run the `usb_normalize` macro |
| Attributed panel empty | Lookup file deployed? Job run? `usb_volume_letter` present? |
| HID panel empty | Audit PnP Activity enabled? 6416 arriving? `usb_class` normalized? |
| Locked panel empty | Sysmon EID 11 configured? `file.extension` extracted? |
| Dashboard works, detections do not | Scheduled search permissions, cron, time range, lookup freshness |

## 7.6 Extending

Good additions, once the base data is reliable:

- A per-user “USB activity” drilldown with serial and allowlist status.
- A panel for sessions whose serial is missing (data-quality signal).
- A panel for attribution lookup age (job health).
- A panel for HID connects by device instance path (when serial is missing).
- A panel for files with sensitive-name patterns, attributed to USB.

Keep panels tied to validated fields; a green chart is not proof that a detection fired.

## 7.7 Elastic appendix

The Elastic KQL/EQL queries in `appendix/elastic/` are translations for teams that use Kibana. The Splunk dashboard is the primary implementation in this guide. If you use Elastic, see [the appendix](../appendix/elastic/README.md) for the field assumptions and missing enrichment pipeline.

Continue with [allowlist](08-allowlist.md).
