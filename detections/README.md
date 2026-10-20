# Detections

The primary detections are Splunk searches in `splunk/`. The Elastic KQL/EQL files are a secondary appendix.

| Rule | File | Schedule / window | Threshold | MITRE |
|---|---|---|---|---|
| Mass sensitive-name copy | `splunk/mass_sensitive_copy.spl` | 5m / `-2h` | 5 file creates per user+serial+host | T1052 |
| Off-hours source copy | `splunk/offhours_source_copy.spl` | 1h / `-26h` | 20 source files per user+host+UTC day | T1052 |
| Ransomware staging | `splunk/ransom_fixed_disk.spl` | 1m / `-15m` | 15 `.locked` files per process in 180s | T1486 |
| HID then shell | `splunk/hid_then_shell.spl` | 5m / `-6m` | HID connect + shell within 60s | T1200 / T1059.001 |

## Dependencies

- Rules 1 and 2 need the `usb_file_attribution` lookup built by `scripts/enrich_usb_attribution.py`. A stale/missing lookup means no alerts.
- Rule 4 needs `usb_allowlist.csv` if the allowlist lookup is enabled.
- All rules need the `usb_normalize` macro and JSON field extraction in Splunk.
- Rule 3 is intentionally broader and does not require USB attribution.

## Deploy

Read [detections](../docs/06-detections.md) for the logic, false positives, and triage notes. Save each SPL file as a scheduled search in alert-only mode; configure suppression by the documented group keys.

## Elastic appendix

The KQL/EQL files in `../appendix/elastic/` are translations for Kibana. They assume fields that must be added by an EDR or enrichment job and are not covered by the Splunk-first walkthrough. See the appendix README before using them.
