# Elastic Appendix (Secondary)

This appendix is for teams that use Elastic/Kibana instead of Splunk. It is not the primary path in this guide and does not include a full enrichment pipeline.

The query files:

- `mass_sensitive_copy.kql` — threshold rule on an enriched index
- `mass_sensitive_copy_approx.eql` — EQL sequence approximation on a raw index
- `offhours_source_copy.kql` — threshold rule on an enriched index
- `ransom_fixed_disk.kql` — threshold rule on a raw index
- `hid_then_shell.eql` — EQL sequence on a raw or normalized index

## Field assumptions

- `mass_sensitive_copy.kql` / `offhours_source_copy.kql` need `usb.serial_number`, `file.drive_type`, `file.name_lower`, `file.extension_lower`, `event.hour_of_day`, and `event.date_utc` from an EDR or an enrichment job. The Splunk attribution job in this repository is Splunk-specific; adapt its host+letter+time join if you need the same fields in Elastic.
- `ransom_fixed_disk.kql` uses `event.type: creation`, `file.extension`, and `file.path`.
- `hid_then_shell.eql` uses `event.code: "6416"`, `event.type: start`, and `usb.device_class: HID`.
- The queries are written for index `usb-monitoring`; remove/replace any index assumption in your Kibana rule.

## Validate before enabling

No Kibana cluster was used to execute these queries in this repository. Create the rules disabled, run them in alert-only mode on your data, and confirm the fields exist. The Splunk chapters remain the reference for telemetry caveats:

- 6416 has no drive letter and no disconnect event.
- 6416 covers HID, but HID serials may be missing.
- Sysmon does not log device connects.
- File events do not carry a USB serial.

See the main [telemetry sources](../../docs/02-telemetry-sources.md), [field mapping](../../docs/04-field-mapping.md), and [allowlist](../../docs/08-allowlist.md) chapters. The process and tuning guidance applies to both platforms.
