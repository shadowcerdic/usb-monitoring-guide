# 10. Validation

This repository does not include synthetic data or an offline detector. Validate on **real telemetry** from systems and devices you are authorized to test.

## 10.1 Data-quality checklist

- [ ] 6416 events arrive with `DeviceId`, `ClassName`, and `host`.
- [ ] Sysmon EID 11 arrives with `file.path`, `file.name`, `user`, `host`.
- [ ] Sysmon EID 1 arrives with `process.name`, `process.entity_id`.
- [ ] Connect events carry `usb.serial_number`.
- [ ] Connect events carry `usb.volume_letter` (collector/EDR).
- [ ] `usb.device_class` is normalized to `USBSTOR`/`HID`.
- [ ] `_time` is endpoint time, not ingestion time.
- [ ] The `usb_normalize` macro returns the expected fields.
- [ ] The attribution lookup exists, has rows, and is fresh.
- [ ] The allowlist lookup exists and is readable by the search role.

## 10.2 Controlled test cases

Use a test host and a test USB device with a known serial. Create benign test files; do not run real malware or unauthorized exfiltration.

### Test 1 — attribution

1. Connect the test USB device.
2. Create one file on it.
3. Run the attribution job or wait for its schedule.
4. Verify:

```spl
| inputlookup usb_file_attribution.csv
| search host="<test-host>" usb_serial="<test-serial>"
```

Expected: one row with the correct path and serial. If not, fix volume letters before testing detections.

### Test 2 — mass sensitive-name copy

Create five files with test names matching the rule (for example `customer_db_test1.csv` … `customer_db_test5.csv`) on the USB device within 30 minutes.

Expected: one mass-copy alert for the user+serial+host. A single file should not alert.

### Test 3 — off-hours source copy

At a controlled off-hours time (or temporarily change the bounds for testing), create 20 `.cs`/`.py` test files on the USB device.

Expected: one off-hours alert. 3 files or 15 files should not alert at the default threshold.

### Test 4 — ransomware staging

On a test host, run a benign script that creates 15 files with the `.locked` extension on `C:` from one process within 180 seconds.

Expected: one ransomware-staging alert with the process and host. A single `.locked` file should not alert.

### Test 5 — HID then shell

1. Connect a test HID keyboard that is **not** in the allowlist.
2. Within 60 seconds, start a benign `powershell.exe -NoProfile -Command "Get-Date"`.
3. Confirm the HID rule fires.
4. Add the device to a test allowlist, repeat, and confirm it suppresses.
5. Test a HID device without a shell: it must not alert.

Expected: one alert for the unknown HID+shell pair, no alert for the allowlisted device or the shell alone.

### Test 6 — benign controls

- One sensitive-named file.
- Three source files during business hours.
- One `.locked` file.
- A PowerShell window with no prior HID event.
- A HID device with no shell.

Expected: none of these produce a critical alert.

## 10.3 Dashboard validation

- Panels populate from the test events.
- The attribution panel shows the test file serial.
- The HID panel shows the test device.
- The locked panel shows the test process.
- Time range and timezone match the test timestamps.
- The dashboard does not show an empty “success” when the lookup/job is stale; check the health panel or saved search.

## 10.4 Detection validation

- Run each SPL search manually first; save it as an alert only after it returns the expected shape.
- Confirm the schedule, lookback, threshold, and suppression.
- Confirm the alert payload includes `host`, `user`, `usb_serial`, file samples, and a triage note.
- Test a second, independent event to confirm suppression does not hide a new incident.
- Record the test date, host, device serial, expected result, and actual result.

## 10.5 What “validated” means here

The SPL, XML, and field mapping in this repository are **reference implementations**. No live Splunk cluster was used to execute them in this repository. A successful validation means:

- the fields and lookup exist in your environment;
- the searches return the expected results on your real test events;
- the dashboard renders without missing-field errors;
- the alert-only phase has acceptable noise;
- the operational checks catch a stopped job/forwarder.

## 10.6 Elastic appendix validation

The KQL/EQL files in `appendix/elastic/` are a secondary translation. They assume the fields described in the appendix; validate them separately in Kibana. They are not covered by the Splunk validation above.

## 10.7 Re-validation after changes

Re-run the controlled cases after changing:

- field mapping or collector;
- attribution job or lookup schema;
- index/sourcetype/props;
- SPL thresholds/logic;
- allowlist key;
- dashboard queries.

Keep the test record with the detection-as-code change.
