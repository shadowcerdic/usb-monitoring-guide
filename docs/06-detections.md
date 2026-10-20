# 6. Detections

Four SPL searches implement the monitoring use cases. They are in `detections/splunk/`. The files include comments and schedule/caveat headers; this chapter explains the logic and how to deploy them.

## 6.1 Overview

| Rule | File | Schedule / window | Threshold | MITRE |
|---|---|---|---|---|
| Mass sensitive-name copy | `mass_sensitive_copy.spl` | every 5m / `-2h` | 5 matching file creates per user+serial+host | T1052 |
| Off-hours source copy | `offhours_source_copy.spl` | hourly / `-26h` | 20 source files per user+host per UTC day | T1052 |
| Ransomware staging | `ransom_fixed_disk.spl` | every 1m / `-15m` | 15 `.locked` files per process in 180s | T1486 |
| HID then shell | `hid_then_shell.spl` | every 5m / `-6m` | HID connect plus shell within 60s | T1200 + T1059.001 |

The thresholds are **starting points**. Calibrate them on your own data; see [tuning](09-tuning-and-operations.md).

> Live-validation note: the mass-copy window was widened from `-30m` to `-2h`
> and the ransom window from `-3m` to `-15m`. A tumbling `bin` bucket must fit
> fully inside the search window, otherwise a burst split across the window
> edge is missed.

## 6.2 Dependencies

- Rules 1 and 2 require the `usb_file_attribution` lookup from [USB session attribution](05-usb-session-attribution.md). Without a fresh lookup they produce nothing.
- Rule 4 requires `usb_allowlist.csv` if you use the allowlist lookup. Create it from `splunk/lookups/usb_allowlist.example.csv`.
- All rules require the `usb_normalize` macro and `KV_MODE=json`/equivalent field extraction from [Splunk ingestion](03-splunk-ingestion.md).
- Rule 3 uses fixed-disk path evidence, not the USB lookup, so it still fires when a USB is not involved. That is intentional.

## 6.3 Mass sensitive-name copy

**Question:** did one user copy a cluster of sensitivity-named files to one USB device in a short window?

```spl
index=usb_monitoring sourcetype=usb_monitoring_json event.code=11
| `usb_normalize`
| eval file_time=strftime(_time,"%s")
| lookup usb_file_attribution.csv host file_path file_time OUTPUTNEW usb_serial
| where isnotnull(usb_serial)
| eval name_lower=lower(file_name)
| where match(name_lower, "(customer_db|iban_|payroll|national_id|api_keys|secrets)")
| bin _time span=30m
| stats count as files values(name_lower) as names by _time user usb_serial host
| where files >= 5
| table _time user host usb_serial files names
```

- `bin` uses tumbling 30-minute buckets. A burst split across a bucket boundary can be missed; the Elastic appendix uses a sliding threshold. If you need a sliding window, use `streamstats` with a time-based reset or run the rule more often.
- The count is file-create events, not unique names. Five writes of the same sensitive file count five times.
- Add organization-specific name patterns only after measuring false positives. One pattern at a time.

**Likely false positives:** finance/HR month-end copies, approved backup/sync jobs, DLP remediation, developers copying test data with sensitive-looking names. Triage the user, device allowlist/CMDB, file names, and whether the device is corporate-issued.

## 6.4 Off-hours source copy

**Question:** did one user copy a source-code tree to removable media outside business hours?

```spl
index=usb_monitoring sourcetype=usb_monitoring_json event.code=11
| `usb_normalize`
| eval file_time=strftime(_time,"%s")
| lookup usb_file_attribution.csv host file_path file_time OUTPUTNEW usb_serial
| where isnotnull(usb_serial)
| eval ext=lower(file_ext), hour=strftime(_time,"%H"), day=strftime(_time,"%Y-%m-%d")
| where match(ext, "^(cs|java|py|go|ts)$") AND (hour < "08" OR hour >= "18")
| stats count as files values(file_name) as samples by day user host
| where files >= 20
| table day user host files samples
```

- The hour is in the **Splunk user’s timezone**. Run the search as a UTC user or adjust the `08`/`18` bounds to the organization’s timezone. Iran is UTC+3:30 with no DST.
- The day grouping is the user’s local date; use a UTC user or an explicit timezone conversion if the business day is defined in local time.
- Count is per user+host+day, not a rolling 24-hour window. The `-26h` lookback makes the previous UTC day visible at the boundary.

**Likely false positives:** release/deploy windows, on-call work, source backups, students/developers working late, build pipelines that create source files on removable media (unusual but possible).

## 6.5 Ransomware staging on a fixed disk

**Question:** is a process mass-creating `.locked` files on a fixed disk?

```spl
index=usb_monitoring sourcetype=usb_monitoring_json event.code=11
| `usb_normalize`
| where lower(file_ext)="locked" AND like(lower(file_path), "c:%")
| eval proc_key=coalesce(process_entity_id, process_name, "unknown")
| bin _time span=180s
| stats count as locked_files values(file_path) as sample_paths by _time host proc_key process_name
| where locked_files >= 15
| table _time host process_name proc_key locked_files sample_paths
```

- The rule is intentionally broader than a USB-delivered scenario: ransomware that arrived by email, RDP, or a vulnerability must also fire. The USB link is a triage step, not a condition.
- The `C:` filter is an example. Change it to your fixed-volume letters or remove it after testing.
- `bin` is tumbling. Keep the search interval at one minute so a short burst is not missed.
- Treat a hit as potential ransomware: check whether `.locked` files are still appearing, isolate the host, preserve evidence, and pull the process tree.

**Likely false positives:** encryption/testing tools, backup/archive utilities that write `.locked` files, scripts creating lock files with that extension. Investigate before tuning.

## 6.6 HID then shell

**Question:** did an unknown HID device connect and a shell start within one minute?

```spl
index=usb_monitoring sourcetype=usb_monitoring_json (event.code=6416 OR event.code=1)
| `usb_normalize`
| eval is_hid=if('event.code'=6416 AND usb_class="HID",1,0)
| eval is_shell=if('event.code'=1 AND match(lower(process_name), "^(powershell|cmd)\.exe$"),1,0)
| where is_hid=1 OR is_shell=1
| lookup usb_allowlist.csv serial AS usb_serial OUTPUTNEW model AS allowlisted_model
| where is_hid=0 OR isnull(allowlisted_model)
| transaction host maxspan=60s
| eval has_hid=mvcount(mvfilter(is_hid=1)), has_shell=mvcount(mvfilter(is_shell=1))
| where has_hid>0 AND has_shell>0
| eval serials=mvjoin(usb_serial,","), processes=mvjoin(process_name,",")
| table _time duration eventcount host has_hid has_shell serials processes
```

- `transaction` proves co-occurrence within 60 seconds, not strict order. Check the timestamps before closing the alert. A legitimate keyboard plus an admin PowerShell window can match.
- The allowlist is keyed on `usb_serial`. If the HID has no serial, the lookup cannot suppress it. Use device instance path or an EDR asset ID if your fleet requires it.
- Security 6416 covers HID only when Audit PnP Activity is enabled. Sysmon does not log device connects.
- Do not allowlist a device because it is “new”; require a ticket, owner, and review date.

**Likely false positives:** IT/helpdesk keyboards, KVM switches, USB hubs with HID, accessibility devices, legitimate PowerShell after a keyboard swap. Use the allowlist and verify serial quality.

## 6.7 Deploying the searches

1. Open **Settings → Searches, reports, and alerts → New Alert** (or save each `.spl` query as a scheduled search).
2. Set the time range and cron from the table above.
3. Use **alert-only** first: no email/page/on-call action. Write to a low-noise channel or the Splunk triggered-alerts index.
4. Set `note`/description with the triage steps.
5. Configure suppression/dedup by the group key:
   - mass: `user`, `usb_serial`, `host`
   - offhours: `user`, `host`, `day`
   - ransom: `host`, `proc_key`
   - HID: `host`, `serials`
6. Do not enable all four on day one. Start with the rule whose data source you have validated.
7. Keep the SPL files in git (detection-as-code) and export the Splunk objects for backup.

## 6.8 Limitations

- The guide does not inspect file contents; a renamed sensitive file is not detected.
- Compressed/encrypted archives are not opened.
- A USB copy that never produces a Sysmon EID 11 (missing config, unsupported filesystem) is invisible to rules 1/2.
- 6416 may be absent or incomplete on hosts outside the audit policy.
- A missing volume letter or stale attribution lookup breaks rules 1/2.
- HID serial quality limits rule 4.
- The `.locked` extension is an example. Real ransomware uses many extensions; extend the rule after testing.

Continue with [dashboards](07-dashboards.md).
