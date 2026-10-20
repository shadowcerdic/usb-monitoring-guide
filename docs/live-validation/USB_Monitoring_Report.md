# USB Monitoring & DLP — Live Deployment Report (Splunk)
> **Redaction note (public version):** the original report contained the lab host's real hostname, the test USB device's real serial number, and the Windows account name. Those values are redacted above and in the screenshots (black boxes). All test serials/hostnames starting with `TEST` are synthetic and were left as-is.



**Host:** REDACTED-HOST (Windows 10 lab VM) · **Date:** 2026-10-19/20 (Iran, UTC+3:30)
**Stack:** Splunk Enterprise 10.2.3 (single instance) · Universal Forwarder 10.2.3 · Sysmon v15.22 (SwiftOnSecurity v74 + lab additions) · Test device: Lexar USB Flash Drive, serial `REDACTED-SERIAL`, drive `E:`

---

## 1. What was deployed (guide steps 2–8)

| Step | Item | State |
|---|---|---|
| 2 | Index `usb_monitoring` + app `usb_monitoring` (indexes/props/transforms/macros/inputs, lookups `usb_allowlist.csv`, `usb_file_attribution.csv`, dashboard, nav) | ✅ live, btool-verified |
| 3 | Audit PNP Activity (`auditpol`) → Security 6416 | ✅ enabled; 6 events at flash connect |
| 3 | Sysmon EID 1 + EID 11 | ✅ flowing (config: `sysmon/swiftconfig_usblab.xml`) |
| 4 | UF forwarding | ✅ Sysmon→`usb_monitoring`, Security/PowerShell→`main`, spool `C:\ProgramData\usb-monitoring\*.jsonl`→`usb_monitoring_json` |
| 5 | `collect_usb_telemetry.ps1` | ✅ `usb.volume_letter=E:` + `usb.serial_number=REDACTED-SERIAL` verified on real flash |
| 6 | `enrich_usb_attribution.py` via REST Bearer token | ✅ exit 0, 30 rows; scheduled every 10 min (Task Scheduler `USB-EnrichAttribution`) |
| 7 | Allowlist bug fix (step-7 gate) | ✅ `OUTPUTNEW allowlisted_model` → `OUTPUTNEW model AS allowlisted_model` (verified live: allowlisted device suppressed) |
| 8 | 4 detections as alert-only (no on-call action) | ✅ `usb_mass_sensitive_copy`, `usb_offhours_source_copy`, `usb_ransom_fixed_disk`, `usb_hid_then_shell` — `actions=None`, scheduled |

## 2. Chapter-10 validation results

| # | Test | Expected | Actual | Verdict |
|---|---|---|---|---|
| 1 | Attribution | row in `usb_file_attribution.csv` | `E:\usb_test\customer_db_test0b.csv → REDACTED-SERIAL, E:` | PASS |
| 2a | Mass copy negative (1 file) | no alert | 0 rows | PASS |
| 2b | Mass copy 5× `customer_db_test*.csv`/30m | one alert | 1 row: `files=5`, names test1..5 | PASS |
| 3a | Off-hours negative (3 files) | no alert | 0 rows | PASS |
| 3b | Off-hours 20× `.py` at 00:34 | one alert | 1 row: `files=20` | PASS |
| 4a | Ransom negative (1 `.locked`) | no alert | 0 rows | PASS |
| 4b | Ransom 15× `.locked` on C: / one process / 180s | one alert | 1 row: `python.exe` + ProcessGuid, `locked_files=16` | PASS |
| 5a | HID allowlisted + shell | suppressed | 0 rows | PASS |
| 5b | HID unknown + shell | one alert | 1 row: `serials=TESTKBD-UNK-9999` | PASS |
| 5c | HID alone (no shell) | no alert | 0 rows | PASS |
| 6 | Benign controls (1 sensitive / 3 source / 1 `.locked` / shell alone / HID alone) | no alerts | all zero | PASS |

## 3. Bugs found in the guide (all fixed in the local guide copy + deploy files)

1. **Allowlist bug (step-7 gate):** `lookup usb_allowlist.csv … OUTPUTNEW allowlisted_model` — the CSV column is `model`, so allowlisted devices still alerted. Fixed to `OUTPUTNEW model AS allowlisted_model`.
2. **Splunk 10.2.3 field resolution:** dotted fields are **null inside `eval`/`if`** unless single-quoted (`'event.code'="11"`), while the same name works as a bare search term in the base filter. Final rules: bare term in filter + quoted dotted names in eval/if. (A quoted term in the filter returns 0 rows — that was an intermediate mistake during this deployment, caught and corrected the same day.)
3. **`enrich_usb_attribution.py` timestamp parsing:** Splunk 10.x JSON export returns `_time` as `2026-10-19 23:59:47.000 Iran Standard Time` — `to_epoch()` extended to parse it (session count went 0 → 4).
4. **HEC envelope:** `@timestamp` in the body is ignored by HEC — envelope `time` (epoch) and envelope `host` are required. Documented in guide ch.3.
5. **Serial normalization:** 6416 USBSTOR DeviceId tail carries an instance suffix (`…&0`); inventory serials are clean. `&N` now stripped in the `usb_normalize` macro, the collector, and the enrich job — sessions/allowlist/attribution now join.
6. **Sysmon FileCreate scope:** SwiftOnSecurity config is include-only; `.csv` on `E:` was never logged. Lab config adds `contains usb_test` + `end with .locked` includes (production hosts need their own reviewed includes).
7. **Detection windows widened** (mass −30m→−2h, ransom −3m→−15m): tumbling bins must fit fully inside the search window or edge bursts are missed.

## 4. Evidence

Screenshots in `screenshots/`:
1. `1_dashboard.png` — USB Monitoring & DLP dashboard, populated (39,984 events; 6 storage connects; 30 attributed file creates; 7 HID connects; 16 `.locked`; top serials incl. `REDACTED-SERIAL`)
2. `2_savedsearches.png` — Alerts list view (legacy page shows the app-scoped list; the 4 `usb_*` rules live in app `search` and dispatch correctly — verified via REST dispatch: mass=1 row)
3. `3_attribution_lookup.png` — `| inputlookup usb_file_attribution.csv` → 10 rows, files attributed to `REDACTED-SERIAL` on `E:`
4. `4_masscopy_alert_search.png` — the mass-copy SPL over 24h: 1 alert row — `_time 00:30`, `user REDACTED-HOST\User`, `usb_serial REDACTED-SERIAL`, `files=5`, names `customer_db_test1..5`

> The screenshots were taken ~5.5 h after the tests ran. In the meantime Splunk's
> bucket lifecycle hid the collector-JSON events from narrow-window term searches
> (XML Sysmon events keep flowing, 40k+ events). All four rules were re-validated
> via REST after the window fix: mass=1 row, offhours=1 row (files=23 incl. benign
> 31–33), ransom=1 row, HID=2 rows (both unknown-serial hosts; allowlisted host
> suppressed). The mass-copy alert screenshot above was re-taken after that fix
> and shows the alert row over the 24h window.

## 5. Operations

- Saved searches (app `search`): cron `*/5`, `0 *`, `* * * *`, `*/5`; windows −2h / −26h / −15m / −6m; **no actions**
- Enrich job: `scripts/run_enrich.cmd` every 10 min → `usb_file_attribution.csv` (30 rows at last run); log `real_logs/enrich_schedule.log`
- Tokens: REST Bearer `usb-enrich-token` (90 d) at `real_logs/splunk_bearer_token.txt`; HEC `usb-monitoring-hec` (in `splunk_httpinput/local/inputs.conf`)
- Dashboard: `USB_Monitoring_Dashboard` (nav default = legacy `usb_center_v2`)
- Full test record: `usb-monitoring-lab/qa/ch10_live_test_record.md`
