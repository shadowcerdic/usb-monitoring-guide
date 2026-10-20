# Splunk Setup

This directory contains the Splunk assets for the guide:

- `indexes.conf` — `usb_monitoring`
- `props.conf` — timestamp and JSON extraction
- `macros.conf` — `usb_normalize` field aliases
- `transforms.conf` — `usb_file_attribution` and `usb_allowlist` lookups
- `USB_Monitoring_Dashboard.xml` — simple XML dashboard
- `lookups/usb_allowlist.example.csv` — allowlist schema

The guide chapters explain the design; this file is the quick installation path.

## 1. Create the app and index

Create a Splunk app named `usb_monitoring` (or use your existing app), then install `indexes.conf` or create the index in **Settings → Indexes**:

```ini
[usb_monitoring]
homePath = $SPLUNK_DB/usb_monitoring/db
coldPath = $SPLUNK_DB/usb_monitoring/colddb
thawedPath = $SPLUNK_DB/usb_monitoring/thaweddb
```

Restrict the index to SOC/IR roles. File paths and names can contain personal/regulated data.

## 2. Install the configs

Copy these into `$SPLUNK_HOME/etc/apps/usb_monitoring/local/`:

```text
props.conf
transforms.conf
macros.conf
```

Create the lookup directory and add the allowlist:

```text
$SPLUNK_HOME/etc/apps/usb_monitoring/lookups/usb_allowlist.csv
```

Use `lookups/usb_allowlist.example.csv` as the schema; replace the example row with real, approved devices. Do not allowlist the example serial.

Restart Splunk or reload the app after changing `props.conf`, `macros.conf`, or `transforms.conf`.

## 3. Send events

Use a Universal Forwarder or HEC with:

- index: `usb_monitoring`
- sourcetype: `usb_monitoring_json`
- JSON object per line/event, with `@timestamp` in UTC

See [Splunk ingestion](../docs/03-splunk-ingestion.md) for the timestamp stanza, UF example, and HEC curl.

## 4. Build the attribution lookup

The dashboard and rules 1/2 need `usb_file_attribution.csv`:

```bash
export SPLUNK_URL="https://splunk.example:8089"
export SPLUNK_TOKEN="<rest-token>"
export SPLUNK_INDEX="usb_monitoring"

python scripts/enrich_usb_attribution.py \
  --file-window-minutes 1560 \
  --session-lookback-hours 48 \
  --out splunk/lookups/usb_file_attribution.csv
```

Copy the generated file to `$SPLUNK_HOME/etc/apps/usb_monitoring/lookups/usb_file_attribution.csv`, or point `--out` directly at that path on the search head/automation host. Schedule it every 5–15 minutes; see [USB session attribution](../docs/05-usb-session-attribution.md).

## 5. Deploy the detections

Open each file in `detections/splunk/` and save it as a scheduled alert:

| File | Cron | Time range |
|---|---|---|
| `mass_sensitive_copy.spl` | `*/5 * * * *` | `-30m` to now |
| `offhours_source_copy.spl` | `0 * * * *` | `-26h` to now |
| `ransom_fixed_disk.spl` | `* * * * *` | `-3m` to now |
| `hid_then_shell.spl` | `*/5 * * * *` | `-6m` to now |

Start in alert-only mode with no on-call action. Configure suppression by the group keys documented in [detections](../docs/06-detections.md).

## 6. Import the dashboard

Copy `USB_Monitoring_Dashboard.xml` to:

```text
$SPLUNK_HOME/etc/apps/usb_monitoring/local/data/ui/views/USB_Monitoring_Dashboard.xml
```

Or import it via **Settings → User Interface → Views**. The dashboard uses a relative time range (`-30d@d` to `now`); adjust it to your investigation window.

## 7. Health checks

- 6416 audit policy enabled on monitored hosts.
- Sysmon EID 1/11 arriving.
- `usb.volume_letter` present on connect events.
- Attribution job exits 0 and the lookup is fresh.
- Allowlist lookup readable by the search role.
- Forwarder/HEC delivery healthy.

A dead attribution job silently disables rules 1/2. Monitor it.

## 8. What was not tested here

No live Splunk cluster was used to execute these searches/dashboard in this repository. Validate the fields and results in alert-only mode on your search head before enabling actions. The SPL/XML target Splunk 9.x; older versions may need syntax adjustments.
