# 3. Splunk Ingestion

This chapter installs the index, timestamp parsing, field extraction, lookup, and macros that every detection and dashboard uses.

## 3.1 Create the index

Create an app in Splunk (for example `usb_monitoring`) and add `splunk/indexes.conf` or create the index in Settings → Indexes:

```ini
[usb_monitoring]
homePath = $SPLUNK_DB/usb_monitoring/db
coldPath = $SPLUNK_DB/usb_monitoring/colddb
thawedPath = $SPLUNK_DB/usb_monitoring/thaweddb
```

Use a dedicated index. File paths and names can contain personal or regulated data, and the index should have its own access role and retention.

## 3.2 Install the configuration files

Copy these into `$SPLUNK_HOME/etc/apps/usb_monitoring/local/`:

- `splunk/props.conf` — line handling, timestamp parsing, JSON field extraction.
- `splunk/transforms.conf` — the `usb_file_attribution` lookup definition.
- `splunk/macros.conf` — the `usb_normalize` field-alias macro.
- `splunk/lookups/usb_allowlist.example.csv` — allowlist schema; create a real `usb_allowlist.csv` from it.

Create the lookup directory if it does not exist, then restart Splunk or reload the app.

## 3.3 Timestamp handling

`splunk/props.conf` expects a JSON event with `"@timestamp":"2026-10-19T10:30:00.000Z"` or `+00:00`:

```ini
[usb_monitoring_json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "@timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N
MAX_TIMESTAMP_LOOKAHEAD = 40
TZ = UTC
TRUNCATE = 0
KV_MODE = json
```

- `KV_MODE = json` extracts JSON fields at search time, so searches do not need `spath`.
- The JSON timestamp suffix `Z` or `+00:00` is ignored by the format and `TZ=UTC` makes the interpretation explicit.
- If your source uses a different timestamp key, change `TIME_PREFIX` and the `@timestamp` references in the collector/job.
- If `_time` still shows ingestion time after installing the stanza, your Splunk build may require `%z` in `TIME_FORMAT` or a timestamp normalized to `Z`; fix it before building sessions, because the attribution job depends on endpoint time.
- Verify the extraction before building anything else:

```spl
index=usb_monitoring sourcetype=usb_monitoring_json earliest=-24h
| stats count min(_time) as first max(_time) as last
| eval first=strftime(first,"%Y-%m-%dT%H:%M:%SZ"), last=strftime(last,"%Y-%m-%dT%H:%M:%SZ")
```

`first`/`last` must look like your endpoint event times, not “a few seconds ago.”

## 3.4 Forwarder or HEC

### Universal Forwarder

Put the JSONL spool in a directory the forwarder can read and add `inputs.conf`:

```ini
[monitor://C:\ProgramData\usb-monitoring\*.jsonl]
sourcetype = usb_monitoring_json
index = usb_monitoring
disabled = false
```

The collector writes one JSON object per line. Do not append raw binary or multiline JSON.

### HEC

Create an HEC token with access to `usb_monitoring`, then send JSON events:

```bash
curl https://splunk.example:8088/services/collector/event \
  -H "Authorization: Splunk <HEC_TOKEN>" \
  -d '{"time":1792443460,"host":"HOST1","event":{"@timestamp":"2026-10-19T10:30:00Z","event":{"code":"6416"},"host":{"name":"HOST1"},"usb":{"serial_number":"SERIAL","volume_letter":"E:","device_class":"USBSTOR"}},"sourcetype":"usb_monitoring_json","index":"usb_monitoring"}'
```

HEC ignores `@timestamp` inside the event body. The event time comes from the
envelope `time` field (epoch seconds) and the host from the envelope `host`
field — both are required, otherwise events land with the wrong timestamp or
host (found during live validation).

Keep the token in a credential store; do not commit it. Use a trusted TLS certificate; do not disable verification for production HEC.

## 3.5 Field normalization

Splunk’s JSON extraction keeps dotted keys such as `file.path` and `usb.serial_number`. The `usb_normalize` macro aliases them to the names used by the SPL/dashboard:

```ini
[usb_normalize]
definition = eval host=coalesce(host,'host.name'), user=coalesce(user,'user.name'), file_path=coalesce(file_path,'file.path'), file_name=coalesce(file_name,'file.name'), file_ext=coalesce(file_ext,'file.extension'), usb_serial=replace(coalesce(usb_serial,'usb.serial_number', if(isnotnull('usb.device_id'), mvindex(split('usb.device_id',"\\"),-1), null())), "&[0-9]+$", ""), usb_letter=coalesce(usb_letter,'usb.volume_letter'), usb_class=coalesce(usb_class,'usb.device_class', case(match(ClassName,"(?i)hid"),"HID", match(ClassName,"(?i)disk|usbstor"),"USBSTOR", true(), null)), process_name=coalesce(process_name,'process.name'), process_entity_id=coalesce(process_entity_id,'process.entity_id')
```

Two live-validation notes on this macro:

- **Splunk 10.x quoting:** a dotted field name is null inside `eval`/`if` unless single-quoted (`'usb.device_id'`), while the same name works as a bare search term in the base filter. The macro already quotes every dotted name.
- **`&N` suffix:** a 6416 USBSTOR `DeviceId` tail looks like `…\SERIAL&0` — the instance suffix is stripped by the trailing `replace()` so the serial joins the clean inventory serials.

Use it at the start of searches:

```spl
index=usb_monitoring sourcetype=usb_monitoring_json earliest=-24h
| `usb_normalize`
| stats count by usb_class, event.code
```

If your source already emits simple names (`usb_serial`, `file_path`, etc.), the `coalesce` keeps them.

## 3.6 Attributions and allowlist lookups

- `splunk/transforms.conf` defines `usb_file_attribution` for the generated lookup.
- `splunk/lookups/usb_allowlist.example.csv` shows the HID allowlist schema. Create `usb_allowlist.csv` with real serials.
- The attribution lookup is generated by `scripts/enrich_usb_attribution.py`; see [USB session attribution](05-usb-session-attribution.md).

## 3.7 Roles, retention, and privacy

- Restrict `usb_monitoring` to SOC/IR roles; do not expose file paths to all users.
- Set retention deliberately. Raw USB/file events often need 30–90 days; summary counts can be kept longer.
- Mask or restrict exports: the dashboard is not a data-loss-prevention content scanner.
- Monitor index volume and forwarder health.

## 3.8 Ingest validation checklist

- [ ] `index=usb_monitoring` returns events.
- [ ] `event.code` is present (6416, 11, 1).
- [ ] `host`/`host.name` and `user`/`user.name` are populated.
- [ ] `file.path` exists for EID 11.
- [ ] `usb.serial_number` exists on connect events.
- [ ] `usb.volume_letter` exists on connect events (from collector/EDR).
- [ ] `_time` is endpoint time, not ingestion time.
- [ ] `KV_MODE=json` or an equivalent extraction is working.

Continue with [field mapping](04-field-mapping.md).
