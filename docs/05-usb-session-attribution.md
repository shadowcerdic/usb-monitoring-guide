# 5. USB Session Attribution

## The problem

A Sysmon file-create event says:

```text
host=FIN-WS-01  file.path=E:\finance\report.xlsx  time=10:32:00
```

A Security 6416 connect event says:

```text
host=FIN-WS-01  usb.serial_number=090100000000  time=10:30:00
```

Neither event contains the full pair. The file event has the letter but no serial; the connect event has the serial but no letter. A third event from the collector/EDR supplies the letter. The attribution job joins:

**host + volume letter + file time inside the session interval → serial**

## Session model

A USBSTOR session is:

```text
connect(host, letter, serial) at T1
  ...
disconnect(host, letter, serial) at T2
```

A file event on the same host and letter at `T1 <= t <= T2` belongs to that serial. If several sessions match, the most recent start wins. If a letter is reused without a disconnect, the new connect closes the old interval at the reconnect time and logs a warning.

## Recommended implementation

`scripts/enrich_usb_attribution.py` uses the Splunk REST API to:

1. Export USB connect/disconnect events for the session lookback (default 48 hours).
2. Export `event.dataset=usb.inventory` rows and build a host+serial → volume-letter map. This is the fallback when a connect event has a serial but no letter (the sample collector produces these rows).
3. Export file-create events for the attribution window (default 1,560 minutes = 26 hours, covering the off-hours detection).
4. Build sessions, derive the volume letter from `file.path`, and join by host + letter + time.
5. Write `splunk/lookups/usb_file_attribution.csv` atomically.

The inventory fallback is a snapshot, not proof of the letter at connect time. If drive letters are reassigned, the map can be stale. Prefer an EDR or a real-time collector that emits the letter on the connect event.

The lookup columns:

```csv
host,file_path,file_time,usb_serial,usb_letter,file_name,user
FIN-WS-01,E:\finance\report.xlsx,1792482720,090100000000,E:,report.xlsx,user.f.nouri
```

`file_time` is the epoch second of the file event. The detection searches recompute the same value from `_time`, so the lookup joins exactly.

## Configuration

Environment variables:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SPLUNK_URL` | yes | `https://localhost:8089` | Search head REST endpoint |
| `SPLUNK_TOKEN` | yes | — | REST token; never commit it |
| `SPLUNK_TOKEN_TYPE` | no | `Splunk` | Use `Bearer` for JWT tokens |
| `SPLUNK_INDEX` | no | `usb_monitoring` | Source index |
| `SPLUNK_VERIFY_TLS` | no | `true` | Set `false` only for a test certificate |

Example:

```bash
export SPLUNK_URL="https://splunk.example:8089"
export SPLUNK_TOKEN="<rest-token>"
export SPLUNK_INDEX="usb_monitoring"
python scripts/enrich_usb_attribution.py \
  --file-window-minutes 1560 \
  --session-lookback-hours 48 \
  --out splunk/lookups/usb_file_attribution.csv
```

Run it manually once and inspect:

```bash
head -5 splunk/lookups/usb_file_attribution.csv
wc -l splunk/lookups/usb_file_attribution.csv
```

Rows with `usb_serial` are the only rows written; unmatched files are omitted.

## Schedule and monitoring

- Run every 5–15 minutes on a search head/automation host.
- Use a dedicated service account/token with read access to `usb_monitoring` and write access to the lookup deployment path.
- Alert if the job exits non-zero or if the newest `file_time` in the lookup is older than ~45 minutes.
- Alert if the lookup has zero rows while `event.code=11` is arriving.
- If the job cannot keep up, narrow the file window or use a summary index/KV store; see “Scaling” below.

Example lookup freshness check:

```spl
| inputlookup usb_file_attribution.csv
| stats max(file_time) as newest_file, count
| eval newest_age_min=round((now()-newest_file)/60,1)
```

There is no `now()`-based alert in the lookup itself; schedule this on the search head.

## Lookup definition

`splunk/transforms.conf`:

```ini
[usb_file_attribution]
filename = usb_file_attribution.csv
```

The detection searches use:

```spl
| lookup usb_file_attribution.csv host file_path file_time OUTPUTNEW usb_serial
```

If you deploy the lookup to an app other than the default, qualify the name (`my_app.usb_file_attribution`).

## Scaling and data volume

The default 26-hour file window is intentionally generous because the off-hours detection counts a UTC day. For a large estate:

- Reduce the job to removable-only evidence if you can identify it reliably.
- Use a KV store lookup or a summary index instead of a flat CSV.
- Run the job on a search head with enough CPU/IO; avoid overlapping runs.
- Consider EDR-side enrichment, which eliminates the join entirely.
- Keep the lookup retention aligned with the detections (30 minutes for mass, 26 hours for off-hours).

A flat CSV lookup has practical size limits. If the file grows beyond your search head’s lookup limits, switch to a KV store or index the enriched events instead of using a lookup.

## Failure modes

| Failure | Effect | Mitigation |
|---|---|---|
| No `usb.volume_letter` on connect | No session can match a file | Fix the collector/EDR volume mapping or provide `event.dataset=usb.inventory` rows; stop and validate |
| No disconnect telemetry | Session stays open until reconnect/lookback | Add EDR/Kernel-PnP removal; keep lookback short |
| Letter reused without reconnect | Old session can cover a new file | Reconnect closes the old interval at the new connect |
| Clock skew | File falls outside the session | Use NTP; allow a small grace window only if necessary |
| Lookup job dies | Mass/off-hours rules go silent | Monitor job exit/lag; alert on stale lookup |
| Missing serial on HID | Allowlist cannot suppress | Use device instance path/EDR asset ID |
| Token/permission error | Job exits non-zero | Fix token scope; do not ignore stderr |

## Alternative: EDR fields directly

If your EDR emits `usb.serial_number` and `usb.volume_letter` on file events, you do not need this job. Keep the field names and let the detections read them directly.

## Alternative: Splunk-only approximation

A `transaction`-based search can group connects, file events, and disconnects on a host, but it is expensive, ordering-sensitive, and difficult to bound to a session. It is not the recommended path for production. Use the lookup job or EDR enrichment.

## Validation

After the first run:

```spl
index=usb_monitoring earliest=-30m event.code=11
| `usb_normalize`
| eval file_time=strftime(_time,"%s")
| lookup usb_file_attribution.csv host file_path file_time OUTPUTNEW usb_serial
| stats count as rows, dc(usb_serial) as serials,
        sum(eval(if(isnotnull(usb_serial),1,0))) as joined
```

If `joined` is 0 while USB connects are present, check the volume letter and session lookback first.

Continue with [detections](06-detections.md).
