#!/usr/bin/env python3
"""Build splunk/lookups/usb_file_attribution.csv from Splunk events.

The join is host + volume letter + time:
  USB connect/disconnect events -> open intervals per host+letter
  file-create events            -> match the active interval
  output lookup                 -> host,file_path,file_time,usb_serial,...

Splunk field names are read with both dotted keys and normalized aliases:
  usb.serial_number / usb_serial
  usb.volume_letter / usb_letter
  usb.device_class / usb_class
  file.path / file_path
  file.name / file_name

This job is intentionally fail-loud: REST errors, malformed responses, and
unwritable lookup paths exit non-zero. A silent empty lookup would disable the
mass-copy and off-hours detections.

Environment:
  SPLUNK_URL            default https://localhost:8089
  SPLUNK_TOKEN          required REST token
  SPLUNK_TOKEN_TYPE     Splunk (default) or Bearer
  SPLUNK_INDEX          default usb_monitoring
  SPLUNK_VERIFY_TLS     true (default) or false

Usage:
  python scripts/enrich_usb_attribution.py \
      --file-window-minutes 1560 \
      --session-lookback-hours 48 \
      --out splunk/lookups/usb_file_attribution.csv
"""
import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

import requests

LETTER_RE = re.compile(r"^([A-Za-z]):[\\/]")
FIELDS = ["host", "file_path", "file_time", "usb_serial", "usb_letter", "file_name", "user"]


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        sys.exit(f"Missing environment variable {name}. Do not put tokens in this file.")
    return value


def pick(row, *names):
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return None


def normalize_letter(value):
    if not value:
        return None
    return str(value).rstrip(":\\").upper() + ":"


def to_epoch(value):
    """Splunk export usually returns _time as epoch; accept ISO too.

    Live validation (Splunk 10.x): the export can render _time as
    "2026-10-19 23:59:47.000 Iran Standard Time". That form is parsed
    here (Iran Standard Time = UTC+3:30, no DST).
    """
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    text = str(value)
    tz_match = re.match(
        r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.+?)\s*$", text)
    if tz_match:
        stamp, tz_name = tz_match.groups()
        tz_offsets = {
            "iran standard time": 3.5 * 3600,
            "utc": 0, "gmt": 0,
        }
        offset = tz_offsets.get(tz_name.strip().lower())
        if offset is not None:
            try:
                naive = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                naive = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
            return naive.replace(tzinfo=timezone.utc).timestamp() - offset
    try:
        text_iso = text.replace("Z", "+00:00")
        return datetime.fromisoformat(text_iso).timestamp()
    except ValueError:
        return None


def splunk_export(base, token_type, token, search, earliest, latest,
                  verify_tls, timeout):
    url = f"{base.rstrip('/')}/services/search/jobs/export"
    headers = {"Authorization": f"{token_type} {token}"}
    data = {
        "search": f"search {search}",
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": "json",
    }
    response = requests.post(url, headers=headers, data=data,
                             verify=verify_tls, stream=True, timeout=(15, timeout))
    response.raise_for_status()
    for line in response.iter_lines(decode_unicode=True):
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = payload.get("result")
        if isinstance(result, dict):
            yield result


def build_sessions(rows, warnings, letter_map):
    """Return USBSTOR intervals keyed by host+letter, tolerant of reconnects."""
    events = []
    for row in rows:
        ts = to_epoch(row.get("_time"))
        host = pick(row, "host", "host.name")
        if ts is None or not host:
            continue
        klass = pick(row, "usb.device_class", "usb_class")
        if klass and str(klass).upper() != "USBSTOR":
            continue
        action = pick(row, "event.action")
        code = str(pick(row, "event.code") or "")
        if action == "usb_device_disconnect":
            kind = "disconnect"
        elif action == "usb_device_connect" or code == "6416":
            kind = "connect"
        else:
            continue
        letter = normalize_letter(pick(row, "usb.volume_letter", "usb_letter"))
        serial = pick(row, "usb.serial_number", "usb_serial")
        # 6416 USBSTOR DeviceId tails carry an instance suffix ("...&0");
        # strip it so sessions join inventory serials (live-validation fix).
        if serial:
            serial = re.sub(r"&\d+$", "", str(serial))
        if serial and not letter:
            letter = letter_map.get((host, str(serial)))
        if kind == "connect" and (not letter or not serial):
            continue
        events.append((ts, host, kind, letter, serial))

    open_by_key = {}
    closed = []
    for ts, host, kind, letter, serial in sorted(events, key=lambda e: e[0]):
        key = (host, letter)
        if kind == "connect":
            current = open_by_key.get(key)
            if current:
                warnings.append(f"reconnect {host} {letter}: closing {current['serial']} at {ts}")
                current["end"] = ts
                closed.append(current)
            open_by_key[key] = {
                "host": host, "letter": letter, "serial": serial,
                "start": ts, "end": None,
            }
        else:
            current = open_by_key.get(key)
            if current and (not serial or serial == current["serial"]):
                current["end"] = ts
                closed.append(current)
                del open_by_key[key]
            elif current:
                warnings.append(f"disconnect mismatch {host} {letter}: "
                                f"session={current['serial']} event={serial}")
    closed.extend(open_by_key.values())
    return closed


def build_letter_map(rows):
    """Latest inventory mapping per host+serial from event.dataset=usb.inventory."""
    mapping = {}
    seen_at = {}
    for row in rows:
        host = pick(row, "host", "host.name")
        serial = pick(row, "usb.serial_number", "usb_serial")
        letter = normalize_letter(pick(row, "usb.volume_letter", "usb_letter"))
        if not (host and serial and letter):
            continue
        key = (host, str(serial))
        timestamp = to_epoch(row.get("_time")) or 0
        if key not in seen_at or timestamp >= seen_at[key]:
            mapping[key] = letter
            seen_at[key] = timestamp
    return mapping


def join_files(file_rows, sessions, warnings):
    by_host_letter = defaultdict(list)
    for session in sessions:
        by_host_letter[(session["host"], session["letter"])].append(session)
    for value in by_host_letter.values():
        value.sort(key=lambda s: s["start"])

    output = {}
    for row in file_rows:
        ts = to_epoch(row.get("_time"))
        host = pick(row, "host", "host.name")
        path = pick(row, "file.path", "file_path")
        if ts is None or not host or not path:
            continue
        match = LETTER_RE.match(str(path))
        if not match:
            continue
        letter = normalize_letter(match.group(1))
        candidates = [
            session for session in by_host_letter.get((host, letter), [])
            if session["start"] <= ts and (session["end"] is None or ts <= session["end"])
        ]
        if not candidates:
            continue
        session = max(candidates, key=lambda s: s["start"])
        key = (host, str(path), int(ts))
        output[key] = {
            "host": host,
            "file_path": path,
            "file_time": int(ts),
            "usb_serial": session["serial"],
            "usb_letter": letter,
            "file_name": pick(row, "file.name", "file_name") or "",
            "user": pick(row, "user", "user.name") or "",
        }
    return [output[key] for key in sorted(output, key=lambda k: (k[2], k[0], k[1]))]


def write_lookup(path, rows):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temporary = f"{path}.tmp.{os.getpid()}"
    with open(temporary, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--file-window-minutes", type=int, default=1560,
                        help="File-create lookback; 1560 = 26h for the off-hours rule.")
    parser.add_argument("--session-lookback-hours", type=int, default=48,
                        help="USB connect/disconnect lookback for session building.")
    parser.add_argument("--out", default="splunk/lookups/usb_file_attribution.csv",
                        help="Output lookup CSV.")
    parser.add_argument("--insecure", action="store_true",
                        help="Do not verify the Splunk TLS certificate.")
    parser.add_argument("--timeout", type=int, default=300,
                        help="HTTP read timeout in seconds.")
    args = parser.parse_args()

    base = os.environ.get("SPLUNK_URL", "https://localhost:8089")
    token = env("SPLUNK_TOKEN")
    token_type = os.environ.get("SPLUNK_TOKEN_TYPE", "Splunk")
    if token_type not in ("Splunk", "Bearer"):
        sys.exit("SPLUNK_TOKEN_TYPE must be Splunk or Bearer")
    index = os.environ.get("SPLUNK_INDEX", "usb_monitoring")
    verify_tls = not (args.insecure or
                      os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() == "false")

    session_query = (
        f"index={index} (event.code=6416 OR event.action=usb_device_connect "
        f"OR event.action=usb_device_disconnect) "
        f"| fields _time host event.action event.code "
        f"usb.serial_number usb.volume_letter usb.device_class usb_serial usb_letter usb_class"
    )
    file_query = (
        f"index={index} (event.code=11 OR event.action=file_created) "
        f"| fields _time host user file.path file.name file.extension "
        f"file_path file_name file_ext"
    )
    inventory_query = (
        f"index={index} event.dataset=usb.inventory "
        f"| fields _time host usb.serial_number usb.volume_letter usb_serial usb_letter"
    )

    warnings = []
    try:
        session_rows = list(splunk_export(
            base, token_type, token, session_query,
            f"-{args.session_lookback_hours}h", "now", verify_tls, args.timeout))
        inventory_rows = list(splunk_export(
            base, token_type, token, inventory_query,
            f"-{args.session_lookback_hours}h", "now", verify_tls, args.timeout))
        file_rows = list(splunk_export(
            base, token_type, token, file_query,
            f"-{args.file_window_minutes}m", "now", verify_tls, args.timeout))
    except requests.RequestException as exc:
        sys.exit(f"Splunk export failed: {exc}")

    letter_map = build_letter_map(inventory_rows)
    sessions = build_sessions(session_rows, warnings, letter_map)
    rows = join_files(file_rows, sessions, warnings)
    write_lookup(args.out, rows)

    for warning in warnings[:10]:
        print(f"WARNING: {warning}", file=sys.stderr)
    if len(warnings) > 10:
        print(f"WARNING: {len(warnings) - 10} more session warnings", file=sys.stderr)
    print(f"sessions={len(sessions)} inventory_mappings={len(letter_map)} "
          f"file_events={len(file_rows)} joined={len(rows)} -> {args.out}")
    if not rows:
        print("WARNING: no file event matched a USB session; "
              "check usb.volume_letter, event times, and the session lookback.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
