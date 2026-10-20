# 8. Allowlist Management

The HID rule needs an allowlist for known keyboards/devices; otherwise every docking station, KVM, or helpdesk swap looks suspicious. The allowlist is an **inventory of known devices**, not a list of “bad” serials.

## 8.1 What belongs in the allowlist

- HID devices that are expected on monitored hosts (keyboards, barcode scanners, accessibility devices).
- Storage devices that are explicitly approved for the users/hosts in scope.
- A record per device:

| Field | Example | Notes |
|---|---|---|
| `serial` | `EXAMPLE-SERIAL-0001` | Primary key; never use an example/placeholder in production |
| `model` | `Example Keyboard` | Human-readable |
| `owner` / `team` | `IT-Dept` | Accountability |
| `added_by` | `analyst` | Audit trail |
| `added_date` | `2026-10-19` | — |
| `review_date` | `2027-01-19` | Default 90 days |

## 8.2 What must never be allowlisted

- `EXAMPLE-SERIAL-*` or any placeholder from this repository.
- VID/PID alone. Many devices share the same VID/PID.
- A device simply because it is new or because an alert was noisy.
- A device with an unknown owner or no review date.

## 8.3 HID serial quality

6416 covers HID, but the serial may be:

- missing;
- a generic instance path;
- shared by identical devices.

If the serial is not stable, use `usb.device_id` (device instance path) or an EDR asset ID as the allowlist key. The HID `transaction` search uses `usb_serial`; adapt the lookup/exception to the key you can actually trust.

Test the key on a real device before relying on it:

```spl
index=usb_monitoring event.code=6416 ClassName="*HID*" earliest=-24h
| table _time host DeviceId ClassName usb_serial
```

Connect/disconnect the same device a few times and compare the values.

## 8.4 Splunk lookup

Schema:

```csv
serial,model,owner,added_by,added_date,review_date
EXAMPLE-SERIAL-0001,Example Keyboard,IT-Dept,analyst,2026-10-19,2027-01-19
```

Deploy as `splunk/lookups/usb_allowlist.csv` (create it from the example). The HID search:

```spl
| lookup usb_allowlist.csv serial AS usb_serial OUTPUTNEW model AS allowlisted_model
| where is_hid=0 OR isnull(allowlisted_model)
```

If you key on device instance path instead, change the lookup field and the `AS` alias.

## 8.5 Process

1. **Request:** ticket with serial/device ID, model, owner, host(s), and reason.
2. **Approve:** data owner or IT manager, not the requester.
3. **Record:** add the row with a review date (default 90 days).
4. **Review:** quarterly, extend or remove each row. An allowlist that is never cleaned becomes “allow everything.”
5. **Test:** after each change, run the rule with an allowlisted device (should suppress) and an unknown device (should alert).
6. **Audit:** keep the lookup in git or export it; changes should be reviewable.

## 8.6 Do not suppress the mass-copy rule with a device allowlist

A known storage device can still be used for exfiltration. The mass-copy rule should alert on sensitive copies regardless of whether the device is allowlisted for HID/IT use. If you need to reduce noise from approved backups, tune the file-name patterns or the threshold, not the device allowlist.

## 8.7 Elastic appendix

If you use Elastic, the HID rule can use an exception list keyed on `usb.serial_number` or `usb.device_id`. The same process and review rules apply. See `appendix/elastic/README.md`.

Continue with [tuning and operations](09-tuning-and-operations.md).
