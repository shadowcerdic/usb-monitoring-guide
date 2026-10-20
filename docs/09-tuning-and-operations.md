# 9. Tuning and Operations

The thresholds in this guide are starting points, not organization-specific truth. Tune them on your own telemetry.

## 9.1 Phase 0 — validate the pipeline (1 day)

- Confirm 6416, Sysmon 11/1, and volume letters arrive.
- Confirm the attribution lookup has rows and is fresh.
- Confirm the dashboard panels populate from real data.
- Run each SPL search manually over the last 7 days; compare the results with known USB activity.
- If HID serials are unreliable, keep the HID rule disabled.

## 9.2 Phase 1 — alert-only (2 weeks)

- Enable all rules you have data for, but write alerts to a low-noise channel (or the triggered-alerts index).
- Do not connect them to on-call.
- Set severity one step below the eventual value.
- Keep the SPL files and Splunk objects under change control.

## 9.3 Phase 2 — measure (end of week 2)

For each rule, record:

| Metric | How | Decision threshold |
|---|---|---|
| Alerts/day | count over 14 days | — |
| False-positive rate | manually label a sample of 20 | above ~30% → tune |
| Median triage time | open to close | above 15 minutes → improve the note/triage |
| Coverage | did it catch known USB scenarios? | if not, extend the logic |
| Job health | lookup age, job exit codes | stale/non-zero → fix before tuning |

## 9.4 Phase 3 — tune one knob at a time

| Rule | Knob | Direction | Side effect |
|---|---|---|---|
| mass copy | threshold (5) | raise if finance/HR bulk copies dominate | may miss low-volume exfiltration |
| mass copy | name patterns | add organization-specific patterns | each pattern adds false positives |
| mass copy | window (30m) | shorter = more burst-sensitive | tumbling-bin boundary effects |
| off-hours | hour bounds | adjust to the org timezone/shift | wrong bounds = silence or flood |
| off-hours | threshold (20) | lower if a single developer must be visible | more noise |
| ransomware | threshold/window | usually leave sensitive | false positives deserve investigation, not mute |
| HID | allowlist/device key | complete the inventory | HID serial quality limits this |

Change **one** knob per cycle and wait two weeks. Two changes at once means you cannot tell what worked.

## 9.5 Suppression and duplicate alerts

- Use Splunk alert suppression by group key; otherwise a threshold rule can re-fire every run while the condition persists.
- Suggested keys:
  - mass: `user`, `usb_serial`, `host`
  - off-hours: `user`, `host`, `day`
  - ransomware: `host`, `proc_key`
  - HID: `host`, `serials`
- Keep suppression windows short enough that a genuinely new incident is not hidden.
- Do not use “mute forever” for a rule; fix the data or the threshold.

## 9.6 Operational health checks

| Check | Frequency | Failure effect |
|---|---|---|
| 6416 audit policy enabled | daily/weekly | no device connects |
| Sysmon service/channel | daily | no file/process evidence |
| Forwarder/HEC delivery | continuous | missing events |
| Attribution job exit | every run | rules 1/2 silent |
| Lookup freshness | every 15 min | rules 1/2 stale |
| Index volume/retention | weekly | cost/retention gaps |
| Allowlist review | quarterly | stale access/noise |
| Detection SPL changes | every change | unknown behavior |

Create a small “pipeline health” dashboard or saved searches for these checks. A dead lookup is a silent detection outage.

## 9.7 Production handoff

1. Set final severity and risk.
2. Connect actions to the right channel — not one person’s mailbox.
3. Write a triage note for each rule (what to check, containment, escalation).
4. Confirm suppression/dedup.
5. Export the Splunk objects and keep the SPL in git.
6. Schedule a monthly 15-minute review of thresholds, allowlist, and name patterns.
7. Re-run the validation cases after any change.

## 9.8 Anti-patterns

- **Muting a rule instead of fixing the cause.** Fix the pattern/threshold/data quality.
- **Copying thresholds from this guide without measuring.** Five files in 30 minutes may be normal in one team and impossible in another.
- **Enabling everything at once.** The first week floods the team and destroys trust.
- **Treating the dashboard as a detection.** A green panel is not proof that a search fired.
- **Ignoring the attribution job.** Without it, rules 1/2 are silent; a green dashboard can be empty.
- **Allowlisting a device to silence HID noise without a ticket.** That is how the rule becomes useless.

Continue with [validation](10-validation.md).
