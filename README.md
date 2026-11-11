# windows-audit

Read-only Windows host audit. The script queries services, scheduled tasks,
registry, disks, event logs and TCP listeners, then prints ONE JSON object to
stdout. It never changes system state. Requires Windows PowerShell 5.1 only —
no external modules.

## What it checks

| Check | Name | Why it matters |
|---|---|---|
| S1 | `auto_service_stopped` | Services set to start automatically that are not running can mean a failed update, a crashed dependency, or something disabled them. |
| S2 | `scheduled_task_failed` | Tasks whose last run returned non-zero are silent failures: missed backups, updaters, or maintenance jobs. |
| S3 | `reboot_pending` | A pending reboot (CBS `RebootPending` or `PendingFileRenameOperations`) means patches are half-applied until the next restart. |
| S4 | `disk_low` | Disks below 15% free space risk failed updates, crashed apps, and missing logs. Flagged `critical`. |
| S5 | `error_events_24h` | Count of critical/error System log entries in the last 24h is a quick system-health pulse. |
| S6 | `port_no_owner` | Listening TCP ports shared by multiple PIDs or owned by a dead PID can indicate a crashed service or something worth investigating. |

Any check whose data source is missing degrades gracefully to an `info` finding
with detail `check unavailable: <reason>` instead of failing the run.

Exit code is `0` when JSON was produced, `1` when it could not be produced.
Use `-Pretty` for indented JSON. Output is pure JSON on stdout, so it pipes
cleanly into other tools.

## Usage

```powershell
powershell -NoProfile -File audit.ps1 -Pretty
python verify.py
python verify.py --save out.json
```

`verify.py` (stdlib only) runs `audit.ps1`, parses stdout as JSON, and checks:
`uptime_hours` numeric; `findings` cover all 6 check ids; each finding has the
required keys with `severity` in `critical|warning|info`; `summary` counts match
actual counts. Exit `0` only if all assertions pass.

## Real run on this machine

`powershell -NoProfile -ExecutionPolicy Bypass -File audit.ps1 -Pretty`
(trimmed to the first 2 findings; remainder replaced with `(truncated)`):

```json
{
  "host": {
    "name": "THAIPC",
    "os": "Microsoft Windows 11 Pro",
    "uptime_hours": 2.89,
    "generated_at": "2026-11-10T17:53:25.7197538Z"
  },
  "findings": [
    {
      "check": "auto_service_stopped",
      "severity": "warning",
      "detail": "7 automatic service(s) not running.",
      "evidence": {
        "stopped_count": 7,
        "services": [
          "AppXSvc [Stopped]",
          "asus [Stopped]",
          "edgeupdate [Stopped]",
          "GoogleUpdaterInternalService157.0.8089.0 [Stopped]",
          "GoogleUpdaterService157.0.8089.0 [Stopped]",
          "LDPlayerSvr [Stopped]",
          "MapsBroker [Stopped]"
        ],
        "truncated": false
      }
    },
    {
      "check": "scheduled_task_failed",
      "severity": "warning",
      "detail": "101 scheduled task(s) with non-zero LastTaskResult.",
      "evidence": {
        "failed_count": 101,
        "tasks": [
          "\\AMDAutoUpdate (0xC000013A)",
          "\\AMDInstallLauncher (0x00041303)",
          "\\CreateExplorerShellUnelevatedTask (0x40010004)",
          "\\HermesWebUIAutoStart (0x8007010B)",
          "\\Hermes_WebUI_taiop (0x8007010B)",
          "\\i4Airplay_Users (0x80070002)",
          "\\OneDrive Per-Machine Standalone Update Task (0x8004EE04)",
          "\\StartAUEP (0x00041301)",
          "\\StartCN (0x00000001)",
          "\\StartDVR (0x00000001)",
          "\\TAIOP-Canonical-Startup (0x00041301)",
          "\\ASUS\\AcPowerNotification (0x00041301)",
          "\\ASUS\\P508PowerAgent_sdk (0x80070002)",
          "\\Microsoft\\Office\\Office Automatic Updates 2.0 (0x8007042B)",
          "\\Microsoft\\Office\\Office Performance Monitor (0x00041303)",
          "\\Microsoft\\Office\\Office Startup Maintenance (0xFFFFFFF8)",
          "\\Microsoft\\Windows\\AccountHealth\\RecoverabilityToastTask (0x80040154)",
          "\\Microsoft\\Windows\\Active Directory Rights Management Services Client\\AD RMS Rights Policy Template Management (Automated) (0x00041303)",
          "\\Microsoft\\Windows\\Active Directory Rights Management Services Client\\AD RMS Rights Policy Template Management (Manual) (0x00041303)",
          "\\Microsoft\\Windows\\Application Experience\\MareBackup (0x00041303)",
          "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser Exp (0x00041303)",
          "\\Microsoft\\Windows\\Application Experience\\SdbinstMergeDbTask (0x00041303)",
          "\\Microsoft\\Windows\\BitLocker\\BitLocker Encrypt All Drives (0x00041303)",
          "\\Microsoft\\Windows\\BitLocker\\BitLocker MDM policy Refresh (0x00041303)",
          "\\Microsoft\\Windows\\Bluetooth\\UninstallDeviceTask (0x00041303)"
        ],
        "truncated": true
      }
    },
    "(truncated)"
  ],
  "summary": {
    "critical": 0,
    "warning": 3,
    "info": 3
  }
}
```

The full untrimmed output of that run is in `sample-output.json`.

`python verify.py`:

```text
PASS: powershell exit code is 0
PASS: stdout is valid JSON
PASS: top level is a JSON object
PASS: top-level keys host, findings, summary present
PASS: host.uptime_hours is numeric
PASS: host.name/os/generated_at are non-empty strings
PASS: findings list covers all 6 expected check ids in order
PASS: every finding has the required keys (check, severity, detail, evidence) with correct types
PASS: every severity is one of critical|warning|info
PASS: summary counts equal actual counts
10/10 assertions passed.
```
