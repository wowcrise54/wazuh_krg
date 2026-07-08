# Application Shimming detections for Wazuh 4.14

`application_shimming_t1546_011_rules.xml` detects MITRE ATT&CK T1546.011 on Windows using Sysmon process, file and registry telemetry.

## Rules

| Wazuh ID | Level | Detection |
|---|---:|---|
| 110330 | 12 | `sdbinst.exe` invoked with an `.sdb` file, excluding explicit uninstall commands |
| 110331 | 10 | `.sdb` created below `Windows\AppPatch\Custom` or `AppPatch64\Custom` |
| 110332 | 10 | `AppCompatFlags\InstalledSDB` or `AppCompatFlags\Custom` modified |
| 110333 | 7 | `AppCompatFlags\Layers` modified |
| 110334 | 13 | `sdbinst.exe` followed by shim registry registration within 60 seconds |
| 110335 | 13 | `sdbinst.exe` followed by custom `.sdb` creation within 60 seconds |

## Prerequisites

Configure Sysmon to collect:

- Event ID 1 for `sdbinst.exe`, including `CommandLine` and `User`.
- Event ID 11 below `C:\Windows\AppPatch\Custom` and `C:\Windows\AppPatch\AppPatch64\Custom`.
- Event IDs 12, 13 and 14 below `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`.

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm these decoded fields:

- Process: `win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.user`.
- File: `win.eventdata.targetFilename`, `win.eventdata.image`, `win.eventdata.user`.
- Registry: `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, `win.eventdata.user`.

## Installation

1. Copy `application_shimming_t1546_011_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative raw Sysmon events using `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Tuning

- Application compatibility tooling and enterprise software deployment can legitimately use `sdbinst.exe`. Allowlist exact signed deployment tools, expected `.sdb` hashes/paths, command lines and maintenance accounts.
- `AppCompatFlags\Layers` is frequently changed by users and installers, so rule 110333 intentionally has a lower level. Disable or narrow it if it is too noisy.
- Rules 110334 and 110335 correlate by Wazuh agent and time window. They do not require the same process GUID because Windows may use helper processes while registering or copying a database.
- The rules focus on installation artifacts. Explicit `sdbinst.exe -u` uninstall operations are excluded from rule 110330 but can be monitored separately for cleanup or defense-evasion investigations.

The selected artifacts follow the current MITRE ATT&CK description and detection strategy for Application Shimming: `sdbinst.exe`, custom databases under `AppPatch`, and `AppCompatFlags` registry registration.
