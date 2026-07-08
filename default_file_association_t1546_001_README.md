# Default file association modification for Wazuh 4.14

`default_file_association_t1546_001_rules.xml` ports MaxPatrol SIEM rule PT-CR-664 (`Default_File_Association_Modify`) to Wazuh. It covers MITRE ATT&CK T1546.001.

## Mapping

| Wazuh ID | Level | PT-CR-664 branch |
|---|---:|---|
| 110280 | 0 | Internal registry selector |
| 110281 | 12 | New value contains `cmd.exe`, `powershell.exe`, or `powershell_ise.exe` |
| 110282 | 10 | `shell\open\command` changed |
| 110283 | 7 | Default value below `Software\Classes\.extension` changed |
| 110284 | 7 | Program added under `FileExts\.extension\OpenWithProgids` by a process other than Explorer |
| 110285 | 7 | Per-user `FileExts\.extension\UserChoice\ProgId` changed |

## Prerequisites

Configure Sysmon to collect Event ID 13 (`RegistryEvent — Value Set`) for:

- `*\shell\open\command\*`
- `*\Software\Classes\.*\(Default)`
- `*\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithProgids\*`
- `*\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\UserChoice\ProgId`

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm that decoded events contain `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, and `win.eventdata.user`.

## Installation

1. Copy `default_file_association_t1546_001_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative raw Sysmon Event 13 records using `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Porting notes and tuning

- PT-CR-664 optionally enriches a registry event with a nearby `cmd.exe /c assoc` or `ftype` process event. The registry event itself is mandatory in the source correlation, so the Wazuh port alerts directly from Sysmon 13 and retains the modifying image.
- The source downgrades bursts of more than three changes because they may represent software installation. Wazuh XML cannot safely reproduce that negative-count decision without delaying or suppressing the first events; tune trusted installer images instead.
- `CheckWL_Registry_Actions` is a MaxPatrol-specific allowlist. Add narrow Wazuh exclusions for trusted signed installers and exact expected ProgIDs after observing the environment.
- Windows frequently changes per-user file associations legitimately. Rules 110283–110285 therefore use lower levels than direct `shell\open\command` modification or a command-shell handler.
