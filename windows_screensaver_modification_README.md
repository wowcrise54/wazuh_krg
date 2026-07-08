# Windows_Screensaver_Modification for Wazuh 4.14

`windows_screensaver_modification_rules.xml` ports MP SIEM rule PT-CR-270 to Wazuh and detects modification of the per-user `SCRNSAVE.EXE` registry value under `Control Panel\Desktop` (MITRE ATT&CK T1546.002).

## Detection paths

| Wazuh ID | Source | Event | Level |
|---|---|---:|---:|
| 110220 | Microsoft Sysmon | 13 — Registry value set | 10 |
| 110221 | Windows Security | 4657 — Registry value modified | 10 |

Both rules require the new value to contain one of the extensions from the source rule: `.scr`, `.exe`, `.cmd`, `.ps1`, or `.bat`.

## Installation

1. Copy `windows_screensaver_modification_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh manager.
2. Test representative raw Event 13 and/or Event 4657 records with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager: `systemctl restart wazuh-manager`.

## Telemetry prerequisites

For the Sysmon branch, configure Sysmon to include registry `SetValue` events for paths ending in `\Control Panel\Desktop\SCRNSAVE.EXE`, and make sure the Wazuh agent collects `Microsoft-Windows-Sysmon/Operational`.

For the Security branch, enable **Audit Registry** and configure an appropriate registry SACL so Windows produces Event 4657. The Wazuh agent must collect the `Security` channel. Sysmon is generally the simpler source because Event 4657 is not emitted merely by enabling the audit subcategory; the target key also needs auditing configured.

Confirm the decoded field names using a real event:

- Sysmon: `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, `win.eventdata.user`.
- Security: `win.eventdata.objectName`, `win.eventdata.objectValueName`, `win.eventdata.newValue`, `win.eventdata.processName`, `win.eventdata.subjectUserName`.

## Allowlisting

The source function `CheckWL_Registry_Actions` is specific to the MP SIEM knowledge base and has no automatic Wazuh XML equivalent. After observing legitimate changes in the environment, add narrowly scoped negated `<field>` conditions for trusted images or approved screen saver paths. Avoid excluding `SCRNSAVE.EXE` changes globally, because that is the persistence mechanism being detected.
