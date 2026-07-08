# Accessibility Features detections for Wazuh 4.14

`accessibility_features_t1546_008_rules.xml` ports MaxPatrol SIEM rules PT-CR-268 and PT-CR-459 to Wazuh. The rules detect abuse of Windows Accessibility Features associated with MITRE ATT&CK T1546.008.

## Mapping

| Wazuh ID | Level | MaxPatrol rule | Detection source |
|---|---:|---|---|
| 110260 | 12 | PT-CR-268 `Windows_Accessibility_StickyKey_Modification` | Sysmon 13: IFEO registry value for an accessibility executable points to an EXE |
| 110261 | 12 | PT-CR-459 `Accessibility_Feature_Tool_Abuse` | Sysmon 1: accessibility executable creates a child process |
| 110262 | 10 | PT-CR-459 | Sysmon 3: accessibility executable creates a network connection |
| 110263 | 10 | PT-CR-459 | Windows Security 5156: alternative network telemetry |

Covered executables: `osk.exe`, `narrator.exe`, `sethc.exe`, `magnify.exe`, `displayswitch.exe`, `utilman.exe`, and `atbroker.exe`.

## Prerequisites

Configure Sysmon to collect:

- Event ID 1 with `Image`, `ParentImage`, `CommandLine`, and `User`.
- Event ID 3 for network connections from the covered executables.
- Event ID 13 below `Image File Execution Options`.

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. To use rule 110263, enable the relevant Windows Filtering Platform auditing and collect the Windows `Security` channel. Sysmon Event 3 is sufficient for the network branch when available.

## Installation

1. Copy `accessibility_features_t1546_008_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative raw events with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager with `systemctl restart wazuh-manager`.

## Tuning

The source functions `CheckWL_Registry_Actions`, `CheckWL_Process_Creation`, and `CheckWL_Networking` use MaxPatrol-specific allowlists. They have no automatic Wazuh XML equivalent. Add narrowly scoped exclusions only after validating legitimate software, using exact image paths, child command lines, destinations, or registry values. Child processes and network activity from pre-logon Accessibility Features are uncommon and should not be broadly suppressed.

Confirm the actual decoded fields for Event 5156 before enabling that branch as an alert source. Depending on Windows/Wazuh versions, destination fields may require adjustment from `win.eventdata.destAddress` and `win.eventdata.destPort` to the names shown by `wazuh-logtest`.
