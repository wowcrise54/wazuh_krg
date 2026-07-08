# Persistence_Netsh_DLL for Wazuh 4.14

`persistence_netsh_dll_rules.xml` ports MaxPatrol SIEM rule PT-CR-607 to Wazuh. It detects Netsh Helper DLL persistence (MITRE ATT&CK T1546.007).

## Rule mapping

| Wazuh ID | Level | Source event | Detection |
|---|---:|---|---|
| 110240 | 12 | Sysmon 1 — Process creation | `netsh.exe` command containing `add`, `helper`, and a DLL path in that order |
| 110241 | 10 | Sysmon 13 — Registry value set | Registry modification under `Microsoft\NetSh` |

The branches are intentionally independent because the MaxPatrol source rule uses `Run_Command OR Add_Value_Registry`.

## Prerequisites

Configure Sysmon to collect:

- Event ID 1 for `netsh.exe`, including the full command line.
- Event ID 13 for registry values below `HKLM\SOFTWARE\Microsoft\NetSh`.

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm that decoded events contain:

- Process event: `win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.user`.
- Registry event: `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, `win.eventdata.user`.

## Installation

1. Copy `persistence_netsh_dll_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh manager.
2. Test representative raw Sysmon events with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Tuning

The MaxPatrol functions `CheckWL_Process_Creation` and `CheckWL_Registry_Actions` rely on product-specific allowlists and have no automatic Wazuh XML equivalent. If legitimate software registers a Netsh helper, add narrow exclusions for its exact signed image, DLL path, command line, or registry value after validating the activity. Do not suppress the entire `Microsoft\NetSh` branch.
