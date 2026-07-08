# AppInit DLL detections for Wazuh 4.14

`appinit_dlls_t1546_010_rules.xml` ports the AppInit DLL branches of MaxPatrol SIEM rule PT-CR-269 (`Windows_Autorun_Modification`) to Wazuh. The rules cover MITRE ATT&CK T1546.010.

## Mapping

| Wazuh ID | Level | PT-CR-269 condition |
|---|---:|---|
| 110270 | 12 | The `AppInit_DLLs` value was changed |
| 110271 | 12 | `LoadAppInit_DLLs` was set to DWORD 1 |

Both native and 32-bit registry views are covered because the expression matches the common suffix `Microsoft\Windows NT\CurrentVersion\Windows`, including paths containing `WOW6432Node` before that suffix.

The other autorun branches inside PT-CR-269—Run keys, Startup folders, BootExecute and Shell Folders—are intentionally excluded because they are not AppInit DLLs/T1546.010.

## Prerequisites

Configure Sysmon to collect Event ID 13 (`RegistryEvent — Value Set`) for:

- `*\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`
- `*\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs`

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm that decoded events contain `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, and `win.eventdata.user`.

## Installation

1. Copy `appinit_dlls_t1546_010_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative raw Sysmon Event 13 records with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Tuning

The MaxPatrol function `CheckWL_Registry_Actions` uses a product-specific allowlist and has no automatic Wazuh XML equivalent. If approved software manages AppInit DLLs, add exclusions scoped to the exact modifying image and expected value. Avoid suppressing either registry value globally.

Rule 110271 recognizes common Sysmon representations such as `DWORD (0x00000001)`, `0x1`, and `1`. Verify the local `win.eventdata.details` format with `wazuh-logtest` before deployment.
