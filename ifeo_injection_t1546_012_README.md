# IFEO injection detections for Wazuh 4.14

`ifeo_injection_t1546_012_rules.xml` ports MaxPatrol SIEM rules PT-CR-521 and PT-CR-261 to Wazuh. The rules cover MITRE ATT&CK T1546.012.

## Mapping

| Wazuh ID | Level | MaxPatrol rule | Detection |
|---|---:|---|---|
| 110310 | 12 | PT-CR-521 `Debugger_In_Image_File_Execution_Options` | `Debugger` value written below an IFEO executable key |
| 110311 | 5, internal | PT-CR-261 stage 1 | IFEO `GlobalFlag` written |
| 110312 | 5, internal | PT-CR-261 stage 2 | `ReportingMode` written within 30 minutes on the same agent |
| 110313 | 10 | Supplemental high-value signal | `MonitorProcess` written below `SilentProcessExit` |
| 110314 | 12 | PT-CR-261 `GlobalFlags_In_Image_File_Execution_Options` | Complete `GlobalFlag` → `ReportingMode` → `MonitorProcess` sequence |

Internal rules use `no_log`: they remain available to temporal correlation without producing standalone alerts.

## Prerequisites

Configure Sysmon to collect Event ID 13 (`RegistryEvent — Value Set`) for:

- `*\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger`
- `*\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\GlobalFlag`
- `*\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*\ReportingMode`
- `*\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*\MonitorProcess`

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm that decoded events contain `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, and `win.eventdata.user`.

## Installation

1. Copy `ifeo_injection_t1546_012_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative raw Sysmon Event 13 records using `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Porting notes and tuning

- PT-CR-261 correlates three registry writes by host within 30 minutes without requiring the executable subkey to be equal. The Wazuh sequence preserves this host-level behavior through `same_location`.
- Wazuh temporal correlation is ordered. Rule 110314 expects the usual configuration order: `GlobalFlag`, then `ReportingMode`, then `MonitorProcess`. Rule 110313 detects `MonitorProcess` independently so a different write order does not become invisible.
- The source rules do not restrict the written values. This port likewise alerts on the value names themselves and exposes the new value in the description.
- `CheckWL_Registry_Actions` is a MaxPatrol-specific allowlist. Add narrow exclusions for approved debugger tooling, exact target executables, modifying images and payload paths after baselining.
