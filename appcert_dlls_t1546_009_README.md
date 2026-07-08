# AppCert DLL detections for Wazuh 4.14

`appcert_dlls_t1546_009_rules.xml` ports MaxPatrol SIEM rules PT-CR-1349 and PT-CR-1360 to Wazuh. It covers MITRE ATT&CK T1546.009.

## Mapping

| Wazuh ID | Level | MaxPatrol logic |
|---|---:|---|
| 110320 | 12 | PT-CR-1360 `Suspicious_Registry_Value`: AppCert DLL registry key/value created or modified |
| 110321 | 12 | PT-CR-1349 `AppCert_DLLs_Persist`: `AppCert` value set and payload exposed in Event 13 |
| 110322 | 5, internal | Optional process command references `Control\Session Manager\AppCertDlls` |
| 110323 | 13 | Same PID writes the registry value within 30 seconds of the command precursor |

PT-CR-1349 and the AppCert entry from PT-CR-1360 overlap on `Control\Session Manager\AppCertDlls\AppCert`. The Wazuh rules use parent/child matching so one Event 13 produces the most specific alert instead of duplicate alerts.

## Prerequisites

Configure Sysmon to collect:

- Event IDs 12 and 13 for `*\Control\Session Manager\AppCertDlls\AppCert`.
- Event ID 1 with full command lines if the optional high-confidence correlation is required.

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm these fields:

- Registry: `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, `win.eventdata.processId`, `win.eventdata.user`.
- Process: `win.eventdata.commandLine`, `win.eventdata.processId`.

## Installation

1. Copy `appcert_dlls_t1546_009_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative Sysmon events with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Porting notes and tuning

- PT-CR-1349 treats the process event as optional; therefore rules 110320/110321 alert even when no matching process creation event was retained. Rule 110323 only raises confidence when the precursor exists.
- PT-CR-1360 is a generic table-driven registry detector. Only its explicit AppCert entry was ported here; unrelated long/Base64 registry-value logic is not part of T1546.009.
- The source allowlist `CheckWL_Registry_Actions` has no automatic Wazuh XML equivalent. Add narrow exclusions for trusted modifying images and exact approved DLL paths after baselining.
- The source rules specifically require the value name `AppCert`. Other AppCertDlls value names are outside their original scope; expand the final path expression only if broader local coverage is intended.
