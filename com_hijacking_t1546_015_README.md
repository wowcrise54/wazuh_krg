# COM hijacking detections for Wazuh 4.14

`com_hijacking_t1546_015_rules.xml` ports MaxPatrol SIEM rules PT-CR-265 and PT-CR-2314 to Wazuh. The primary technique is MITRE ATT&CK T1546.015.

## Mapping

| Wazuh ID | Level | MaxPatrol rule | Detection |
|---|---:|---|---|
| 110300 | 7 | PT-CR-265 `COM_Object_Persistence` | `InprocServer`, `LocalServer`, or `ScriptletURL` points to DLL/SCT/EXE/OCX content |
| 110301 | 10 | PT-CR-265 | A COM `TreatAs` registration is created or changed |
| 110302 | 5, internal | PT-CR-2314 candidate | Outlook registers a DLL under a Forms directory as `InprocServer32` |
| 110303 | 12 | PT-CR-2314 `CVE_2024_21378_Outlook_RCE` | The same Outlook PID loads a Forms DLL within five seconds |

Rule 110302 uses `no_log`: it remains available for temporal correlation without producing a standalone alert.

## Prerequisites

Configure Sysmon to collect:

- Event IDs 12, 13, and 14 below user and machine `Software\Classes` COM registrations.
- Event ID 7 for DLL loads by `OUTLOOK.EXE`, including DLLs below users' `AppData\Local\Microsoft*\Forms` directories.

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm these decoded fields:

- Registry: `win.eventdata.targetObject`, `win.eventdata.details`, `win.eventdata.image`, `win.eventdata.processId`, `win.eventdata.user`.
- Image load: `win.eventdata.image`, `win.eventdata.imageLoaded`, `win.eventdata.processId`, `win.eventdata.user`.

Event ID 7 can be noisy. Filter it in Sysmon to Outlook and the relevant Forms paths instead of collecting every image load.

## Installation

1. Copy `com_hijacking_t1546_015_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Test representative raw registry and image-load events using `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Porting notes and tuning

- PT-CR-265 groups registry subevents for two seconds. Wazuh evaluates each matching registry event independently, retaining the modifying process and value.
- PT-CR-2314 joins on host, Outlook PID and DLL path. The Wazuh rule preserves host, PID and five-second timing. Wazuh XML cannot compare the registry `details` field directly with the later `imageLoaded` field, so both are independently constrained to the same Outlook Forms directory pattern.
- The source functions `CheckWL_Registry_Actions` and `CheckWL_Specific_Only` rely on MaxPatrol-specific allowlists. Add narrow exclusions for trusted signed software, known CLSIDs and exact approved server paths after baselining.
- The Outlook path expression covers traditional Office and Click-to-Run `root\OfficeNN` layouts. Adjust it if Outlook is installed elsewhere.
