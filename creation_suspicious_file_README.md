# Creation_Suspicious_File for Wazuh 4.14

The file `creation_suspicious_file_rules.xml` ports MP SIEM rule PT-CR-225 to Wazuh and expects Microsoft Sysmon FileCreate events (Event ID 11). It uses stock Wazuh parent rule `61613`.

## Installation

1. Copy the XML file to `/var/ossec/etc/rules/creation_suspicious_file_rules.xml` on the Wazuh manager.
2. Check the manager configuration and test representative Sysmon Event ID 11 messages with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager: `systemctl restart wazuh-manager`.

## Rule mapping

| Wazuh ID | Level | MP SIEM branch | MITRE ATT&CK |
|---|---:|---|---|
| 110200 | 0 | Candidate selector (internal, no alert) | - |
| 110201 | 12 | Credential-dumping artifact | T1003 |
| 110202 | 10 | PowerShell profile persistence | T1546.013 |
| 110203 | 7 | Remaining suspicious file / subrule | T1570 |
| 110204 | 10 | PowerShell profile created (FIM) | T1546.013 |
| 110205 | 10 | PowerShell profile modified (FIM) | T1546.013 |

## FIM configuration for T1546.013

The ready-to-deploy centralized configuration is in `fim_t1546_013_agent.conf`. Place its contents in `/var/ossec/etc/shared/<WINDOWS_GROUP>/agent.conf` on the manager and assign the Windows agents to that group. It monitors standard and OneDrive-redirected profile locations for all users during scheduled FIM scans.

Wazuh reloads wildcard paths during scheduled scans; wildcard paths do not provide realtime monitoring. For realtime/Who-data monitoring, add the actual user profile paths to the Windows agent's `<syscheck>` configuration (locally or through centralized agent configuration):

```xml
<syscheck>
  <directories realtime="yes" report_changes="yes">C:\Users\USER\Documents\PowerShell</directories>
  <directories realtime="yes" report_changes="yes">C:\Users\USER\Documents\WindowsPowerShell</directories>
</syscheck>
```

Repeat the entries for each relevant local profile. If Documents is redirected to OneDrive or another location, monitor the effective redirected path instead. Explicit paths are preferable to recursively monitoring all of `C:\Users`, which can create unnecessary FIM load.

After changing centralized configuration, allow the agent to receive it and confirm that it remains connected. After changing local `ossec.conf`, restart the Wazuh agent.

## Intentional implementation differences

- MP SIEM correlates an optional process-start event with a file-create event for 30 seconds. Sysmon Event ID 11 already supplies the creator image, process ID/GUID, user, and target filename, so Wazuh can evaluate the file event directly without losing the fields used by the alert.
- MP SIEM's `CheckWL_File_Creation` and `Windows_Hacktools` are product-specific knowledge-base queries. They have no direct XML-rules equivalent and are not silently approximated here. Add local exceptions as negated `win.eventdata.image` or `win.eventdata.targetFilename` fields after tuning in your environment. A Wazuh CDB list can also be used when the allowlist consists of exact/prefix keys.
- MP SIEM marks the generic branch as an informational subrule. Wazuh has no equivalent incident/subrule type, so it is emitted as level 7. Adjust the level if this branch should be retained only for downstream correlation.

## Prerequisite

For the Sysmon branch, Sysmon must log Event ID 11 and the Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Confirm that decoded events contain `win.eventdata.targetFilename`, `win.eventdata.image`, and, if desired in descriptions, `win.eventdata.user`. The FIM branch works independently of Sysmon but requires the PowerShell profile directories to be monitored.
