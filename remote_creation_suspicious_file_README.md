# Remote_Creation_Suspicious_File for Wazuh 4.14

`remote_creation_suspicious_file_rules.xml` is a native Wazuh port of MP SIEM rule PT-CR-1373. It detects access to suspicious file types over a Windows SMB share using Security Event ID 5145.

## Prerequisites

- Enable **Audit Detailed File Share** (`Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Object Access`).
- The Wazuh agent must collect the Windows `Security` event channel.
- Verify that a decoded 5145 event contains `win.eventdata.ipAddress`, `win.eventdata.accessList`, `win.eventdata.shareName`, and `win.eventdata.relativeTargetName`.

## Installation

1. Copy `remote_creation_suspicious_file_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh manager.
2. Validate representative raw 5145 events with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager with `systemctl restart wazuh-manager`.

## Rule mapping

| Wazuh ID | Level | Purpose | MITRE ATT&CK |
|---|---:|---|---|
| 110210 | 0 | Internal 5145 selector | - |
| 110211 | 12 | Credential-dumping artifacts | T1003, T1570 |
| 110212 | 10 | Suspicious scripts, executables and source/project files | T1570 |

## Porting notes

- Event 5145 already carries the remote source IP, account, logon ID, share and relative target name, so the Wazuh implementation detects the remote share operation directly.
- The MP SIEM branch correlating `Creation_Suspicious_File` with a network logon consumes a product-specific correlation event that does not exist in Wazuh. It is not imitated with a weaker cross-event correlation.
- The source filters `CheckWL_File_Creation` and `CheckWL_Windows_Shares` are MP SIEM knowledge-base functions. Add environment-specific exceptions as extra negated `<field>` conditions after the selector, or maintain a Wazuh CDB list for stable exact/prefix allowlist keys.
- The access check preserves the source rule's use of Windows access tokens `%%4416` and `%%4417`. If the local event language renders access names rather than tokens, tune the `win.eventdata.accessList` condition against an actual decoded 5145 event.
