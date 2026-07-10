# Modify Authentication Process T1556 for Wazuh

`modify_authentication_process_t1556_rules.xml` contains Wazuh rules for the requested MITRE ATT&CK T1556 sub-techniques.

## Mapping

| Technique | Source request | Wazuh IDs | Detection logic |
|---|---|---:|---|
| T1556.001 | PT-CR-834 | 110500 | AD CS `EditFlags` enabling SAN attributes (`Enable_SAN_Flag_CA_Policy`) |
| T1556.001 | PT-CR-2439, PT-CR-2427, PT-CR-3341 not found locally | 110501-110502 | LSASS access/module anomalies aligned to Domain Controller Authentication behavior |
| T1556.002 | MITRE ATT&CK v19 | 110510-110513 | LSA `Notification Packages` / `Authentication Packages`, command-line modification, suspicious System32 DLL creation |
| T1556.003 | PT-CR-1695 | 110520-110523 | PAM configuration/module changes via FIM and auditd |
| T1556.005 | MITRE ATT&CK v19 | 110530-110532 | Reversible password encryption enabled through account changes, directory changes, or AD PowerShell |
| T1556.007 | MITRE ATT&CK v19 | 110540-110543 | AD FS / hybrid identity configuration changes through PowerShell, registry, FIM, or script block logging |
| T1556.008 | PT-CR-2633, PT-CR-2623 not found locally; implemented from MITRE ATT&CK v19 | 110550-110554 | Network Provider DLL registration, provider path changes, suspicious DLL creation, and short-window correlation |

The local `knowledgebase_2025_04_10` export contains only `PT-CR-834` and `PT-CR-1695` from the requested PT rule IDs. It does not contain `PT-CR-2439`, `PT-CR-2427`, `PT-CR-3341`, `PT-CR-2633`, or `PT-CR-2623`.

## Event Sources

- Windows Sysmon:
  - Event ID 1 / Wazuh `61603` for process creation.
  - Event ID 7 through the `sysmon` group for image loads.
  - Event ID 10 through the `sysmon` group for process access.
  - Event ID 11 / Wazuh `61613` for file creation.
  - Event ID 13 / Wazuh `61615` for registry value set.
- Windows Security:
  - Event ID 4738 for user account changes.
  - Event ID 5136 for directory object changes.
- Windows PowerShell:
  - Event ID 4104 for script block logging.
- Linux:
  - FIM rules `550` and `554` for modified/created PAM files.
  - auditd base rule `80700` with key `pam_authentication`.

## Supporting Config

- `auditd_t1556_003.rules` adds audit watches for PAM paths.
- `fim_t1556_agent.conf` adds optional FIM coverage for Linux PAM paths and Windows AD FS paths.

Deploy the XML rules to `/var/ossec/etc/rules/`, then add the relevant agent configuration and auditd rules on endpoints that should produce those events.

## Tuning Notes

- Rule `110501` detects suspicious LSASS process access and should be scoped to domain controllers through agent groups or tuned allowlists.
- Rule `110502` needs Sysmon image load logging; without Event ID 7 collection it will never fire.
- Rule `110500` preserves the MP SIEM `EditFlags` value pattern for `Enable_SAN_Flag_CA_Policy`. Validate against real Sysmon Event ID 13 samples from your CA servers.
- Rule `110554` correlates a Network Provider `ProviderPath` registry change with suspicious DLL creation on the same Wazuh agent within five minutes.
- Package manager PAM changes are suppressed with `no_log` in rule `110523`; remove or adjust this rule if package upgrades should be visible.

