# Unix shell configuration detections for Wazuh 4.14

This package implements the requested MaxPatrol SIEM coverage associated with MITRE ATT&CK T1546.004.

## Files

- `unix_shell_t1546_004_rules.xml`: manager-side detection rules.
- `unix_shell_t1546_004_agent.conf`: Linux FIM configuration.
- `auditd_t1546_004.rules`: audit watches and TIOCSTI syscall auditing.

## Mapping

| Wazuh ID | MaxPatrol rule | Implementation |
|---|---|---|
| 110250, 110251, 110253 | PT-CR-1670 `Unix_Shell_Config_Modify` | System/user shell configuration changes through FIM and auditd |
| 110252, 110253 | PT-CR-1029 `Unix_Sensitive_File_Modification` | Sensitive shell files and editor swap artifacts |
| 110254 | PT-CR-2750 `Unix_TTY_Command_Injection` | Direct audit of `ioctl(TIOCSTI)` |
| 110255 | PT-CR-3003 `CVE_2025_32433_Erlang_SSH_RCE` | Suspicious command tagged as launched from an Erlang SSH context |

## Installation

1. Copy `unix_shell_t1546_004_rules.xml` to `/var/ossec/etc/rules/` on the manager.
2. Deploy the contents of `unix_shell_t1546_004_agent.conf` through the relevant Linux agent group.
3. Copy the audit rules to `/etc/audit/rules.d/t1546_004.rules`, validate with `augenrules --check`, and load them using `augenrules --load` or restart `auditd` according to the distribution's procedure.
4. Ensure the Wazuh agent collects audit logs and remains connected.
5. Test representative FIM and audit records with `/var/ossec/bin/wazuh-logtest`, then restart `wazuh-manager`.

Before loading the audit rules, remove watches for paths that do not exist on the endpoint. Add explicit `-w` entries for important user dotfiles because Linux audit watches do not support shell-style user wildcards.

## Accuracy and limitations

- Exact local source rules were available for PT-CR-1670 and PT-CR-1029. PT-CR-3003 and PT-CR-2750 were not present in the supplied knowledge-base snapshot; their purposes were recovered from Positive Technologies' public T1546.004 matrix and implemented behaviorally.
- PT-CR-1029 uses the MaxPatrol `Unix_Sensitive_Files` knowledge table. Wazuh has no equivalent built-in list, so this package limits that branch to shell startup files relevant to T1546.004.
- Rule 110254 detects the decisive TIOCSTI syscall but does not reproduce MaxPatrol's preceding user-switch correlation. The alert retains audit identity and executable context for investigation.
- Rule 110255 deliberately requires upstream ancestry enrichment with audit key `erlang_ssh_rce`. Standard Linux audit cannot safely express a portable `beam.smp` parent-process rule because Erlang paths and service UIDs vary. Configure this key using an endpoint-specific audit/eBPF policy; without it, rule 110255 remains dormant rather than generating broad false positives.
- Wildcard FIM paths are evaluated during scheduled scans. Add explicit non-wildcard paths for realtime monitoring of critical local accounts.
