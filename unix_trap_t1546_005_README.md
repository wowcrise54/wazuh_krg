# Unix trap detection for Wazuh 4.14

`unix_trap_t1546_005_rules.xml` ports the `trap` signature used by MaxPatrol SIEM rule PT-CR-1021 (`Unix_Suspicious_Command`) to Wazuh. It covers MITRE ATT&CK T1546.005.

## Detection

Rule 110290, level 10, detects a command shaped like:

```sh
trap 'action' SIGNAL
trap "action" SIGNAL
```

The expression preserves the MaxPatrol table entry: `\btrap\b\s+['"](.+)['"]\s+\b\w+\b`.

## Prerequisites

The Linux endpoint must send auditd `EXECVE` records to Wazuh. Confirm that a test such as `bash -c "trap 'echo test' EXIT"` produces an event matching stock Wazuh rule 80792 and that the assembled command line is available as `audit.command`.

If command execution auditing is not already configured, add a properly scoped audit policy for the relevant shell executables. Avoid enabling an unrestricted, duplicate `execve` policy without estimating event volume first.

## Installation

1. Copy `unix_trap_t1546_005_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh manager.
2. Pass a representative raw audit event to `/var/ossec/bin/wazuh-logtest` and verify `audit.command`.
3. Restart the manager using `systemctl restart wazuh-manager`.

## Limitations and tuning

- `trap` is normally a shell builtin. Auditd sees it when it appears in arguments to a newly executed shell, such as `bash -c`, but does not generate a new `EXECVE` syscall when a user enters `trap` inside an already-running interactive shell. Detecting that case requires shell-command telemetry, eBPF/EDR instrumentation, or audited modifications to shell startup scripts.
- PT-CR-1021 uses the MaxPatrol `Legitimate_Processes_Linux` and `CheckWL_Linux_Process_Creation` exclusions. Wazuh has no automatic equivalent. Add narrowly scoped exclusions for approved scripts, service accounts, executable paths, and working directories after observing the environment.
- Legitimate administration and cleanup scripts commonly use `trap`, so the command should be investigated in context rather than treated as proof of compromise by itself.
