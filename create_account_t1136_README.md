# Create Account T1136 for Wazuh

This package ports the requested MP SIEM detections to Wazuh and aligns their behavior with MITRE ATT&CK Enterprise v19.

## Files

- `create_account_t1136_rules.xml`: Wazuh manager rules.
- `auditd_t1136_001.rules`: Linux Audit rules for `useradd`, `adduser`, `/etc/passwd`, and `/etc/shadow`.
- `fim_t1136_001_agent.conf`: Linux FIM fragment for the account databases.
- `t1136_ad-domain-names.list`: template for `etc/lists/ad-domain-names`.
- `t1136_authorized-account-creators.list`: template for `etc/lists/authorized-account-creators`.

## Mapping

| Technique | MP SIEM rule | Wazuh rule IDs | Ported behavior |
|---|---|---:|---|
| T1136.001 | PT-CR-259 | 110601-110603 | Local Windows 4720; optional local Administrators addition |
| T1136.001 | PT-CR-260 | 110604-110605 | Same local account created and deleted within 24 hours |
| T1136.001 | PT-CR-264 | 110610-110613 | `net user /add`, `New-LocalUser`, or `Add-NetUser`, correlated with 4720 |
| T1136.001 | PT-CR-2594 | 110620 | Direct non-LSASS write to SAM user keys, including hidden account creation |
| T1136.001 | PT-CR-1908 | 110625-110628 | Unexpected WER report, abnormal SYSTEM `wermgr`, process tampering, then SYSTEM 4720 |
| T1136.001 | MITRE v19 AN1236 | 110630-110632 | Linux account utilities and `/etc/passwd` or `/etc/shadow` changes |
| T1136.002 | PT-CR-663 | 110650-110651 | Domain 4720 on a configured AD domain |
| T1136.002 | MITRE v19 AN0006 | 110652-110654 | Domain account command followed by 4720 |
| T1136.002 | PT-CR-2143 | 110660-110662 | Kerberos network logon followed by unauthorized 4741 |
| T1136.002 | PT-CR-1342, PT-CR-1344 | 110670-110673 | Account-creation branches of PowerView LDAP/command activity followed by 4720 or 4741 |
| T1136.002 | PT-CR-3079 | 110657-110658, 110675-110676 | gMSA/dMSA creation through 5137, optionally preceded by `New-ADServiceAccount` |

## Required manager configuration

Copy `create_account_t1136_rules.xml` to `/var/ossec/etc/rules/`.

Create these CDB lists on the manager:

1. `/var/ossec/etc/lists/ad-domain-names`

   Add each Active Directory NetBIOS domain exactly as it appears in `win.eventdata.targetDomainName`. CDB matching is case-sensitive, so include both observed case variants when necessary. Replace the template entries; do not keep them as the only entries.

2. `/var/ossec/etc/lists/authorized-account-creators`

   Add the SIDs of helpdesk, provisioning, domain admin, and service accounts that are authorized to create computer or managed service accounts. The included `S-1-0-0` entry is a harmless sentinel and should be supplemented with real SIDs.

Register both lists in the manager's `<ruleset>` block:

```xml
<list>etc/lists/ad-domain-names</list>
<list>etc/lists/authorized-account-creators</list>
```

Restart `wazuh-manager` after changing rules or lists.

## Required telemetry

- Windows Security: 4624, 4720, 4726, 4732, 4741, 5137.
- Directory Service diagnostic event 1644 for the PowerView correlation rules.
- PowerShell Operational 4103/4104.
- Sysmon 1, 11, 12, 13, and 25.
- Linux Auditd and/or Wazuh FIM for MITRE v19 AN1236.

## Wazuh correlation notes

- Rules referenced by `if_matched_sid` or `if_matched_group` are level 1 with `no_log`; Wazuh discards level 0 rules from correlation memory.
- Correlation rules use the minimum valid `frequency="2"` together with `timeframe`; the selector event and the current event form the two-event sequence.
- Windows correlations use `same_field` on `win.system.computer`, not `same_location`; this allows a Security event to correlate with Sysmon or PowerShell telemetry from the same host even though the channels differ.
- Rule 110603 uses the same computer and a 30-second window. Native Windows fields use `targetUserName` for 4720 but `memberSid`/`memberName` for 4732, so Wazuh cannot compare the account across those two event schemas without a custom normalization decoder.
- PT-CR-260 used a failed 4724 as a stop condition. Wazuh has no native negative/interruption operator, so 110605 implements the stable part of the behavior: same account, same agent, create then delete within 24 hours.
- PT-CR-1342 and PT-CR-1344 contain many non-creation PowerView actions. This package intentionally ports only their `Add-DomainUser`, `New-DomainUser`, and `Add-DomainComputer` branches because the requested scope is T1136.002.
- Test field names against real events with `wazuh-logtest`, especially Event 1644 and 5137, because Windows provider versions can change the populated `win.eventdata.*` fields.
