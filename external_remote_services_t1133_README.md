# External Remote Services T1133 for Wazuh

`external_remote_services_t1133_rules.xml` ports the available MP SIEM rules for MITRE ATT&CK T1133 External Remote Services to Wazuh XML rules.

## Source mapping

| MP SIEM ID | MP SIEM rule | Wazuh IDs | Wazuh logic |
|---|---|---:|---|
| PT-CR-472 | External_VPN_Service_Usage | 110400-110403 | Level 0 selectors for ESP, UDP VPN ports and PPTP, followed by one alert rule with `if_sid` |
| PT-CR-1937 | SMB_RPC_Internet_Connection | 110410-110414 | Level 0 selectors for Sysmon 3 and Windows 5156 involving external SMB/RPC, followed by one alert rule with `if_sid` |
| PT-CR-1783 | Owa_Abnormal_Access | 110420-110422 | Successful OWA access from normalized JSON or decoded IIS fields |
| PT-CR-1036 | Mail_Abnormal_Access | 110430-110432 | Successful ActiveSync POST with DeviceId from normalized JSON or decoded IIS fields |
| PT-CR-1787 | MFA_Abnormal_Access | 110440-110441 | Successful MFA response plus a Wazuh `if_matched_sid` correlation for same account from different external IPs |
| PT-CR-1056 | VPN_MultiUser_IP | 110450-110453 | Level 1 `no_log` selectors plus `if_matched_sid`, `same_field` and `different_field` correlation |
| PT-CR-2653 | Duplicate_Remote_Session | 110460 | Normalized duplicated remote-session event |
| PT-CR-427 | Connect_To_Significant_Hosts_From_VPN | 110470-110471 | CDB list based VPN-pool to significant-destination detection |

The local `knowledgebase_2025_04_10` export did not contain `PT-CR-1058`, `PT-CR-1048`, or `PT-CR-1055`, so they are not implemented in this file.

## Required CDB Lists

Rule `110470` requires these lists to be registered inside the manager `<ruleset>` configuration:

```xml
<list>etc/lists/vpn-networks</list>
<list>etc/lists/significant-networks</list>
<list>etc/lists/significant-hosts-whitelist</list>
```

Example list entries:

```text
10.8.0.0/24:
172.20.30.0/24:
```

Use `vpn-networks` for VPN address pools, `significant-networks` for protected destinations, and `significant-hosts-whitelist` for destination IPs that should not alert.

## Prerequisites

- Wazuh manager with these custom rules loaded from `/var/ossec/etc/rules/`.
- Sysmon Event ID 3 collected from `Microsoft-Windows-Sysmon/Operational` if using `PT-CR-1937` Sysmon coverage.
- Windows Security Event ID 5156 collected if using `PT-CR-1937` Windows Filtering Platform coverage.
- IIS/Exchange logs decoded into Wazuh static fields such as `url`, `status`, `user`, `srcip`, and `method`, or normalized JSON fields matching the MP SIEM field names in the rule file.
- VPN, firewall, MFA and remote-access logs decoded as JSON with fields such as `event_src.title`, `src.ip`, `dst.ip`, `subject.account.name`, `object.account.name`, and `external_src.ip`.

## Porting Notes

- MP SIEM profile tables such as `Risk_User_Logon_Correlation_Profile`, `Auto_Profile`, `Check_Profile`, `CheckWL_Profiling`, `VPN_Networks`, and `Significant_Networks` are not native Wazuh XML features.
- Wazuh `if_matched_sid` cannot use level 0 rules because level 0 matches are discarded. The VPN correlation selectors are therefore level 1 with `no_log`.
- `same_field` and `different_field` are used only with dynamic JSON fields.
- `PT-CR-427` is implemented with CDB address lists, which is the Wazuh-native replacement for MP SIEM lookup tables in this case.
- Validate actual decoded field names with `/var/ossec/bin/wazuh-logtest`; adjust field names if your decoders use a different schema.

