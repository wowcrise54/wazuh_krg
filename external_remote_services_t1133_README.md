# External Remote Services T1133 for Wazuh 4.14

`external_remote_services_t1133_rules.xml` ports the available MP SIEM rules for MITRE ATT&CK T1133 External Remote Services to Wazuh.

## Source mapping

| MP SIEM ID | MP SIEM rule | Wazuh IDs | Coverage |
|---|---|---:|---|
| PT-CR-472 | External_VPN_Service_Usage | 110400-110403 | ESP, IPsec/IKE, OpenVPN, L2TP and PPTP flows to external addresses |
| PT-CR-1937 | SMB_RPC_Internet_Connection | 110410-110413 | Sysmon 3 and Windows Security 5156 for SMB/RPC ports to or from external addresses |
| PT-CR-1783 | Owa_Abnormal_Access | 110420-110422 | Successful OWA access from external clients |
| PT-CR-1036 | Mail_Abnormal_Access | 110430-110432 | Successful Exchange ActiveSync POST with DeviceId |
| PT-CR-1787 | MFA_Abnormal_Access | 110440-110441 | Successful MFA responses and repeated successes from different external IPs |
| PT-CR-1056 | VPN_MultiUser_IP | 110450-110453 | Multiple VPN users authenticating from the same external IP |
| PT-CR-2653 | Duplicate_Remote_Session | 110460-110461 | Duplicated remote sessions from normalized VPN/Windows events |
| PT-CR-427 | Connect_To_Significant_Hosts_From_VPN | 110470 | Broad VPN/firewall-to-internal selector that must be tuned with local VPN pools and significant hosts |

The local `knowledgebase_2025_04_10` export did not contain `PT-CR-1058`, `PT-CR-1048`, or `PT-CR-1055`, so they are not implemented in this file.

## Prerequisites

- Wazuh manager 4.14 or compatible.
- Windows agents collecting:
  - `Microsoft-Windows-Sysmon/Operational` with Sysmon Event ID 3 for network connections.
  - Windows `Security` Event ID 5156 if Windows Filtering Platform coverage is desired.
- IIS/Exchange access logs decoded into either the standard IIS fields (`url`, `method`, `status`, `user`, `srcip`) or MP-style normalized JSON fields.
- VPN, firewall, MFA and remote access logs decoded as JSON with fields matching the MP-style names used in the XML, such as `event_src.title`, `src.ip`, `dst.ip`, `subject.account.name`, `object.account.name`, `external_src.ip`.

## Installation

1. Copy `external_remote_services_t1133_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh manager.
2. Validate representative raw events with `/var/ossec/bin/wazuh-logtest`.
3. Restart the manager with `systemctl restart wazuh-manager`.

## Porting notes

- MP SIEM profile checks such as `Risk_User_Logon_Correlation_Profile`, `Auto_Profile`, `Check_Profile`, `CheckWL_Profiling`, `CheckWL_Networking`, `VPN_Networks`, and `Significant_Networks` have no direct Wazuh XML equivalent.
- Rules 110441, 110452 and 110453 use Wazuh `frequency/timeframe` with `same_field` and `different_field` as practical approximations for selected profile anomalies.
- Rule 110470 is intentionally low level and marked with `needs_tuning`; replace its broad private-address conditions with local VPN pool and significant-host logic before using it as a high-severity alert.
- The IIS rules depend heavily on local decoder field names. If your IIS decoder stores the URI in another field, change `url` or the MP-style `object.path/object.fullpath` conditions accordingly.
- Add environment-specific allowlists as narrow negated `<field>` conditions, or move high-volume allowlists into CDB lists after confirming the final decoded fields.

