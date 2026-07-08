# WMI subscription detections for Wazuh 4.14

`wmi_subscription_t1546_003_rules.xml` ports the requested MaxPatrol SIEM rule family to Wazuh. The primary technique is MITRE ATT&CK T1546.003 (Windows Management Instrumentation Event Subscription).

## Rule mapping

| Wazuh ID | MaxPatrol rule | Detection |
|---|---|---|
| 110230 | PT-CR-272 `WMI_Subscriptions` | Sysmon 19/20/21 subscription component changed |
| 110231 | PT-CR-2774 `WMI_Subscription_Creation` | Component operation is `Created` |
| 110232–110233 | PT-CR-1095 `LiquidSnake_WMI_EventFilter` | `Win32_LogonSession` filter plus DCOM-launched `scrcons.exe` within 3 minutes |
| 110234 | PT-CR-1096 `Deserialization_Payload_WMI_Subscription` | `VBScript` consumer event containing `AAEAAAD//` |
| 110235 | PT-CR-2773 `WMI_Subscription_Execution` | Process launched by `WmiPrvSE.exe` or `scrcons.exe` |
| 110236 | PT-CR-2449 `WMEye_Event_Filter_Creation` | MSBuild starts within 3 minutes of subscription creation on the same agent |
| 110237 | PT-CR-2450 `WMEye_Execution` | WMI infrastructure directly launches MSBuild |

## Prerequisites

Configure Sysmon to collect:

- Event IDs 19, 20 and 21 (`WmiEventFilter`, `WmiEventConsumer`, and `WmiEventConsumerToFilter`).
- Event ID 1 with `Image`, `CommandLine`, `ParentImage`, and `ParentCommandLine`.

The Wazuh agent must collect `Microsoft-Windows-Sysmon/Operational`. Rule 110234 additionally requires the Windows `Application` channel and a decoded event containing `win.system.message`.

Install the XML in `/var/ossec/etc/rules/`, validate representative raw events with `/var/ossec/bin/wazuh-logtest`, and then restart `wazuh-manager`.

## Important porting limitations

- Exact source definitions were available locally for PT-CR-1095, PT-CR-272 and PT-CR-1096. PT-CR-2773, PT-CR-2774, PT-CR-2449 and PT-CR-2450 were absent from the supplied MaxPatrol knowledge-base snapshot; their Wazuh implementations are behavior-based reconstructions from the descriptions.
- Wazuh XML correlation can relate prior alerts to a current event by time window and agent (`same_location`), but it cannot reproduce MaxPatrol's arbitrary multi-event joins and enrichment objects. The LiquidSnake rule therefore preserves the distinctive filter query and DCOM process chain but does not require the intermediate network-logon event.
- Rules 110235 and 110236 are intentionally broad and require tuning. Legitimate WMI consumers and build automation can produce matching process chains.
- MaxPatrol allowlist functions such as `CheckWL_Specific_Only` have no automatic XML equivalent. Add narrow exclusions for known subscription names, queries, consumers, accounts, and approved MSBuild command lines after observing local baselines.
- If Event ID 2 does not expose its text as `win.system.message` in your environment, capture one raw event and adjust rule 110234 to the actual decoded `win.eventdata.*` field.
