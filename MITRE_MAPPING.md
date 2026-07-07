# MITRE ATT&CK® Mapping

Every detection rule in [`detections/`](detections/) is mapped to the MITRE ATT&CK framework,
both inside the rule JSON (`threat` block, so Kibana renders it natively) and in
[`alert_consumer/enrich.py`](alert_consumer/enrich.py) (used by the triage CLI). A consistency
test in [`tests/test_enrich.py`](tests/test_enrich.py) fails CI if the two ever drift apart.

| Rule ID | Rule | Tactic | Technique | Sub-technique | Data Source |
|---------|------|--------|-----------|---------------|-------------|
| `edl-001-ssh-brute-force` | SSH Brute Force Attempts | Credential Access (TA0006) | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Linux `auth.log` |
| `edl-002-impossible-travel` | Impossible Travel Login | Initial Access (TA0001) | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | — | Windows Security 4624 |
| `edl-003-sudo-escalation` | Suspicious Sudo Privilege Escalation | Privilege Escalation (TA0004) | [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) | [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | Linux `auth.log` |
| `edl-004-web-shell` | Web Shell Request Pattern | Persistence (TA0003) | [T1505 Server Software Component](https://attack.mitre.org/techniques/T1505/) | [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/) | Nginx access logs |
| `edl-005-data-exfiltration` | Data Exfiltration via Unusual Outbound Volume | Exfiltration (TA0010) | [T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) | — | Nginx access logs |
| `edl-006-new-admin-account` | New Admin Account Creation | Persistence (TA0003) | [T1136 Create Account](https://attack.mitre.org/techniques/T1136/) ・ [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) | Windows Security 4720 + 4732 |

## Tactic coverage at a glance

```
Initial Access      ████ T1078   (edl-002)
Persistence         ████ T1505.003, T1136.001 (edl-004, edl-006)
Privilege Escalation████ T1548.003 (edl-003)
Credential Access   ████ T1110.001 (edl-001)
Exfiltration        ████ T1048   (edl-005)
```

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
