# Honeypot #2: Wazuh detection rules

Honeypot #2 is a real Debian 12 server (`web01`) on Google Cloud with a bait account, next to a gateway that
runs the Wazuh manager (4.14.10). The two talk only over WireGuard, and every other outbound connection from
the victim is blocked. Wazuh alerts go to Microsoft Sentinel's `Hp2Wazuh_CL` table. Its first real intrusion is
written up as [INC-001](https://uig.me/writing/inc-001/).

These rules are Wazuh XML, not Sigma, and they sit outside the
[uig-detections](https://github.com/estul-lachin/uig-detections) pipeline. That pipeline reads Honeypot #1's
Cowrie and Suricata logs. Sentinel only gets Wazuh's *alerts* from this host, not the raw sshd and FIM events
these rules match. Most of these rules exist because of a real intrusion, and each one was checked against
real or self-made events, as listed below.

[`wazuh/local_rules.xml`](wazuh/local_rules.xml) is a copy of the gateway's `/var/ossec/etc/rules/local_rules.xml`,
without Wazuh's sample rule. Change it on the gateway, check with `wazuh-logtest`, restart the manager, then
update this copy.

| ID | Level | Fires on | ATT&CK | Verified by |
|---|---|---|---|---|
| 100200 | 12 | The victim probing the gateway through the tunnel (nftables log prefix `VICTIM-`). Triggers isolation. | T1046 | Test at deployment |
| 100201 | 6 | A victim outbound connection dropped by the host nftables tripwire (prefix `HP2-OUT-DROP`) | | Real attack traffic (INC-001) |
| 100210 | 13 | `admin` logs in with `Accepted password` or `Accepted keyboard-interactive`, with or without failures first (`if_sid` 5715) | T1078, T1110.001 | `wazuh-logtest`: both log formats. The first version matched only `Accepted password` and missed the real attack, which used keyboard-interactive. |
| 100211 | 12 | Any add, change or delete under `/var/spool/cron` or `/etc/cron*` (`if_sid` 550/553/554) | T1053.003 | Fired on the attacker's cron writes at 02:41 and 02:43 UTC; self-test with `touch`/`rm` |
| 100212 | 12 | Any file change under `/home/admin/` (FIM with whodata, so the alert names the process and user) | T1105 | Self-test with `touch`/`rm` |
| 100213 | 13 | `admin` logs in with `Accepted publickey`: the attacker's planted key being used | T1098.004, T1078 | `wazuh-logtest` on the real log line: 118[.]36[.]203[.]94 logged in with the key 17 seconds after writing it |

Rules 100210-100213 were added during INC-001 to close the gaps it exposed (see the report's
*Detection improvements*). Rule 40112, which caught the intrusion, fires only when failures come before a
success. An attacker who already has the password produces only rule 5715 at level 3.

## Sentinel

One scheduled analytics rule on `Hp2Wazuh_CL` raises incidents from these alerts. Its query is
[`sentinel/hp2-wazuh-high.kql`](sentinel/hp2-wazuh-high.kql). It runs every 15 minutes on `rule_level >= 12` and
groups each run's alerts by source IP, agent and rule. IP and Host are its entities, and level 13 and above is High. Each run reads what was
*ingested* in its window: `ingestion_time() > ago(15m) and ingestion_time() <= now()`. Both bounds are needed.
Sentinel can start a run up to 5 minutes after its window ends, with `now()` set to the window's end. With only
the lower bound, events ingested in those minutes were alerted twice (uig-detections' README has the details).

Since 2026-11-14 15:36 UTC the gateway's uploader (`hp2_sentinel.py`) sends at most one rule 100201 alert per
destination IP:port per hour, so 100201 counts in Sentinel after that are not attempt counts; the full numbers are in
the gateway's Wazuh alerts (`/var/ossec/logs/alerts/`, rotated daily). Alerts at level 10 or higher are always
uploaded, even after the 20 MB daily budget is used up.

Level 12 is the threshold instead of 10 because rule 2502 (level 10) fires about every 7 minutes from constant
scanning.
