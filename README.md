# SIEM Automation

Automated monitoring, triage, and alerting for a Wazuh SIEM deployment. Built after my Wazuh manager crashed and stayed down for 3 days without anyone noticing ;  including me.

The system has three parts: a watchdog that detects and auto-restarts failed SIEM services, an AI-powered triage bot that classifies alerts and sends daily reports, and a CVE validation pipeline that checks whether flagged vulnerabilities actually apply to the affected hosts.

## Why This Exists

I run Wazuh across a home lab with multiple Linux hosts. In May 2026, the Wazuh manager crashed after a reboot ;  stale PID files in `/var/ossec/var/run/` prevented the service from restarting. No alerts were generated because the system that generates alerts was the thing that was down.

I found out 3 days later when I happened to check manually. That's unacceptable.

## Components

### 1. SIEM Watchdog

Runs on a cron schedule, SSHs into the SIEM host, and checks Wazuh service health.

- Detects stale PID files and clears them before restart
- Auto-restarts crashed services (max 2 attempts per 24 hours to avoid restart loops)
- Successful restart = HIGH finding; failed restart = CRITICAL + phone notification
- Tracks restart attempts in a JSON state file so it doesn't retry endlessly

### 2. AI Triage Bot

Fetches recent Wazuh alerts over SSH, classifies them with Claude, and sends a daily summary.

- Pre-flight health check: if the Wazuh manager is down, sends an urgent alert immediately instead of trying to fetch alerts from a dead service
- Zero alerts + healthy manager gets flagged as anomalous (not "quiet day")
- SSH failures are handled gracefully ;  no more crashes from unreachable hosts
- Sends reports via ntfy push notification

### 3. CVE Validation

Wazuh flags kernel CVEs aggressively. Most of them don't actually apply to the running kernel version.

- Pulls flagged CVEs from Wazuh alerts
- Checks each one against the NVD API for affected version ranges
- Compares against the actual running kernel version on each host
- Generates a report: confirmed real vs. false positive, with reasoning
- False positives get Wazuh rule overrides (level 0 suppression) so they stop generating alerts

**Example finding:** Wazuh flagged CVE-2026-31461 on a host running kernel 6.8. The NVD affected range starts at 6.13. That's a false positive ;  the host isn't running a vulnerable version. Added a suppression rule.

### 4. Alerting

- ntfy push notifications on all CRITICAL findings
- File-based cooldown (1 hour per agent) to prevent alert spam from cron runs
- Audible "Master we need your input" via Windows SAPI for human-in-the-loop decisions

## Decisions and Tradeoffs

**ntfy over PagerDuty/Slack:** This is a home lab, not an enterprise. ntfy is free, self-hostable, and I can subscribe on my phone in 30 seconds. PagerDuty is overkill. Slack requires a workspace. ntfy just works.

**File-based cooldown over rate limiting:** A rate limiter would be more elegant, but a file with a timestamp is debuggable. I can see when the last alert fired by reading a file. If cooldown breaks, I can fix it by deleting a file.

**Max 2 restarts per 24 hours:** Infinite restart loops are worse than a down service. If the service won't stay up after 2 attempts, something is fundamentally wrong and a human needs to look at it.

**Claude for triage, not for detection:** Wazuh handles detection. Claude classifies and prioritizes the results. Using an LLM for detection would miss the rule-based patterns that Wazuh is purpose-built for.

**Custom Wazuh rules over modifying defaults:** False positive overrides use custom rules (100100+ range) in `local_rules.xml`, never modifications to the default ruleset. This survives Wazuh upgrades and makes it easy to see exactly what's been tuned.

## False Positive Tuning

| Rule ID | What It Suppresses | Why |
|---|---|---|
| 100101 | Root SSH from ops host | Cron jobs SSH as root for health checks ;  not unauthorized access |
| 100160 | CVE-2026-31461 | NVD affected range starts at 6.13; host runs 6.8 |
| 100170 | Sudo alerts on SIEM host | Cloud-init gives the service account NOPASSWD ALL by default |

## Architecture

```
Cron (hourly)
    |
    v
+-------------------+        +------------------+
| SIEM Watchdog     |--SSH-->| SIEM Host        |
| (check health,    |        | (Wazuh manager)  |
|  auto-restart)    |        +------------------+
+-------------------+
    |
    v (findings)
+-------------------+        +------------------+
| Triage Bot        |--SSH-->| Wazuh API        |
| (Claude classify, |        | (fetch alerts)   |
|  daily report)    |        +------------------+
+-------------------+
    |
    v (alerts)
+-------------------+
| ntfy push         |---->  Phone notification
| Windows SAPI      |---->  Audible alert
+-------------------+
```

## Current State

Running in production on my home lab. The watchdog has caught and auto-resolved two Wazuh manager crashes since deployment. CVE validation eliminated 10 false critical alerts per scan cycle. The triage bot sends daily summaries to my phone.

## What I'd Do Differently

- Add Prometheus metrics for SIEM health instead of relying solely on the SSH-based check. Would give me historical uptime data and alerting integration with Grafana.
- The CVE validation could cache NVD responses to avoid repeated API calls for the same CVE across scan cycles.
