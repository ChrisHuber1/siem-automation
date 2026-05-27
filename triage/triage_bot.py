"""AI Triage Bot -- classifies Wazuh alerts and generates daily summaries.

The full triage implementation runs on the SIEM host itself, where it has
direct access to Wazuh alert logs and the Wazuh API. This module provides
the classification logic and report generation.

Key behaviors:
- Pre-flight health check: if Wazuh manager is down, sends urgent alert
  immediately instead of trying to fetch alerts from a dead service
- Zero alerts + healthy manager gets flagged as anomalous (a silent SIEM
  is more suspicious than a noisy one)
- SSH failures are handled gracefully with retry and fallback alerting
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
SIEM_HOST = os.environ.get("SIEM_HOST", "your-siem-host")

ALERT_LOG_PATH = "/var/ossec/logs/alerts/alerts.json"
REPORT_DIR = Path(__file__).resolve().parent.parent / "state" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Alert classification
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    range(0, 4): "noise",
    range(4, 7): "low",
    range(7, 10): "medium",
    range(10, 13): "high",
    range(13, 16): "critical",
}


def classify_alert_level(wazuh_level: int) -> str:
    """Map Wazuh numeric alert level to a classification tier."""
    for level_range, classification in SEVERITY_MAP.items():
        if wazuh_level in level_range:
            return classification
    return "unknown"


def build_triage_prompt(alerts: list) -> str:
    """Build a Claude prompt for alert triage and classification.

    The prompt asks Claude to:
    1. Group alerts by category (auth, network, file integrity, etc.)
    2. Identify which alerts are actionable vs. noise
    3. Flag any patterns that suggest active threats
    4. Produce a summary suitable for a daily report
    """
    alert_text = json.dumps(alerts[:50], indent=2)  # Cap at 50 alerts
    return f"""You are a SOC analyst reviewing Wazuh SIEM alerts from the last 24 hours.

Analyze these alerts and produce a triage report:

1. **Critical/Actionable:** Alerts requiring immediate investigation
2. **Suspicious patterns:** Correlated events that suggest ongoing activity
3. **Noise/Expected:** Known benign activity (cron jobs, health checks, etc.)
4. **Recommendations:** Specific next steps for any actionable findings

Be concise. Flag false positives explicitly so they can be tuned.

Alerts:
{alert_text}
"""


def generate_daily_report(alerts: list, manager_healthy: bool) -> dict:
    """Generate a structured daily triage report.

    Args:
        alerts: List of Wazuh alert dicts from the last 24 hours.
        manager_healthy: Whether the Wazuh manager is running.

    Returns:
        Report dict with classification counts and summary.
    """
    if not manager_healthy:
        return {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "status": "URGENT",
            "message": "Wazuh manager is DOWN -- alerts are not being generated",
            "alert_count": 0,
            "action_required": True,
        }

    if not alerts:
        return {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "status": "ANOMALOUS",
            "message": "Zero alerts with healthy manager -- verify agent connectivity",
            "alert_count": 0,
            "action_required": True,
        }

    # Classify alerts by severity
    classifications = {}
    for alert in alerts:
        level = alert.get("rule", {}).get("level", 0)
        tier = classify_alert_level(level)
        classifications[tier] = classifications.get(tier, 0) + 1

    return {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "status": "OK" if not classifications.get("critical") else "ALERT",
        "alert_count": len(alerts),
        "breakdown": classifications,
        "action_required": classifications.get("critical", 0) > 0
                          or classifications.get("high", 0) > 5,
    }


def save_report(report: dict) -> Path:
    """Save the daily report to disk."""
    date_str = report.get("date", datetime.now().strftime("%Y-%m-%d"))
    path = REPORT_DIR / f"{date_str}.json"
    path.write_text(json.dumps(report, indent=2))
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Example: generate a report with sample data
    sample_alerts = [
        {"rule": {"level": 3, "description": "SSH auth success"}, "agent": {"name": "web01"}},
        {"rule": {"level": 10, "description": "Multiple auth failures"}, "agent": {"name": "db01"}},
        {"rule": {"level": 14, "description": "Rootkit detection"}, "agent": {"name": "app01"}},
    ]
    report = generate_daily_report(sample_alerts, manager_healthy=True)
    print(json.dumps(report, indent=2))
