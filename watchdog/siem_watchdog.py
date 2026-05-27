"""SIEM Watchdog -- Wazuh services health, triage bot output, critical alert forwarding.

Monitors Wazuh manager, indexer, and dashboard services via SSH. Detects stale PID
files that prevent restart after crashes. Auto-restarts failed services with a
daily attempt limit to prevent restart loops.
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration -- override via environment variables or .env
# ---------------------------------------------------------------------------

SIEM_HOST = os.environ.get("SIEM_HOST", "your-siem-host")
SSH_USER = os.environ.get("SSH_USER", "your-ssh-user")
SSH_KEY_PATH = Path(os.environ.get("SSH_KEY_PATH", "~/.ssh/id_ed25519")).expanduser()

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
RESTART_STATE_FILE = STATE_DIR / "siem_restart_count.json"

MAX_RESTARTS_PER_DAY = 2
WAZUH_SERVICES = ["wazuh-manager", "wazuh-indexer", "wazuh-dashboard"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    severity: Severity
    source: str
    message: str
    details: str = ""
    host: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class WatchdogResult:
    success: bool
    findings: list = field(default_factory=list)
    summary: str = ""
    run_time: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [f if isinstance(f, dict) else f.to_dict()
                         for f in self.findings]
        return d

    @property
    def critical_count(self):
        return sum(1 for f in self.findings
                   if (f.severity if isinstance(f, Finding) else f.get("severity")) == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings
                   if (f.severity if isinstance(f, Finding) else f.get("severity")) == Severity.HIGH)

    def has_actionable(self):
        return self.critical_count > 0 or self.high_count > 0


# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def siem_ssh(command: str, timeout: int = 15) -> tuple:
    """SSH to the SIEM host and run a command. Returns (stdout, stderr, returncode)."""
    cmd = [
        "ssh",
        "-i", str(SSH_KEY_PATH),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        f"{SSH_USER}@{SIEM_HOST}",
        command,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        return r.stdout, r.stderr, r.returncode
    except Exception as e:
        return "", str(e), 1


# ---------------------------------------------------------------------------
# Restart state tracking
# ---------------------------------------------------------------------------

def _get_restart_counts() -> dict:
    try:
        if RESTART_STATE_FILE.exists():
            return json.loads(RESTART_STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_restart_counts(counts: dict):
    try:
        RESTART_STATE_FILE.write_text(json.dumps(counts, indent=2))
    except OSError:
        pass


def _reset_restart_counts():
    try:
        RESTART_STATE_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _can_restart(service: str) -> bool:
    counts = _get_restart_counts()
    entry = counts.get(service, {})
    count = entry.get("count", 0)
    first = entry.get("first_attempt", "")
    if count >= MAX_RESTARTS_PER_DAY and first:
        try:
            first_dt = datetime.fromisoformat(first)
            if (datetime.now() - first_dt).total_seconds() < 86400:
                return False
        except ValueError:
            pass
    return True


def _record_restart(service: str):
    counts = _get_restart_counts()
    entry = counts.get(service, {"count": 0, "first_attempt": ""})
    if entry["count"] == 0 or not entry.get("first_attempt"):
        entry["first_attempt"] = datetime.now().isoformat()
    entry["count"] = entry.get("count", 0) + 1
    entry["last_attempt"] = datetime.now().isoformat()
    counts[service] = entry
    _save_restart_counts(counts)


# ---------------------------------------------------------------------------
# Service checks
# ---------------------------------------------------------------------------

def _attempt_restart(service: str) -> tuple:
    """Clear stale PIDs and restart a Wazuh service. Returns (success, new_status)."""
    if not _can_restart(service):
        return False, "restart limit reached (2/day)"

    _record_restart(service)

    # Wazuh manager leaves stale PID files after unclean service stop
    if service == "wazuh-manager":
        siem_ssh("sudo rm -f /var/ossec/var/run/*.pid", timeout=10)

    siem_ssh(f"sudo systemctl restart {service}", timeout=30)
    time.sleep(5)

    stdout, _, rc = siem_ssh(f"systemctl is-active {service}", timeout=10)
    new_status = stdout.strip()
    return new_status == "active", new_status


def check_wazuh_services() -> list:
    """Check each Wazuh service and auto-restart if down."""
    findings = []
    for svc in WAZUH_SERVICES:
        stdout, stderr, rc = siem_ssh(
            f"systemctl is-active {svc} 2>/dev/null", timeout=10,
        )
        status = stdout.strip()

        if rc != 0 and not status:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source="siem_watchdog",
                message=f"Cannot reach SIEM host to check {svc}",
                details=stderr[:200],
                host="siem-host",
            ))
            continue

        if status == "active":
            findings.append(Finding(
                severity=Severity.INFO,
                source="wazuh_services",
                message=f"{svc}: active",
                host="siem-host",
            ))
            continue

        # Service is down -- attempt restart
        restarted, new_status = _attempt_restart(svc)
        if restarted:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="siem_watchdog",
                message=f"{svc} was DOWN ({status}), auto-restarted successfully",
                host="siem-host",
            ))
        else:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source="siem_watchdog",
                message=f"Wazuh service DOWN: {svc} ({status}). "
                        f"Auto-restart failed: {new_status}",
                host="siem-host",
            ))
    return findings


def check_recent_alerts() -> list:
    """Check recent Wazuh alert log for high-severity events."""
    findings = []
    stdout, stderr, rc = siem_ssh(
        "tail -100 /var/ossec/logs/alerts/alerts.log 2>/dev/null "
        "| grep -c 'level.*1[0-5]' || echo 0",
        timeout=10,
    )
    try:
        high_alerts = int(stdout.strip())
    except ValueError:
        high_alerts = 0

    if high_alerts > 20:
        findings.append(Finding(
            severity=Severity.HIGH,
            source="siem_watchdog",
            message=f"Wazuh: {high_alerts} high-severity alerts in recent log tail",
            host="siem-host",
        ))
    elif high_alerts > 0:
        findings.append(Finding(
            severity=Severity.INFO,
            source="siem_watchdog",
            message=f"Wazuh: {high_alerts} high-severity alerts (normal range)",
            host="siem-host",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_watchdog() -> WatchdogResult:
    """Execute a full watchdog check cycle."""
    start = time.time()
    findings = []

    findings.extend(check_wazuh_services())
    findings.extend(check_recent_alerts())

    svc_ok = sum(1 for f in findings if f.source == "wazuh_services" and f.severity == Severity.INFO)
    summary = f"{svc_ok}/{len(WAZUH_SERVICES)} services up"

    if svc_ok == len(WAZUH_SERVICES):
        _reset_restart_counts()

    result = WatchdogResult(
        success=True,
        findings=findings,
        summary=summary,
        duration_seconds=round(time.time() - start, 2),
    )

    # Save result to state
    result_path = STATE_DIR / "watchdog_result.json"
    try:
        result_path.write_text(json.dumps(result.to_dict(), indent=2))
    except OSError:
        pass

    # Alert on actionable findings
    if result.has_actionable():
        try:
            from alerting.ntfy_alert import send_alert
            send_alert(
                title="SIEM Watchdog Alert",
                message=summary,
                priority="urgent" if result.critical_count > 0 else "high",
            )
        except ImportError:
            print(f"[ALERT] {summary}")

    return result


if __name__ == "__main__":
    result = run_watchdog()
    print(f"Watchdog: {result.summary}")
    for f in result.findings:
        print(f"  [{f.severity.value}] {f.message}")
