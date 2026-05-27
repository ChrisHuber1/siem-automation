"""Alerting module -- sends push notifications via ntfy.

ntfy (https://ntfy.sh) is a simple HTTP-based pub-sub notification service.
This module handles sending alerts with priority levels and cooldown tracking
to prevent notification spam from cron-scheduled checks.
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "your-ntfy-topic")
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh")

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
COOLDOWN_FILE = STATE_DIR / "alert_cooldown.json"

# One alert per agent per hour to prevent spam from cron runs
COOLDOWN_SECONDS = 3600


# ---------------------------------------------------------------------------
# Cooldown tracking
# ---------------------------------------------------------------------------

def _load_cooldowns() -> dict:
    try:
        if COOLDOWN_FILE.exists():
            return json.loads(COOLDOWN_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_cooldowns(cooldowns: dict):
    try:
        COOLDOWN_FILE.write_text(json.dumps(cooldowns, indent=2))
    except OSError:
        pass


def _is_in_cooldown(agent_name: str = "default") -> bool:
    """Check if an agent is within its cooldown window."""
    cooldowns = _load_cooldowns()
    last_sent = cooldowns.get(agent_name)
    if not last_sent:
        return False
    try:
        last_dt = datetime.fromisoformat(last_sent)
        elapsed = (datetime.now() - last_dt).total_seconds()
        return elapsed < COOLDOWN_SECONDS
    except (ValueError, TypeError):
        return False


def _record_alert(agent_name: str = "default"):
    """Record that an alert was sent for cooldown tracking."""
    cooldowns = _load_cooldowns()
    cooldowns[agent_name] = datetime.now().isoformat()
    _save_cooldowns(cooldowns)


def clear_cooldown(agent_name: str = "default"):
    """Clear cooldown for an agent (e.g., after all services recover)."""
    cooldowns = _load_cooldowns()
    cooldowns.pop(agent_name, None)
    _save_cooldowns(cooldowns)


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def send_alert(
    title: str,
    message: str,
    priority: str = "default",
    tags: list = None,
    agent_name: str = "default",
    force: bool = False,
) -> bool:
    """Send a push notification via ntfy.

    Args:
        title: Notification title.
        message: Notification body text.
        priority: ntfy priority level (min, low, default, high, urgent).
        tags: Optional list of emoji tags (e.g., ["warning", "rotating_light"]).
        agent_name: Agent identifier for cooldown tracking.
        force: If True, bypass cooldown check.

    Returns:
        True if the notification was sent successfully.
    """
    if not force and _is_in_cooldown(agent_name):
        return False

    url = f"{NTFY_SERVER}/{NTFY_TOPIC}"
    headers = {
        "Title": title,
        "Priority": priority,
    }
    if tags:
        headers["Tags"] = ",".join(tags)

    try:
        req = urllib.request.Request(
            url,
            data=message.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                _record_alert(agent_name)
                return True
    except (urllib.error.URLError, OSError) as e:
        # Log but don't crash -- alerting failure shouldn't stop the watchdog
        print(f"[ntfy] Failed to send alert: {e}")

    return False


# ---------------------------------------------------------------------------
# Windows SAPI voice alert (optional, requires pyttsx3)
# ---------------------------------------------------------------------------

def speak_alert(message: str = "Attention: SIEM alert requires review"):
    """Play an audible alert via Windows text-to-speech (optional)."""
    try:
        import pyttsx3
        engine = pyttsx3.init()
        engine.say(message)
        engine.runAndWait()
    except ImportError:
        pass  # pyttsx3 not installed -- skip voice alert
    except Exception:
        pass  # SAPI not available (e.g., running on Linux)


if __name__ == "__main__":
    # Quick test -- sends a test notification
    sent = send_alert(
        title="Test Alert",
        message="SIEM automation alerting is working.",
        priority="low",
        tags=["white_check_mark"],
        force=True,
    )
    print(f"Alert sent: {sent}")
