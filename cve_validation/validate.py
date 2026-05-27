"""CVE Validation -- checks whether Wazuh-flagged CVEs actually apply.

Wazuh flags kernel CVEs aggressively based on package version matching.
Many of these are false positives -- the CVE's affected version range
doesn't include the running kernel version. This module validates each
flagged CVE against the NVD API and generates override rules for
confirmed false positives.

Key behaviors:
- Queries NVD API for affected version ranges
- Compares against the actual running kernel version on each host
- Generates Wazuh local_rules.xml overrides (level 0) for false positives
- Never modifies the default Wazuh ruleset -- only appends custom rules
"""

import json
import os
import re
import subprocess
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIEM_HOST = os.environ.get("SIEM_HOST", "your-siem-host")
SSH_USER = os.environ.get("SSH_USER", "your-ssh-user")
SSH_KEY_PATH = Path(os.environ.get("SSH_KEY_PATH", "~/.ssh/id_ed25519")).expanduser()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

STATE_DIR = Path(__file__).resolve().parent.parent / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_FILE = STATE_DIR / "cve_validation_results.json"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CVEValidationResult:
    cve_id: str
    host: str
    running_version: str
    affected_range: str
    is_false_positive: bool
    reasoning: str
    validated_at: str = ""

    def __post_init__(self):
        if not self.validated_at:
            self.validated_at = datetime.now().isoformat()

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "host": self.host,
            "running_version": self.running_version,
            "affected_range": self.affected_range,
            "is_false_positive": self.is_false_positive,
            "reasoning": self.reasoning,
            "validated_at": self.validated_at,
        }


# ---------------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------------

def fetch_cve_details(cve_id: str) -> Optional[dict]:
    """Fetch CVE details from the NVD API.

    Args:
        cve_id: CVE identifier (e.g., CVE-2026-31461).

    Returns:
        NVD vulnerability dict, or None on failure.
    """
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "siem-automation-cve-validator/1.0")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"[CVE] Failed to fetch {cve_id}: {e}")
    return None


def extract_affected_versions(cve_data: dict) -> list:
    """Extract affected version ranges from NVD CVE data."""
    affected = []
    configurations = cve_data.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    entry = {
                        "criteria": match.get("criteria", ""),
                        "version_start": match.get("versionStartIncluding", ""),
                        "version_end": match.get("versionEndExcluding",
                                       match.get("versionEndIncluding", "")),
                    }
                    affected.append(entry)
    return affected


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def parse_version(version_str: str) -> tuple:
    """Parse a version string into comparable tuple of integers."""
    parts = re.findall(r'\d+', version_str)
    return tuple(int(p) for p in parts)


def version_in_range(running: str, start: str, end: str) -> bool:
    """Check if a running version falls within an affected range."""
    try:
        running_v = parse_version(running)
        if start:
            start_v = parse_version(start)
            if running_v < start_v:
                return False
        if end:
            end_v = parse_version(end)
            if running_v >= end_v:
                return False
        return True
    except (ValueError, IndexError):
        # If we can't parse, assume it might be affected (safe default)
        return True


# ---------------------------------------------------------------------------
# Host version detection
# ---------------------------------------------------------------------------

def get_host_kernel_version(host: str) -> Optional[str]:
    """Get the running kernel version from a remote host via SSH."""
    cmd = [
        "ssh",
        "-i", str(SSH_KEY_PATH),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"{SSH_USER}@{host}",
        "uname -r",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_cve(cve_id: str, host: str) -> Optional[CVEValidationResult]:
    """Validate whether a CVE actually affects a specific host.

    Args:
        cve_id: CVE identifier.
        host: Target hostname or IP.

    Returns:
        CVEValidationResult with determination and reasoning.
    """
    running_version = get_host_kernel_version(host)
    if not running_version:
        return CVEValidationResult(
            cve_id=cve_id,
            host=host,
            running_version="unknown",
            affected_range="unknown",
            is_false_positive=False,
            reasoning="Could not determine running kernel version via SSH",
        )

    cve_data = fetch_cve_details(cve_id)
    if not cve_data:
        return CVEValidationResult(
            cve_id=cve_id,
            host=host,
            running_version=running_version,
            affected_range="unknown",
            is_false_positive=False,
            reasoning="Could not fetch CVE data from NVD API",
        )

    affected_versions = extract_affected_versions(cve_data)
    if not affected_versions:
        return CVEValidationResult(
            cve_id=cve_id,
            host=host,
            running_version=running_version,
            affected_range="no version data in NVD",
            is_false_positive=False,
            reasoning="NVD entry has no version range data -- manual review needed",
        )

    for entry in affected_versions:
        start = entry.get("version_start", "")
        end = entry.get("version_end", "")
        if version_in_range(running_version, start, end):
            return CVEValidationResult(
                cve_id=cve_id,
                host=host,
                running_version=running_version,
                affected_range=f"{start} - {end}",
                is_false_positive=False,
                reasoning=f"Running version {running_version} falls within "
                          f"affected range {start}-{end}",
            )

    # Not in any affected range -- false positive
    ranges_str = "; ".join(
        f"{e.get('version_start', '?')}-{e.get('version_end', '?')}"
        for e in affected_versions
    )
    return CVEValidationResult(
        cve_id=cve_id,
        host=host,
        running_version=running_version,
        affected_range=ranges_str,
        is_false_positive=True,
        reasoning=f"Running version {running_version} is outside all "
                  f"affected ranges: {ranges_str}",
    )


# ---------------------------------------------------------------------------
# Wazuh rule generation
# ---------------------------------------------------------------------------

def generate_suppression_rule(cve_id: str, rule_id: int, description: str) -> str:
    """Generate a Wazuh local_rules.xml override to suppress a false positive.

    Uses level 0 suppression in the custom rule range (100100+).
    Never modifies the default ruleset -- appends to local_rules.xml.
    """
    return f"""  <rule id="{rule_id}" level="0">
    <if_sid>23505</if_sid>
    <field name="vulnerability.cve">{cve_id}</field>
    <description>{description}</description>
  </rule>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Example validation
    print("CVE Validation Module")
    print("Usage: validate_cve('CVE-2026-XXXXX', 'hostname')")
    print()
    print("This module validates Wazuh-flagged CVEs against the NVD API")
    print("and generates suppression rules for confirmed false positives.")
