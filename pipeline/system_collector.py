"""
System-Level Metric and Vulnerability Collector.
Collects or derives realistic system telemetry:
- hours_since_last_patch
- critical_vulns, high_vulns, total_vulns
- os_type (0 = Linux, 1 = Other OS)
"""

import random
from typing import Dict, Any, Optional
from pipeline.config import OS_TYPE_LINUX

class SystemTelemetryCollector:
    """
    Collects system security telemetry matching empirical server distributions.
    Correlates patch age in hours with vulnerability growth according to CVE publication rates.
    """
    def __init__(self, os_type: int = OS_TYPE_LINUX, exact_os_name: str = "Ubuntu 20.04 LTS"):
        self.os_type = os_type
        self.exact_os_name = exact_os_name

    def generate_telemetry(
        self,
        seed: Optional[int] = None,
        patch_age_hours: Optional[int] = None,
        patch_age_days: Optional[int] = None,
        sev_counts: Optional[Dict[str, int]] = None,
        failed_rules_count: Optional[int] = None,
        is_anomalous: bool = False
    ) -> Dict[str, Any]:
        """
        Generates consistent system-level telemetry.
        If sev_counts is provided, critical_vulns, high_vulns, and total_vulns are derived
        directly and authoritatively from the CIS annotated rules mapping.
        """
        rng = random.Random(seed)

        if is_anomalous:
            # Anomalous state: patch neglect or extreme exposure
            hours_since_patch = rng.randint(720, 1440)  # 30 to 60 days
            crit_vulns = rng.randint(15, 30)
            high_vulns = rng.randint(35, 60)
            total_vulns = crit_vulns + high_vulns + rng.randint(40, 80)
        else:
            if patch_age_hours is not None:
                hours_since_patch = max(1, patch_age_hours)
            elif patch_age_days is not None:
                hours_since_patch = max(1, patch_age_days * 24)
            else:
                # Clean realistic maintenance distribution (in hours):
                # 70% well-maintained (12 - 168 hours, half day to 1 week),
                # 30% moderately delayed (192 - 720 hours, 8 to 30 days)
                tier = rng.random()
                if tier < 0.70:
                    hours_since_patch = rng.randint(12, 168)
                else:
                    hours_since_patch = rng.randint(192, 720)

            # If authoritative audit severities are provided, derive vulnerabilities directly
            if sev_counts is not None:
                crit_vulns = sev_counts.get("Critical", 0)
                high_vulns = sev_counts.get("High", 0)
                total_vulns = failed_rules_count if failed_rules_count is not None else sum(sev_counts.values())
            else:
                # Correlated fallback
                base_crit_rate = max(1, hours_since_patch / 72.0)
                crit_vulns = max(0, int(rng.gauss(base_crit_rate, 0.8)))
                base_high_rate = max(1, hours_since_patch / 36.0)
                high_vulns = max(crit_vulns, int(rng.gauss(base_high_rate, 1.5)))
                total_vulns = crit_vulns + high_vulns + max(0, int(hours_since_patch / 18.0))

        return {
            "exact_os_name": self.exact_os_name,
            "os_type": self.os_type,
            "hours_since_last_patch": int(hours_since_patch),
            "critical_vulns": int(crit_vulns),
            "high_vulns": int(high_vulns),
            "total_vulns": int(total_vulns)
        }
