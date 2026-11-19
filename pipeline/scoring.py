"""
Severity Mapping, Compliance Score Calculation, and Risk Labeling Engine.
Treats cis_rules_annotated.csv as the authoritative source of truth.
Supports full Level 1 and Level 2 benchmark evaluation with configurable scoring weights.
"""

import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from pipeline.config import SEVERITY_CSV_PATH, DEFAULT_SCORING_WEIGHTS, RISK_THRESHOLD

class AuthoritativeSeverityMapper:
    """
    Authoritative severity mapper for CIS Benchmark rules.
    Prioritizes explicit OS annotations from cis_rules_annotated (1).csv,
    with hierarchical subsection fallback to guarantee 100% rule coverage.
    """
    def __init__(self, csv_path=SEVERITY_CSV_PATH):
        self.csv_path = str(csv_path)
        self.direct_map: Dict[str, Dict[str, Any]] = {}
        self.os_direct_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.prefix_map: Dict[str, Dict[str, Any]] = {}
        self.load_authoritative_csv()

    def load_authoritative_csv(self):
        df = pd.read_csv(self.csv_path)
        
        # Precedence: exact OS matches take priority
        def priority_score(os_str):
            os_clean = str(os_str).lower().strip()
            if "20.04" in os_clean or "ubuntu_20" in os_clean:
                return 3
            if "ubuntu" in os_clean or "windows" in os_clean:
                return 2
            return 1
            
        df['priority'] = df['os_version'].apply(priority_score)
        df_sorted = df.sort_values(by=['priority', 'cvss_base_score'], ascending=[True, True])

        for _, row in df_sorted.iterrows():
            cid = str(row['cis_id']).strip()
            os_ver = str(row['os_version']).strip().lower()
            sev = str(row['severity_label']).strip()
            score = row['cvss_base_score']
            if pd.isna(sev) or sev.lower() in ['nan', 'none', '']:
                if pd.notna(score):
                    sc = float(score)
                    if sc >= 9.0:
                        sev = "Critical"
                    elif sc >= 7.0:
                        sev = "High"
                    elif sc >= 4.0:
                        sev = "Medium"
                    else:
                        sev = "Low"
                else:
                    sev = "Medium"

            sev = sev.capitalize()
            if sev == "Crit":
                sev = "Critical"

            entry = {
                "severity": sev,
                "cvss_score": float(score) if pd.notna(score) else 0.0,
                "os_version": str(row['os_version']),
                "rule_title": str(row['rule_title'])
            }

            self.direct_map[cid] = entry
            self.os_direct_map[(os_ver, cid)] = entry

            parts = cid.split('.')
            for i in range(1, len(parts)):
                prefix = '.'.join(parts[:i])
                if prefix not in self.prefix_map or row['priority'] >= 3:
                    self.prefix_map[prefix] = {
                        "severity": sev,
                        "cvss_score": float(score) if pd.notna(score) else 0.0,
                        "source_prefix": prefix
                    }

    def get_severity(self, rule_id: str, target_os: Optional[str] = None, default_level: Optional[str] = "Level 1") -> Dict[str, Any]:
        """
        Resolves the severity of a CIS rule ID using multi-tier authoritative resolution.
        If target_os is provided, prioritizes annotations for that specific OS.
        """
        clean_id = str(rule_id).strip()

        # Tier 0: Direct match for specific target OS
        if target_os:
            os_key = str(target_os).strip().lower().replace('-', '_').replace(' ', '_')
            if (os_key, clean_id) in self.os_direct_map:
                match = self.os_direct_map[(os_key, clean_id)]
                return {
                    "rule_id": clean_id,
                    "severity": match["severity"],
                    "cvss_score": match["cvss_score"],
                    "resolution_tier": f"direct_os_match_{os_key}",
                    "os_version": match["os_version"]
                }

        # Tier 1: Direct match in authoritative CSV
        if clean_id in self.direct_map:
            match = self.direct_map[clean_id]
            return {
                "rule_id": clean_id,
                "severity": match["severity"],
                "cvss_score": match["cvss_score"],
                "resolution_tier": "direct_match",
                "os_version": match["os_version"]
            }

        # Tier 2: Hierarchical prefix match in authoritative CSV
        parts = clean_id.split('.')
        for i in range(len(parts) - 1, 0, -1):
            prefix = '.'.join(parts[:i])
            if target_os:
                os_key = str(target_os).strip().lower().replace('-', '_').replace(' ', '_')
                if (os_key, prefix) in self.os_direct_map:
                    match = self.os_direct_map[(os_key, prefix)]
                    return {
                        "rule_id": clean_id,
                        "severity": match["severity"],
                        "cvss_score": match["cvss_score"],
                        "resolution_tier": f"prefix_os_match_{prefix}",
                        "os_version": match["os_version"]
                    }
            if prefix in self.direct_map:
                match = self.direct_map[prefix]
                return {
                    "rule_id": clean_id,
                    "severity": match["severity"],
                    "cvss_score": match["cvss_score"],
                    "resolution_tier": f"prefix_match_{prefix}",
                    "os_version": match["os_version"]
                }
            if prefix in self.prefix_map:
                match = self.prefix_map[prefix]
                return {
                    "rule_id": clean_id,
                    "severity": match["severity"],
                    "cvss_score": match["cvss_score"],
                    "resolution_tier": f"prefix_branch_{prefix}",
                    "os_version": "hierarchical_csv"
                }

        # Tier 3: Benchmark level fallback
        fallback_sev = "High" if default_level and "2" in default_level else "Medium"
        return {
            "rule_id": clean_id,
            "severity": fallback_sev,
            "cvss_score": 7.0 if fallback_sev == "High" else 5.0,
            "resolution_tier": "benchmark_level_fallback",
            "os_version": "inferred"
        }


def calculate_compliance_score(
    failed_severities: Dict[str, int], 
    weights: Optional[Dict[str, float]] = None,
    base_score: float = 100.0,
    max_possible_penalty: Optional[float] = 813.0
) -> Tuple[float, Dict[str, float]]:
    """
    Calculates weighted compliance score according to the formula:
    Penalties = w_high * N_high/crit + w_medium * N_medium + w_low * N_low
    Normalized Score = 100 * (1 - Total_Penalties / Max_Possible_Penalty)
    Configurable weights support custom FYP research methodologies.
    """
    if weights is None:
        weights = DEFAULT_SCORING_WEIGHTS

    penalties = {}

    crit_high_count = failed_severities.get("High", 0) + failed_severities.get("Critical", 0)
    med_count = failed_severities.get("Medium", 0)
    low_count = failed_severities.get("Low", 0)

    w_high = weights.get("High", 5.0)
    w_med = weights.get("Medium", 0.5)
    w_low = weights.get("Low", 5.0)

    penalty_high = crit_high_count * w_high
    penalty_med = med_count * w_med
    penalty_low = low_count * w_low

    penalties["High_Critical"] = penalty_high
    penalties["Medium"] = penalty_med
    penalties["Low"] = penalty_low
    penalties["Total_Penalty"] = penalty_high + penalty_med + penalty_low

    if max_possible_penalty is not None and max_possible_penalty > 0:
        raw_score = base_score * (1.0 - (penalties["Total_Penalty"] / max_possible_penalty))
    else:
        raw_score = base_score - penalties["Total_Penalty"]

    final_score = max(0.0, min(100.0, round(raw_score, 2)))
    return final_score, penalties


def assign_risk_label(compliance_score: float, threshold: float = RISK_THRESHOLD) -> int:
    """
    Assigns binary risk label based on compliance score threshold.
    Compliance Score < 70 -> 1 (High Risk)
    Compliance Score >= 70 -> 0 (Normal/Low Risk)
    """
    return 1 if compliance_score < threshold else 0
