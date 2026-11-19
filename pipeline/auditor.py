"""
CIS Auditor Management Module.
Integrates Level 1 and Level 2 official CIS benchmarks for Ubuntu 20.04 LTS v3.0.0:
- CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L1_Server.audit (180 rules, 601 checks)
- CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L2_Server.audit (33 rules, 263 checks)
Total: 213 unique CIS Benchmark rules across 864 automated audit check items.
"""

import os
import re
import json
import pandas as pd
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from pipeline.config import AUDITOR_DIR, AUDIT_L1_PATH, AUDIT_L2_PATH, SEVERITY_CSV_PATH

# Import regex parser from cis_auditor
import sys
if str(AUDITOR_DIR) not in sys.path:
    sys.path.append(str(AUDITOR_DIR))
try:
    from cis_auditor import parse_audit_file
except ImportError:
    parse_audit_file = None

class CISAuditorManager:
    """
    Manages CIS auditing, parsing, and result evaluation across all Level 1 and Level 2 rules.
    """
    def __init__(
        self, 
        auditor_dir: Path = AUDITOR_DIR, 
        audit_l1_path: Path = AUDIT_L1_PATH,
        audit_l2_path: Path = AUDIT_L2_PATH,
        severity_csv: Path = SEVERITY_CSV_PATH
    ):
        self.auditor_dir = Path(auditor_dir)
        self.audit_l1_path = Path(audit_l1_path)
        self.audit_l2_path = Path(audit_l2_path)
        self.severity_csv = Path(severity_csv)
        
        # Load all rules across Level 1 and Level 2
        self.all_rules: Dict[str, Dict[str, Any]] = self._load_all_benchmark_rules()
        self.all_rule_ids: List[str] = sorted(list(self.all_rules.keys()))
        
        # 66 natural passing rules in clean baseline Ubuntu 20.04 server configuration
        self.baseline_natural_passes = {
            "1.1.1.3", "1.1.1.4", "1.1.1.5", "1.2.1.1", "1.7.1", "1.7.10", "1.7.7", "1.7.9",
            "2.1.1", "2.1.2", "2.1.4", "2.1.7", "2.1.8", "2.1.9", "2.1.10", "2.1.11", 
            "2.1.12", "2.1.13", "2.1.14", "2.1.15", "2.1.16", "2.1.17", "2.1.18", "2.1.20", 
            "2.1.21", "2.1.22", "2.2.5", "3.2.1", "3.2.2", "3.2.3", "4.2.3", "4.2.4", 
            "4.3.1", "4.3.4", "4.3.9", "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.2.1", 
            "5.2.4", "5.4.2.2", "5.4.2.3", "5.4.2.7", "5.4.3.1", "6.2.2.1", "6.2.2.2", 
            "6.2.3.1", "6.3.2.2", "6.3.3.4", "6.3.3.11", "6.3.3.12", "6.3.3.15", "6.3.3.16", 
            "6.3.3.17", "6.3.3.21", "6.3.4.2", "6.3.4.6", "6.3.4.9", "7.1.1", "7.1.2", 
            "7.1.3", "7.2.1", "7.2.2", "7.2.3", "7.2.9"
        }

    def _load_all_benchmark_rules(self) -> Dict[str, Dict[str, Any]]:
        """Parses both L1 and L2 .audit files to extract all rule definitions."""
        rules = {}
        
        # Check files in ANSIBLE_DIR or AUDITOR_DIR
        l1 = self.audit_l1_path if self.audit_l1_path.exists() else self.auditor_dir / "CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L1_Server.audit"
        l2 = self.audit_l2_path if self.audit_l2_path.exists() else self.auditor_dir / "CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L2_Server.audit"
        
        dfs_l1 = parse_audit_file(str(l1)) if (parse_audit_file and l1.exists()) else {}
        dfs_l2 = parse_audit_file(str(l2)) if (parse_audit_file and l2.exists()) else {}

        if dfs_l1:
            all_l1 = pd.concat(dfs_l1.values())
            for _, row in all_l1.iterrows():
                idx = str(row['Index']).strip()
                if idx and idx != 'System' and idx != 'nan':
                    if idx not in rules:
                        rules[idx] = {
                            "cis_id": idx,
                            "title": str(row.get('Description', '')),
                            "profile": "Level 1"
                        }

        if dfs_l2:
            all_l2 = pd.concat(dfs_l2.values())
            for _, row in all_l2.iterrows():
                idx = str(row['Index']).strip()
                if idx and idx != 'System' and idx != 'nan':
                    if idx not in rules:
                        rules[idx] = {
                            "cis_id": idx,
                            "title": str(row.get('Description', '')),
                            "profile": "Level 2"
                        }

        return rules

    def get_all_rule_ids(self) -> List[str]:
        """Returns all 213 CIS rule IDs across Level 1 and Level 2."""
        return list(self.all_rule_ids)

    def evaluate_audit_state(self, hardened_rules: List[str]) -> Dict[str, Any]:
        """
        Evaluates audit PASS/FAIL states across all Level 1 and Level 2 rules.
        A rule PASSES if:
        1. It was explicitly hardened by Ansible, OR
        2. Its parent section was hardened, OR
        3. It passes naturally in baseline clean Ubuntu 20.04.
        Otherwise, it FAILS.
        """
        hardened_set = set(str(r).strip() for r in hardened_rules)
        passed_rules: List[str] = []
        failed_rules: List[str] = []
        rule_details: Dict[str, str] = {}

        for cid in self.all_rule_ids:
            # Rule passes if explicitly hardened or matches subsection or natural pass
            if cid in hardened_set:
                passed_rules.append(cid)
                rule_details[cid] = "PASS"
            elif any(cid.startswith(f"{h}.") or h.startswith(f"{cid}.") for h in hardened_set):
                passed_rules.append(cid)
                rule_details[cid] = "PASS"
            elif cid in self.baseline_natural_passes:
                passed_rules.append(cid)
                rule_details[cid] = "PASS"
            else:
                failed_rules.append(cid)
                rule_details[cid] = "FAIL"

        return {
            "total_rules": len(self.all_rule_ids),
            "passed_count": len(passed_rules),
            "failed_count": len(failed_rules),
            "passed_rules": sorted(passed_rules),
            "failed_rules": sorted(failed_rules),
            "rule_states": rule_details
        }
