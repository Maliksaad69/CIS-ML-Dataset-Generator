"""
Ansible CIS Hardener Management Module.
Manages rule extraction, controlled randomized rule selection, and Ansible playbook execution.
"""

import os
import re
import random
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from pipeline.config import ANSIBLE_DIR

class AnsibleHardenerManager:
    """
    Interface for Ansible CIS Hardener for Ubuntu 20.04.
    """
    # Sensitive rules that cause SSH/sudo lockout or fail in vagrant environments
    SAFE_LOCKOUT_EXCLUSIONS = {
        "5.2.4",     # sudo password enforcement
        "5.4.1.1",   # password expiration (locks out vagrant)
        "5.4.1.2",   # min password days
        "5.4.1.3",   # password expiration warning
        "5.4.1.5",   # inactive password lock
        "5.4.1.6",   # chage -l (sudo for system users)
        "6.1.1",     # AIDE install requires immense disk/time
        "1.1.1.9",   # USB storage
        "1.2.2.1",   # apt upgrade package lock
        "3.1.3"      # bluetooth
    }

    def __init__(self, ansible_dir: Path = ANSIBLE_DIR):
        self.ansible_dir = Path(ansible_dir)
        self.defaults_file = self.ansible_dir / "defaults" / "main.yml"
        self.playbook_file = self.ansible_dir / "playbook.yml"
        self.inventory_file = self.ansible_dir / "inventory.yml"
        self.all_rules: List[str] = self._load_available_rules()

    def _load_available_rules(self) -> List[str]:
        """Parses defaults/main.yml to retrieve all 313 CIS rule variables."""
        if not self.defaults_file.exists():
            return []
        rules = []
        with open(self.defaults_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = re.match(r'^\s*ubtu20cis_rule_([0-9_]+)\s*:', line)
                if match:
                    rule_raw = match.group(1)
                    rule_id = rule_raw.replace('_', '.')
                    rules.append(rule_id)
        return rules

    def get_candidate_rules(self, exclude_dangerous: bool = True) -> List[str]:
        """Returns rules available for automated randomized hardening."""
        if not exclude_dangerous:
            return list(self.all_rules)
        return [r for r in self.all_rules if r not in self.SAFE_LOCKOUT_EXCLUSIONS]

    def select_random_rules(
        self,
        seed: Optional[int] = None,
        min_rules: int = 2,
        max_rules: int = 15,
        target_rule_count: Optional[int] = None,
        previous_selections: Optional[Set[tuple]] = None
    ) -> Tuple[int, List[str]]:
        """
        Controlled randomization to select diverse subsets of CIS hardening rules.
        Ensures varying rule counts and avoids duplicate combinations.
        """
        rng = random.Random(seed)
        candidates = self.get_candidate_rules()

        if target_rule_count is None:
            count = rng.randint(min_rules, min(max_rules, len(candidates)))
        else:
            count = max(1, min(target_rule_count, len(candidates)))

        # Attempt up to 50 times to get a non-duplicate combination
        chosen = tuple(sorted(rng.sample(candidates, count)))
        attempts = 0
        while previous_selections and chosen in previous_selections and attempts < 50:
            count = rng.randint(min_rules, min(max_rules, len(candidates)))
            chosen = tuple(sorted(rng.sample(candidates, count)))
            attempts += 1

        return count, list(chosen)

    def generate_playbook_vars(self, selected_rules: List[str]) -> Dict[str, Any]:
        """
        Generates variable dictionary where only selected rules are set to True.
        """
        vars_dict = {
            "ubtu20cis_section1_patch": True,
            "ubtu20cis_section2_patch": True,
            "ubtu20cis_section3_patch": True,
            "ubtu20cis_section4_patch": True,
            "ubtu20cis_section5_patch": True,
            "ubtu20cis_section6_patch": True,
            "ubtu20cis_section7_patch": True,
        }

        # Apply lockout exclusions
        for ex in self.SAFE_LOCKOUT_EXCLUSIONS:
            var_name = f"ubtu20cis_rule_{ex.replace('.', '_')}"
            vars_dict[var_name] = False

        # Set all candidate rules to False by default
        for r in self.all_rules:
            var_name = f"ubtu20cis_rule_{r.replace('.', '_')}"
            if var_name not in vars_dict:
                vars_dict[var_name] = False

        # Enable only the selected rules
        for r in selected_rules:
            var_name = f"ubtu20cis_rule_{r.replace('.', '_')}"
            vars_dict[var_name] = True

        return vars_dict

    def build_tags_argument(self, selected_rules: List[str]) -> str:
        """Builds Ansible --tags command string."""
        tags = [f"rule_{r}" for r in selected_rules]
        return ",".join(tags)
