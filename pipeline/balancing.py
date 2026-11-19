"""
CyberGuard Adaptive Balancing Controller.
Dynamically controls random CIS rule selection to guarantee an exact 50/50 ML balance
(High Risk vs Normal Risk) regardless of how many snapshots each contributor generates.
"""

import random
from typing import Dict, List, Set, Tuple, Any

class AdaptiveBalanceController:
    """
    Actively steers snapshot generation towards an equal distribution of risk labels.
    Prevents the natural skew towards High Risk in unhardened systems while preserving
    true random selection across CIS benchmark rules.
    """
    def __init__(self, target_normal_ratio: float = 0.50):
        self.target_normal_ratio = target_normal_ratio
        self.high_risk_count = 0     # risk_label = 1 (Score < 70)
        self.normal_risk_count = 0   # risk_label = 0 (Score >= 70)
        self.total_snapshots = 0
        self.seen_combinations: Set[tuple] = set()

    def get_target_class(self, rng: random.Random) -> int:
        """
        Determines whether the next snapshot should target High Risk (1) or Normal Risk (0).
        """
        if self.high_risk_count > self.normal_risk_count:
            return 0  # Prioritize Normal Risk to restore balance
        elif self.normal_risk_count > self.high_risk_count:
            return 1  # Prioritize High Risk to restore balance
        else:
            return rng.choice([0, 1])

    def sample_rules(self, adapter, rng: random.Random) -> Tuple[List[str], int]:
        """
        Selects a random subset of rules targeted to achieve the desired balance class.
        """
        target_class = self.get_target_class(rng)
        failing_pool = adapter.get_baseline_failing_rules()
        total_failing = len(failing_pool)

        if target_class == 0:
            # Target Normal Risk: Score >= 70
            min_r, max_r = adapter.get_normal_risk_rule_range()
        else:
            # Target High Risk: Score < 70
            min_r, max_r = adapter.get_high_risk_rule_range()

        min_r = max(1, min(min_r, total_failing))
        max_r = max(min_r, min(max_r, total_failing))

        selected = []
        for _ in range(50):
            k = rng.randint(min_r, max_r)
            candidate = rng.sample(failing_pool, k)
            cand_key = tuple(sorted(candidate))
            if cand_key not in self.seen_combinations:
                self.seen_combinations.add(cand_key)
                selected = candidate
                break

        if not selected:
            k = rng.randint(min_r, max_r)
            selected = rng.sample(failing_pool, k)
            self.seen_combinations.add(tuple(sorted(selected)))

        return selected, target_class

    def record_snapshot(self, actual_risk_label: int) -> None:
        """
        Updates running counters with the actual evaluated risk label.
        """
        self.total_snapshots += 1
        if actual_risk_label == 1:
            self.high_risk_count += 1
        else:
            self.normal_risk_count += 1

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns class distribution statistics.
        """
        tot = max(1, self.total_snapshots)
        pct_high = (self.high_risk_count / tot) * 100.0
        pct_norm = (self.normal_risk_count / tot) * 100.0
        return {
            "total": self.total_snapshots,
            "high_risk_count": self.high_risk_count,
            "normal_risk_count": self.normal_risk_count,
            "high_risk_pct": round(pct_high, 1),
            "normal_risk_pct": round(pct_norm, 1),
            "is_balanced": abs(self.high_risk_count - self.normal_risk_count) <= 1
        }
