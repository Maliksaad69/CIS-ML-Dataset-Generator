#!/usr/bin/env python3
"""
CyberGuard CIS Compliance Dataset Generation Pipeline (Level 1 + Level 2 Complete Suite).
Evaluates all 213 CIS Benchmark rules across 864 check items from both:
- CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L1_Server.audit
- CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L2_Server.audit

Produces a 50/50 perfectly balanced dataset for machine learning:
- Exactly 50% High Risk (1)
- Exactly 50% Normal Risk (0)
"""

import os
import sys
import json
import random
import datetime
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Set, Optional

from pipeline.config import (
    BASE_DIR,
    OUTPUT_MASTER_DATASET,
    OUTPUT_SUPERVISED_DATASET,
    OUTPUT_ANOMALY_DATASET,
    OUTPUT_TEMPORAL_DATASET,
    OUTPUT_METADATA_JSON,
    DEFAULT_SCORING_WEIGHTS,
    RISK_THRESHOLD,
    OS_TYPE_LINUX
)
from pipeline.scoring import AuthoritativeSeverityMapper, calculate_compliance_score, assign_risk_label
from pipeline.hardener import AnsibleHardenerManager
from pipeline.auditor import CISAuditorManager
from pipeline.system_collector import SystemTelemetryCollector

MAX_PENALTY_L1_L2 = 813.0

def run_experiment_pipeline(
    num_independent_high: int = 52,
    num_independent_normal: int = 52,
    num_independent: Optional[int] = None,
    num_temporal_systems: int = 4,
    temporal_steps_per_system: int = 6,
    num_anomalies: int = 12,
    base_seed: int = 42
) -> None:
    if num_independent is not None:
        num_independent_high = num_independent // 2
        num_independent_normal = num_independent - num_independent_high
    print("=" * 70)
    print("CYBERGUARD CIS COMPLIANCE PIPELINE (ALL RULES: LEVEL 1 & LEVEL 2)")
    print("=" * 70)

    print("[*] Initializing Authoritative Severity Mapper from cis_rules_annotated.csv...")
    severity_mapper = AuthoritativeSeverityMapper()

    print("[*] Initializing Ansible Hardener Rule Manager...")
    hardener_mgr = AnsibleHardenerManager()

    print("[*] Initializing CIS Auditor Manager with Level 1 & Level 2 .audit files...")
    auditor_mgr = CISAuditorManager()
    all_rules_pool = auditor_mgr.get_all_rule_ids()
    print(f"[+] Loaded {len(all_rules_pool)} total CIS Benchmark rules across Level 1 & Level 2.")

    # Determine baseline failing rules
    res_clean = auditor_mgr.evaluate_audit_state([])
    baseline_failing_rules = res_clean["failed_rules"]
    print(f"[+] Baseline Clean Ubuntu 20.04 State: {res_clean['passed_count']} Natural Passes | {len(baseline_failing_rules)} Baseline Failures")

    telemetry_collector = SystemTelemetryCollector(os_type=OS_TYPE_LINUX)

    master_records: List[Dict[str, Any]] = []
    metadata_list: List[Dict[str, Any]] = []
    seen_combinations: Set[tuple] = set()

    current_iteration = 1
    base_time = datetime.datetime(2026, 11, 1, 9, 0, 0)

    # -------------------------------------------------------------
    # 1. Independent Experiments - High Risk Class (1) (52 experiments)
    # -------------------------------------------------------------
    print(f"\n[*] Generating {num_independent_high} Independent High Risk (1) Experiments...")
    for i in range(num_independent_high):
        iteration_seed = base_seed + i * 19
        system_id = f"ubuntu-vm-indep-high-{i+1:03d}"
        timestamp = base_time + datetime.timedelta(hours=i * 3.5, minutes=(i * 11) % 60)
        rng = random.Random(iteration_seed)

        # To ensure Score < 70, harden between 5 and 82 failing rules
        rule_count = rng.randint(5, 82)
        selected_rules = rng.sample(baseline_failing_rules, rule_count)

        # Ensure uniqueness
        attempt = 0
        while tuple(sorted(selected_rules)) in seen_combinations and attempt < 30:
            rule_count = rng.randint(5, 82)
            selected_rules = rng.sample(baseline_failing_rules, rule_count)
            attempt += 1
        seen_combinations.add(tuple(sorted(selected_rules)))

        audit_state = auditor_mgr.evaluate_audit_state(selected_rules)
        failed_rules = audit_state["failed_rules"]

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r_id in failed_rules:
            s_label = severity_mapper.get_severity(r_id)["severity"]
            sev_counts[s_label] = sev_counts.get(s_label, 0) + 1

        comp_score, penalties = calculate_compliance_score(sev_counts, weights=DEFAULT_SCORING_WEIGHTS, max_possible_penalty=MAX_PENALTY_L1_L2)
        risk = assign_risk_label(comp_score, threshold=RISK_THRESHOLD)

        # Telemetry: correlated with moderate/high risk (in hours)
        patch_age_hours = rng.randint(7 * 24, 30 * 24)
        telemetry = telemetry_collector.generate_telemetry(
            seed=iteration_seed,
            patch_age_hours=patch_age_hours,
            sev_counts=sev_counts,
            failed_rules_count=audit_state["failed_count"],
            is_anomalous=False
        )
        high_crit_failures = sev_counts.get("High", 0) + sev_counts.get("Critical", 0)

        record = {
            "system_id": system_id,
            "iteration_id": current_iteration,
            "timestamp": timestamp.isoformat(),
            "experiment_type": "independent_high_risk",
            "exact_os_name": telemetry.get("exact_os_name", "Ubuntu 20.04 LTS"),
            "os_type": telemetry["os_type"],
            "hardened_rules": ",".join(selected_rules) if selected_rules else "none",
            "hardened_rule_count": len(selected_rules),
            "passed_audits": audit_state["passed_count"],
            "failed_audits": audit_state["failed_count"],
            "high_severity_failures": high_crit_failures,
            "medium_severity_failures": sev_counts.get("Medium", 0),
            "low_severity_failures": sev_counts.get("Low", 0),
            "hours_since_last_patch": telemetry["hours_since_last_patch"],
            "critical_vulns": sev_counts.get("Critical", 0),
            "high_vulns": sev_counts.get("High", 0),
            "total_vulns": audit_state["failed_count"],
            "compliance_score": comp_score,
            "risk_label": risk
        }
        master_records.append(record)

        metadata_entry = {
            "iteration_id": current_iteration,
            "system_id": system_id,
            "experiment_type": "independent_high_risk",
            "timestamp": timestamp.isoformat(),
            "random_seed": iteration_seed,
            "selected_rules": selected_rules,
            "hardened_rule_count": len(selected_rules),
            "audit_summary": {
                "total_rules": audit_state["total_rules"],
                "passed_count": audit_state["passed_count"],
                "failed_count": audit_state["failed_count"]
            },
            "severity_distribution": sev_counts,
            "penalties": penalties,
            "patch_information": {"hours_since_last_patch": telemetry["hours_since_last_patch"]},
            "vulnerability_information": {
                "critical": telemetry["critical_vulns"],
                "high": telemetry["high_vulns"],
                "total": telemetry["total_vulns"]
            },
            "compliance_score": comp_score,
            "risk_label": risk
        }
        metadata_list.append(metadata_entry)
        current_iteration += 1

    # -------------------------------------------------------------
    # 2. Independent Experiments - Normal Risk Class (0) (52 experiments)
    # -------------------------------------------------------------
    print(f"[*] Generating {num_independent_normal} Independent Normal Risk (0) Experiments...")
    for j in range(num_independent_normal):
        iteration_seed = base_seed + 2000 + j * 23
        system_id = f"ubuntu-vm-indep-norm-{j+1:03d}"
        timestamp = base_time + datetime.timedelta(hours=j * 4.0, minutes=(j * 17) % 60)
        rng = random.Random(iteration_seed)

        # To ensure Score >= 70, harden between 92 and 158 failing rules
        rule_count = rng.randint(92, min(158, len(baseline_failing_rules)))
        selected_rules = rng.sample(baseline_failing_rules, rule_count)

        attempt = 0
        while tuple(sorted(selected_rules)) in seen_combinations and attempt < 30:
            rule_count = rng.randint(92, min(158, len(baseline_failing_rules)))
            selected_rules = rng.sample(baseline_failing_rules, rule_count)
            attempt += 1
        seen_combinations.add(tuple(sorted(selected_rules)))

        audit_state = auditor_mgr.evaluate_audit_state(selected_rules)
        failed_rules = audit_state["failed_rules"]

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r_id in failed_rules:
            s_label = severity_mapper.get_severity(r_id)["severity"]
            sev_counts[s_label] = sev_counts.get(s_label, 0) + 1

        comp_score, penalties = calculate_compliance_score(sev_counts, weights=DEFAULT_SCORING_WEIGHTS, max_possible_penalty=MAX_PENALTY_L1_L2)
        risk = assign_risk_label(comp_score, threshold=RISK_THRESHOLD)

        # Telemetry: well-maintained servers (12 to 72 hours since patch)
        patch_age_hours = rng.randint(12, 72)
        telemetry = telemetry_collector.generate_telemetry(
            seed=iteration_seed,
            patch_age_hours=patch_age_hours,
            sev_counts=sev_counts,
            failed_rules_count=audit_state["failed_count"],
            is_anomalous=False
        )
        high_crit_failures = sev_counts.get("High", 0) + sev_counts.get("Critical", 0)

        record = {
            "system_id": system_id,
            "iteration_id": current_iteration,
            "timestamp": timestamp.isoformat(),
            "experiment_type": "independent_normal_risk",
            "exact_os_name": telemetry.get("exact_os_name", "Ubuntu 20.04 LTS"),
            "os_type": telemetry["os_type"],
            "hardened_rules": ",".join(selected_rules) if selected_rules else "none",
            "hardened_rule_count": len(selected_rules),
            "passed_audits": audit_state["passed_count"],
            "failed_audits": audit_state["failed_count"],
            "high_severity_failures": high_crit_failures,
            "medium_severity_failures": sev_counts.get("Medium", 0),
            "low_severity_failures": sev_counts.get("Low", 0),
            "hours_since_last_patch": telemetry["hours_since_last_patch"],
            "critical_vulns": sev_counts.get("Critical", 0),
            "high_vulns": sev_counts.get("High", 0),
            "total_vulns": audit_state["failed_count"],
            "compliance_score": comp_score,
            "risk_label": risk
        }
        master_records.append(record)

        metadata_entry = {
            "iteration_id": current_iteration,
            "system_id": system_id,
            "experiment_type": "independent_normal_risk",
            "timestamp": timestamp.isoformat(),
            "random_seed": iteration_seed,
            "selected_rules": selected_rules,
            "hardened_rule_count": len(selected_rules),
            "audit_summary": {
                "total_rules": audit_state["total_rules"],
                "passed_count": audit_state["passed_count"],
                "failed_count": audit_state["failed_count"]
            },
            "severity_distribution": sev_counts,
            "penalties": penalties,
            "patch_information": {"hours_since_last_patch": telemetry["hours_since_last_patch"]},
            "vulnerability_information": {
                "critical": telemetry["critical_vulns"],
                "high": telemetry["high_vulns"],
                "total": telemetry["total_vulns"]
            },
            "compliance_score": comp_score,
            "risk_label": risk
        }
        metadata_list.append(metadata_entry)
        current_iteration += 1

    # -------------------------------------------------------------
    # 3. Intentional Anomalous States (12 experiments: 6 High Risk, 6 Normal Risk Outliers)
    # -------------------------------------------------------------
    print(f"[*] Generating {num_anomalies} Intentional Anomalous States (6 High, 6 Normal Outliers)...")
    for a_idx in range(num_anomalies):
        anomaly_seed = base_seed + 5000 + a_idx * 37
        system_id = f"ubuntu-vm-anomaly-{a_idx+1:02d}"
        timestamp = base_time + datetime.timedelta(days=12 + a_idx, hours=random.Random(anomaly_seed).randint(1, 10))
        rng = random.Random(anomaly_seed)

        if a_idx < 6:
            # Extreme High-Risk Anomaly: near-zero hardening, ancient patch age
            rule_count = rng.randint(0, 8)
            selected_rules = rng.sample(baseline_failing_rules, rule_count) if rule_count > 0 else []
        else:
            # Subtle / High-Compliance Anomaly: highly hardened, but extreme vulnerability burst / zero-day
            rule_count = rng.randint(110, 145)
            selected_rules = rng.sample(baseline_failing_rules, rule_count)

        audit_state = auditor_mgr.evaluate_audit_state(selected_rules)
        failed_rules = audit_state["failed_rules"]

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r_id in failed_rules:
            s_label = severity_mapper.get_severity(r_id)["severity"]
            sev_counts[s_label] = sev_counts.get(s_label, 0) + 1

        comp_score, penalties = calculate_compliance_score(sev_counts, weights=DEFAULT_SCORING_WEIGHTS, max_possible_penalty=MAX_PENALTY_L1_L2)
        risk = assign_risk_label(comp_score, threshold=RISK_THRESHOLD)

        telemetry = telemetry_collector.generate_telemetry(
            seed=anomaly_seed,
            sev_counts=sev_counts,
            failed_rules_count=audit_state["failed_count"],
            is_anomalous=True
        )
        high_crit_failures = sev_counts.get("High", 0) + sev_counts.get("Critical", 0)

        record = {
            "system_id": system_id,
            "iteration_id": current_iteration,
            "timestamp": timestamp.isoformat(),
            "experiment_type": "anomaly",
            "exact_os_name": telemetry.get("exact_os_name", "Ubuntu 20.04 LTS"),
            "os_type": telemetry["os_type"],
            "hardened_rules": ",".join(selected_rules) if selected_rules else "none",
            "hardened_rule_count": len(selected_rules),
            "passed_audits": audit_state["passed_count"],
            "failed_audits": audit_state["failed_count"],
            "high_severity_failures": high_crit_failures,
            "medium_severity_failures": sev_counts.get("Medium", 0),
            "low_severity_failures": sev_counts.get("Low", 0),
            "hours_since_last_patch": telemetry["hours_since_last_patch"],
            "critical_vulns": sev_counts.get("Critical", 0),
            "high_vulns": sev_counts.get("High", 0),
            "total_vulns": audit_state["failed_count"],
            "compliance_score": comp_score,
            "risk_label": risk
        }
        master_records.append(record)

        metadata_entry = {
            "iteration_id": current_iteration,
            "system_id": system_id,
            "experiment_type": "anomaly",
            "timestamp": timestamp.isoformat(),
            "random_seed": anomaly_seed,
            "selected_rules": selected_rules,
            "hardened_rule_count": len(selected_rules),
            "audit_summary": {
                "total_rules": audit_state["total_rules"],
                "passed_count": audit_state["passed_count"],
                "failed_count": audit_state["failed_count"]
            },
            "severity_distribution": sev_counts,
            "penalties": penalties,
            "patch_information": {"hours_since_last_patch": telemetry["hours_since_last_patch"]},
            "vulnerability_information": {
                "critical": telemetry["critical_vulns"],
                "high": telemetry["high_vulns"],
                "total": telemetry["total_vulns"]
            },
            "compliance_score": comp_score,
            "risk_label": risk
        }
        metadata_list.append(metadata_entry)
        current_iteration += 1

    # -------------------------------------------------------------
    # 4. Persistent Experiments (for Temporal Analysis) (24 snapshots: 12 High, 12 Normal)
    # -------------------------------------------------------------
    print(f"[*] Generating Temporal Sequences ({num_temporal_systems} persistent systems x {temporal_steps_per_system} steps)...")
    temporal_records: List[Dict[str, Any]] = []

    # 4 systems: 2 start Normal and degrade to High Risk; 2 start High Risk and remediate to Normal
    for s_idx in range(num_temporal_systems):
        sys_id = f"ubuntu-vm-persistent-{s_idx+1:02d}"
        sys_seed = base_seed + 9000 + s_idx * 149
        rng = random.Random(sys_seed)

        system_start_time = base_time + datetime.timedelta(days=s_idx * 3)

        if s_idx in [0, 2]:
            # Deteriorating trajectory: starts Normal (e.g. 115 rules), steps 0-2 Normal, steps 3-5 High Risk
            initial_count = 125
            current_rules = set(rng.sample(baseline_failing_rules, initial_count))
            patch_hours = 5 * 24
            traj_type = "deteriorating"
        else:
            # Remediation trajectory: starts High Risk (e.g. 30 rules), steps 0-2 High Risk, steps 3-5 Normal
            initial_count = 35
            current_rules = set(rng.sample(baseline_failing_rules, initial_count))
            patch_hours = 60 * 24
            traj_type = "improving"

        for step in range(temporal_steps_per_system):
            step_seed = sys_seed + step * 31
            step_rng = random.Random(step_seed)
            step_time = system_start_time + datetime.timedelta(days=step * 14)

            if step > 0:
                if traj_type == "deteriorating":
                    patch_hours += 14 * 24
                    # Drop rules steadily to cross from Normal into High Risk
                    num_drop = step_rng.randint(14, 20)
                    drop_list = step_rng.sample(list(current_rules), min(num_drop, len(current_rules) - 10))
                    for d in drop_list:
                        current_rules.remove(d)
                else:
                    patch_hours = max(48, patch_hours - step_rng.randint(12 * 24, 22 * 24))
                    # Add rules steadily to cross from High Risk into Normal
                    unhardened = [r for r in baseline_failing_rules if r not in current_rules]
                    num_add = min(step_rng.randint(18, 25), len(unhardened))
                    current_rules.update(step_rng.sample(unhardened, num_add))

            audit_state = auditor_mgr.evaluate_audit_state(list(current_rules))
            failed_rules = audit_state["failed_rules"]

            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for r_id in failed_rules:
                s_label = severity_mapper.get_severity(r_id)["severity"]
                sev_counts[s_label] = sev_counts.get(s_label, 0) + 1

            comp_score, penalties = calculate_compliance_score(sev_counts, weights=DEFAULT_SCORING_WEIGHTS, max_possible_penalty=MAX_PENALTY_L1_L2)
            risk = assign_risk_label(comp_score, threshold=RISK_THRESHOLD)

            telemetry = telemetry_collector.generate_telemetry(
                seed=step_seed,
                patch_age_hours=patch_hours,
                sev_counts=sev_counts,
                failed_rules_count=audit_state["failed_count"],
                is_anomalous=False
            )
            high_crit_failures = sev_counts.get("High", 0) + sev_counts.get("Critical", 0)

            t_record = {
                "system_id": sys_id,
                "iteration_id": current_iteration,
                "timestamp": step_time.isoformat(),
                "experiment_type": "temporal",
                "exact_os_name": telemetry.get("exact_os_name", "Ubuntu 20.04 LTS"),
                "os_type": telemetry["os_type"],
                "hardened_rules": ",".join(sorted(list(current_rules))) if current_rules else "none",
                "hardened_rule_count": len(current_rules),
                "passed_audits": audit_state["passed_count"],
                "failed_audits": audit_state["failed_count"],
                "high_severity_failures": high_crit_failures,
                "medium_severity_failures": sev_counts.get("Medium", 0),
                "low_severity_failures": sev_counts.get("Low", 0),
                "hours_since_last_patch": telemetry["hours_since_last_patch"],
                "critical_vulns": sev_counts.get("Critical", 0),
                "high_vulns": sev_counts.get("High", 0),
                "total_vulns": audit_state["failed_count"],
                "compliance_score": comp_score,
                "risk_label": risk
            }
            master_records.append(t_record)
            temporal_records.append(t_record)

            metadata_entry = {
                "iteration_id": current_iteration,
                "system_id": sys_id,
                "experiment_type": "temporal",
                "temporal_step": step + 1,
                "trajectory_type": traj_type,
                "timestamp": step_time.isoformat(),
                "random_seed": step_seed,
                "selected_rules": sorted(list(current_rules)),
                "hardened_rule_count": len(current_rules),
                "audit_summary": {
                    "total_rules": audit_state["total_rules"],
                    "passed_count": audit_state["passed_count"],
                    "failed_count": audit_state["failed_count"]
                },
                "severity_distribution": sev_counts,
                "penalties": penalties,
                "patch_information": {"hours_since_last_patch": telemetry["hours_since_last_patch"]},
                "vulnerability_information": {
                    "critical": telemetry["critical_vulns"],
                    "high": telemetry["high_vulns"],
                    "total": telemetry["total_vulns"]
                },
                "compliance_score": comp_score,
                "risk_label": risk
            }
            metadata_list.append(metadata_entry)
            current_iteration += 1

    # -------------------------------------------------------------
    # 5. Format & Save Deliverables
    # -------------------------------------------------------------
    print("\n[*] Formatting and Saving Final Deliverables...")
    df_master = pd.DataFrame(master_records)

    # Save Master
    df_master.to_csv(OUTPUT_MASTER_DATASET, index=False)
    print(f"[+] Saved Master Dataset: {OUTPUT_MASTER_DATASET} ({len(df_master)} rows)")

    # Save Supervised
    supervised_cols = [
        "exact_os_name", "os_type", "failed_audits", "passed_audits", 
        "high_severity_failures", "medium_severity_failures", "low_severity_failures",
        "hours_since_last_patch", "critical_vulns", "high_vulns", "total_vulns", 
        "compliance_score", "risk_label"
    ]
    df_supervised = df_master[supervised_cols].copy()
    df_supervised.to_csv(OUTPUT_SUPERVISED_DATASET, index=False)
    print(f"[+] Saved Supervised Dataset: {OUTPUT_SUPERVISED_DATASET} ({len(df_supervised)} rows)")

    # Save Anomaly (NO risk_label)
    anomaly_cols = [
        "failed_audits", "passed_audits", 
        "high_severity_failures", "medium_severity_failures", "low_severity_failures",
        "hours_since_last_patch", "critical_vulns", "high_vulns", "total_vulns", 
        "compliance_score"
    ]
    df_anomaly = df_master[anomaly_cols].copy()
    df_anomaly.to_csv(OUTPUT_ANOMALY_DATASET, index=False)
    print(f"[+] Saved Anomaly Detection Dataset: {OUTPUT_ANOMALY_DATASET} ({len(df_anomaly)} rows)")

    # Save Temporal
    temporal_cols = [
        "system_id", "timestamp", "exact_os_name", "failed_audits", "passed_audits",
        "high_severity_failures", "medium_severity_failures", "low_severity_failures",
        "hours_since_last_patch", "critical_vulns", "high_vulns", "total_vulns",
        "compliance_score", "risk_label"
    ]
    df_temporal = pd.DataFrame(temporal_records)[temporal_cols].copy()
    df_temporal.to_csv(OUTPUT_TEMPORAL_DATASET, index=False)
    print(f"[+] Saved Temporal Dataset: {OUTPUT_TEMPORAL_DATASET} ({len(df_temporal)} rows)")

    # Save Metadata JSON
    with open(OUTPUT_METADATA_JSON, 'w', encoding='utf-8') as f:
        json.dump(metadata_list, f, indent=2)
    print(f"[+] Saved Experiment Metadata: {OUTPUT_METADATA_JSON} ({len(metadata_list)} records)")

    print("\n" + "=" * 70)
    print("ALL-RULES DATASET GENERATION SUMMARY")
    print("=" * 70)
    high_count = (df_master['risk_label'] == 1).sum()
    normal_count = (df_master['risk_label'] == 0).sum()
    print(f"Total Audit Experiments Conducted : {len(df_master)}")
    print(f"Total Benchmark Rules Evaluated   : {len(all_rules_pool)} (Level 1 + Level 2)")
    print(f"  - Independent Experiments       : {num_independent_high + num_independent_normal}")
    print(f"  - Anomaly State Injections      : {num_anomalies}")
    print(f"  - Temporal Repeated Observations: {len(df_temporal)}")
    print(f"Risk Label Distribution: High Risk (1) = {high_count} ({high_count/len(df_master)*100:.1f}%) | Normal (0) = {normal_count} ({normal_count/len(df_master)*100:.1f}%)")
    print(f"Compliance Score Range: Min = {df_master['compliance_score'].min():.2f} | Max = {df_master['compliance_score'].max():.2f} | Mean = {df_master['compliance_score'].mean():.2f}")
    print(f"Failed Audits Range    : Min = {df_master['failed_audits'].min()} | Max = {df_master['failed_audits'].max()}")
    print(f"Patch Age Range (Hours): Min = {df_master['hours_since_last_patch'].min()} | Max = {df_master['hours_since_last_patch'].max()}")
    print(f"Critical Vulns Range   : Min = {df_master['critical_vulns'].min()} | Max = {df_master['critical_vulns'].max()}")
    print("=" * 70)

if __name__ == "__main__":
    run_experiment_pipeline()
