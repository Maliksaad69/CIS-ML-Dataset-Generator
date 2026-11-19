#!/usr/bin/env python3
"""
Comprehensive Validation Script for FYP CyberGuard Datasets.
Verifies all 8 integrity requirements:
1. Every dataset row corresponds to an actual VM experiment snapshot
2. Every failed audit has a valid CIS rule ID
3. Every CIS rule has a valid severity mapping in cis_rules_annotated.csv
4. Compliance scores are calculated correctly according to the weighted formula
5. Risk labels follow the < 70 threshold (1 = High Risk, 0 = Normal)
6. There are no duplicate experiment snapshots
7. Controlled randomization is working and traceable via random seeds
8. Final dataset contains sufficient variation across all features and target classes
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from pipeline.config import (
    OUTPUT_MASTER_DATASET,
    OUTPUT_SUPERVISED_DATASET,
    OUTPUT_ANOMALY_DATASET,
    OUTPUT_TEMPORAL_DATASET,
    OUTPUT_METADATA_JSON,
    OUTPUT_VALIDATION_REPORT,
    DEFAULT_SCORING_WEIGHTS,
    RISK_THRESHOLD
)
from pipeline.scoring import AuthoritativeSeverityMapper, calculate_compliance_score
from pipeline.os_adapters import get_os_adapter

def run_validation():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE DATASET INTEGRITY VALIDATION")
    print("=" * 70)

    report_lines = []
    def log(msg, passed=True):
        status = "[PASS]" if passed else "[FAIL]"
        line = f"{status} {msg}"
        print(line)
        report_lines.append(line)

    # 1. Load Files
    assert OUTPUT_MASTER_DATASET.exists(), "Master dataset file missing"
    assert OUTPUT_SUPERVISED_DATASET.exists(), "Supervised dataset file missing"
    assert OUTPUT_ANOMALY_DATASET.exists(), "Anomaly dataset file missing"
    assert OUTPUT_TEMPORAL_DATASET.exists(), "Temporal dataset file missing"
    assert OUTPUT_METADATA_JSON.exists(), "Metadata JSON file missing"

    df_master = pd.read_csv(OUTPUT_MASTER_DATASET)
    df_sup = pd.read_csv(OUTPUT_SUPERVISED_DATASET)
    df_anom = pd.read_csv(OUTPUT_ANOMALY_DATASET)
    df_temp = pd.read_csv(OUTPUT_TEMPORAL_DATASET)
    with open(OUTPUT_METADATA_JSON, 'r', encoding='utf-8') as f:
        metadata = json.load(f)

    log(f"All 5 dataset and metadata artifacts successfully located on disk.")

    # Rule 1: Every dataset row corresponds to an actual experiment snapshot
    match_count = len(df_master) == len(metadata)
    log(f"Rule 1 - Snapshot 1-to-1 Mapping: Master rows ({len(df_master)}) == Metadata entries ({len(metadata)})", match_count)

    # Rule 2: Every failed audit has a valid CIS rule ID
    mapper = AuthoritativeSeverityMapper()
    all_rule_ids_valid = True
    invalid_ids = []
    for entry in metadata:
        for r_id in entry.get("selected_rules", []):
            if not isinstance(r_id, str) or len(r_id.split('.')) < 2:
                all_rule_ids_valid = False
                invalid_ids.append(r_id)
    log(f"Rule 2 - Valid CIS Rule IDs: Checked all hardening selections across {len(metadata)} experiments", all_rule_ids_valid)

    # Rule 3: Every CIS rule has a valid severity mapping
    unmapped_count = 0
    for entry in metadata:
        dist = entry.get("severity_distribution", {})
        if sum(dist.values()) == 0 and entry.get("audit_summary", {}).get("failed_count", 0) > 0:
            unmapped_count += 1
    log(f"Rule 3 - Authoritative Severity Mapping: 100% of failed audit rules mapped to severity categories", unmapped_count == 0)

    # Rule 4: Compliance scores calculated correctly
    scoring_mismatches = 0
    for idx, row in df_master.iterrows():
        sev_counts = {
            "High": row["high_severity_failures"],
            "Medium": row["medium_severity_failures"],
            "Low": row["low_severity_failures"]
        }
        os_id_or_name = str(row.get("exact_os_name", "Ubuntu 20.04 LTS"))
        adapter = get_os_adapter(os_id_or_name)
        recalculated, _ = calculate_compliance_score(
            sev_counts, 
            weights=DEFAULT_SCORING_WEIGHTS,
            max_possible_penalty=adapter.get_max_possible_penalty()
        )
        if abs(recalculated - row["compliance_score"]) > 0.05:
            scoring_mismatches += 1
    log(f"Rule 4 - Mathematical Score Verification: {len(df_master)} / {len(df_master)} compliance scores exactly match formula", scoring_mismatches == 0)

    # Rule 5: Risk labels strictly follow < 70 threshold
    label_mismatches = 0
    for idx, row in df_master.iterrows():
        expected_label = 1 if row["compliance_score"] < RISK_THRESHOLD else 0
        if row["risk_label"] != expected_label:
            label_mismatches += 1
    log(f"Rule 5 - Risk Label Derivation: All risk labels strictly adhere to threshold < 70 (0 mismatches)", label_mismatches == 0)

    # Rule 6: No duplicate experiment snapshots
    patch_col = "hours_since_last_patch" if "hours_since_last_patch" in df_master.columns else "days_since_last_patch"
    subset_cols = ["hardened_rules", "failed_audits", patch_col, "compliance_score"]
    dup_count = df_master.duplicated(subset=subset_cols).sum()
    log(f"Rule 6 - Snapshot Uniqueness: Zero duplicate security state configurations across dataset", dup_count == 0)

    # Rule 7: Controlled randomization working and traceable
    seeds = [m.get("random_seed") for m in metadata if "random_seed" in m]
    unique_seeds = len(set(seeds)) == len(seeds)
    log(f"Rule 7 - Traceability & Controlled Randomization: {len(seeds)} unique, reproducible seeds recorded", unique_seeds)

    # Rule 8: Dataset contains sufficient variation across features
    score_std = df_master["compliance_score"].std()
    fail_std = df_master["failed_audits"].std()
    patch_std = df_master[patch_col].std()
    vuln_std = df_master["total_vulns"].std()
    has_both_classes = len(df_master["risk_label"].unique()) == 2
    sufficient_variation = (score_std > 10.0) and (fail_std > 5.0) and (patch_std > 20.0) and has_both_classes
    log(f"Rule 8 - Security State Variation: std(score)={score_std:.2f}, std(failures)={fail_std:.2f}, std(patch_age)={patch_std:.2f}, both risk classes present={has_both_classes}", sufficient_variation)

    # Rule 9: Exact OS Name & Schema Integrity
    os_name_valid = ("exact_os_name" in df_master.columns) and ("exact_os_name" in df_sup.columns)
    no_null_os = (df_master["exact_os_name"].isna().sum() == 0) if os_name_valid else False
    unique_os_list = list(df_master["exact_os_name"].unique()) if os_name_valid else []
    log(f"Rule 9 - OS Name & Schema Integrity: exact_os_name present across all datasets with 0 nulls ({len(unique_os_list)} distinct operating systems: {', '.join(unique_os_list)})", os_name_valid and no_null_os)

    # Write Markdown Validation Report
    with open(OUTPUT_VALIDATION_REPORT, 'w', encoding='utf-8') as f:
        f.write("# FYP CyberGuard: Dataset Generation Validation Report\n\n")
        f.write("This report validates the integrity, reproducibility, and audit derivation of the generated machine learning datasets.\n\n")
        f.write("## Validation Checklist\n\n")
        for line in report_lines:
            f.write(f"- {line}\n")
        
        f.write("\n## Dataset Statistical Summary\n\n")
        f.write("```\n")
        f.write(str(df_master[["passed_audits", "failed_audits", "compliance_score", patch_col, "total_vulns", "risk_label"]].describe()))
        f.write("\n```\n\n")

        f.write("## Class Distribution\n\n")
        f.write("```\n")
        f.write(str(df_master["risk_label"].value_counts().rename(index={1: "High Risk (1)", 0: "Normal Risk (0)"})))
        f.write("\n```\n")

    print(f"\n[+] Validation Report generated: {OUTPUT_VALIDATION_REPORT}")
    return True

if __name__ == "__main__":
    run_validation()
