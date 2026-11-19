# FYP CyberGuard: Dataset Generation Validation Report

This report validates the integrity, reproducibility, and audit derivation of the generated machine learning datasets.

## Validation Checklist

- [PASS] All 5 dataset and metadata artifacts successfully located on disk.
- [PASS] Rule 1 - Snapshot 1-to-1 Mapping: Master rows (140) == Metadata entries (140)
- [PASS] Rule 2 - Valid CIS Rule IDs: Checked all hardening selections across 140 experiments
- [PASS] Rule 3 - Authoritative Severity Mapping: 100% of failed audit rules mapped to severity categories
- [PASS] Rule 4 - Mathematical Score Verification: 140 / 140 compliance scores exactly match formula
- [PASS] Rule 5 - Risk Label Derivation: All risk labels strictly adhere to threshold < 70 (0 mismatches)
- [PASS] Rule 6 - Snapshot Uniqueness: Zero duplicate security state configurations across dataset
- [PASS] Rule 7 - Traceability & Controlled Randomization: 140 unique, reproducible seeds recorded
- [PASS] Rule 8 - Security State Variation: std(score)=21.64, std(failures)=46.25, std(patch_age)=431.32, both risk classes present=True
- [PASS] Rule 9 - OS Name & Schema Integrity: exact_os_name present across all datasets with 0 nulls (1 distinct operating systems: Ubuntu 20.04 LTS)

## Dataset Statistical Summary

```
       passed_audits  failed_audits  ...  total_vulns  risk_label
count     140.000000     140.000000  ...   140.000000  140.000000
mean      137.321429      75.678571  ...    75.678571    0.535714
std        46.252710      46.252710  ...    46.252710    0.500514
min        53.000000       2.000000  ...     2.000000    0.000000
25%        93.750000      31.750000  ...    31.750000    0.000000
50%       137.500000      75.500000  ...    75.500000    1.000000
75%       181.250000     119.250000  ...   119.250000    1.000000
max       211.000000     160.000000  ...   160.000000    1.000000

[8 rows x 6 columns]
```

## Class Distribution

```
risk_label
High Risk (1)      75
Normal Risk (0)    65
Name: count, dtype: int64
```
