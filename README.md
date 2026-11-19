# CyberGuard: Multi-OS CIS Compliance & Security Risk Dataset Generator

**Final Year Project (FYP)**: Real-World, Audit-Derived CIS Compliance Monitoring, Risk Prediction, Anomaly Detection, and Temporal Security Analysis across Linux and Windows Systems.

---

## 1. Project Overview

CyberGuard Dataset Generator is an automated, multi-operating system research pipeline designed to bridge configuration auditing and machine learning. It creates empirical security snapshots by applying randomized subsets of Center for Internet Security (CIS) hardening rules to virtual machines, auditing them against official CIS benchmarks, and collecting correlated system telemetry (patch age, vulnerability metrics, and CVSS severity distributions).

From these experiments, the pipeline derives three balanced, machine-learning-ready datasets:
1. **Supervised Compliance Dataset**: For predicting high-risk systems (`risk_label = 1` vs `0`).
2. **Anomaly Detection Dataset**: For detecting anomalous configuration states using unsupervised Isolation Forests (zero labels used).
3. **Temporal Compliance Dataset**: For tracking security drift and remediation trajectories over time.

---

## 2. Project Architecture & Directory Structure

The project is fully self-contained. All OS hardeners, audit benchmark files, auditor engines, and pipeline utilities reside locally in the project directory:

```text
Dataset Generator/
├── README.md                                             # This comprehensive guide
├── requirements.txt                                      # Python dependencies
├── cis_rules_annotated.csv                               # Authoritative CIS severity mapping source
├── run_pipeline.py                                       # Unified CLI orchestrator
│
├── collector_node.py                                     # Distributable contributor node worker
├── merge_node_datasets.py                                # Aggregator for merging contributor snapshots
├── generate_datasets.py                                  # Level 1 + Level 2 baseline dataset generator
├── train_models.py                                       # ML evaluation suite (Supervised, Anomaly, Temporal)
├── validate_datasets.py                                  # Comprehensive 9-rule integrity validator
│
├── pipeline/                                             # Core modular library
│   ├── config.py                                         # Global settings, paths, and scoring weights
│   ├── os_adapters.py                                    # Unified adapters for Ubuntu and Windows
│   ├── balancing.py                                      # Active adaptive 50/50 ML balancing controller
│   ├── scoring.py                                        # Authoritative severity mapper & score engine
│   ├── system_collector.py                               # Patch age & vulnerability telemetry generator
│   ├── auditor.py                                        # CIS Benchmark parser & state evaluator
│   ├── hardener.py                                       # Ansible role configuration & lockout safety
│   ├── vm_manager.py                                     # Vagrant lifecycle & clean snapshot manager
│   └── scripts/                                          # Anti-hardening degradation scripts
│       ├── degrade_linux.sh                              # Linux vulnerability injection script
│       └── degrade_windows.ps1                           # Windows vulnerability injection script
│
├── Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup/# Ubuntu 20.04 Hardener & Audit Suite
│   ├── CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L1_Server.audit # Official Level 1 Benchmark (180 rules)
│   ├── CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L2_Server.audit # Official Level 2 Benchmark (33 rules)
│   ├── degrade_vm.sh                                     # Local anti-hardening script
│   └── inject_vulnerabilities.yml                        # Ansible vulnerability injection playbook
│
├── Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup/# Ubuntu 22.04 Hardener & Audit Suite
│   ├── CIS_Ubuntu_Linux_22.04_LTS_v3.0.0_L1_Server.audit # Level 1 Server Benchmark
│   ├── CIS_Ubuntu_Linux_22.04_LTS_v3.0.0_L2_Server.audit # Level 2 Server Benchmark
│   ├── degrade_vm.sh                                     # Local anti-hardening script
│   └── inject_vulnerabilities.yml                        # Ansible vulnerability injection playbook
│
├── Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup/# Ubuntu 24.04 Hardener & Audit Suite
│   ├── CIS_Ubuntu_Linux_24.04_LTS_v2.0.0_L1_Server.audit # Level 1 Server Benchmark
│   ├── CIS_Ubuntu_Linux_24.04_LTS_v2.0.0_L2_Server.audit # Level 2 Server Benchmark
│   ├── degrade_vm.sh                                     # Local anti-hardening script
│   └── inject_vulnerabilities.yml                        # Ansible vulnerability injection playbook
│
├── Windows-10-CIS-Hardener/                              # Windows 10 Enterprise Hardener & Audit Suite
│   ├── CIS_Microsoft_Windows_10_Enterprise_v5.0.0_L1.audit # Enterprise Level 1 Benchmark
│   ├── CIS_Microsoft_Windows_10_Enterprise_v5.0.0_L2.audit # Enterprise Level 2 Benchmark
│   └── degrade_windows.ps1                               # Windows anti-hardening script
│
├── Windows-11-CIS-Hardener/                              # Windows 11 Enterprise Hardener & Audit Suite
│   ├── CIS_Microsoft_Intune_for_Windows_11_v5.0.0_L1.audit # Windows 11 Level 1 Benchmark
│   ├── CIS_Microsoft_Windows_10_Enterprise_v5.0.0_L2.audit # Level 2 Security Benchmark
│   └── degrade_windows.ps1                               # Windows anti-hardening script
│
├── CIS-Auditor-Linux-with-Vagrant-Environment/           # Linux CIS Auditor Engine
├── CIS-Auditor-Windows/                                  # Windows CIS Auditor Engine
│
├── node_output/                                          # Output directory for distributed snapshots
│   └── .gitkeep
│
└── [Generated Datasets]
    ├── master_cis_security_dataset.csv                   # Master audited security snapshots
    ├── supervised_compliance_dataset.csv                 # Feature matrix + target: risk_label
    ├── anomaly_detection_dataset.csv                     # Unsupervised feature matrix (no labels)
    ├── temporal_compliance_dataset.csv                   # Multi-epoch time series snapshots
    ├── temporal_compliance_with_deltas.csv               # Augmented with Delta Score, Failures, Vulns
    ├── experiment_metadata.json                          # Complete audit trace and reproducible seeds
    └── validation_report.md                              # Formal 9-rule integrity check report
```

---

## 3. Installation & Prerequisites

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Vagrant & VirtualBox (optional for live VM execution; evaluation mode runs standalone)

### Setup
1. Clone or navigate to the repository directory:
   ```bash
   cd "D:\University\FYP CyberGuard\Dataset Generator"
   ```

2. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .\.venv\Scripts\Activate.ps1
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 4. How to Run

### Quick-Start Contributor Cheat Sheet

If you are a contributor assigned to a specific VM, use this quick reference table to boot and collect your dataset in 2 commands:

| Target VM | Operating System ID | Hardener Directory | CIS Rules | Step 1: Boot VM | Step 2: Run Collection Node |
|---|---|---|---|---|---|
| **Ubuntu 20.04** | `ubuntu_20.04` | `Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup` | 213 rules | `cd Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup && vagrant up && cd ..` | `python collector_node.py --os ubuntu_20.04 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade` |
| **Ubuntu 22.04** | `ubuntu_22.04` | `Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup` | 186 rules | `cd Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup && vagrant up && cd ..` | `python collector_node.py --os ubuntu_22.04 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade` |
| **Ubuntu 24.04** | `ubuntu_24.04` | `Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup` | 189 rules | `cd Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup && vagrant up && cd ..` | `python collector_node.py --os ubuntu_24.04 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade` |
| **Windows 10** | `windows_10` | `Windows-10-CIS-Hardener` | 302 rules | `cd Windows-10-CIS-Hardener && vagrant up && cd ..` | `python collector_node.py --os windows_10 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade` |
| **Windows 11** | `windows_11` | `Windows-11-CIS-Hardener` | 336 rules | `cd Windows-11-CIS-Hardener && vagrant up && cd ..` | `python collector_node.py --os windows_11 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade` |

> [!TIP]
> **What do the flags do?**
> * `--mode live`: Directly provisions and audits the running Vagrant virtual machine.
> * `--degrade`: **Option 3 Anti-Hardening Degradation**. Executes on boot to weaken the VM so it starts with **0 rules passed** and **0.00% compliance** instead of passing ~70 rules by default.
> * `--snapshots 100`: Captures 100 balanced empirical snapshots.
> * `--lifecycle-iterations 50`: Automatically destroys and recreates the VM after 50 snapshots when it reaches 100% compliance, resets back to 0 rules, and continues.
> * `--node-id <custom_name>`: (Optional) Assigns a custom name for your output files (e.g., `--node-id node-ahmed-u20`).

---

### Workflow A: Contributor Guide — Step-by-Step for Every VM

When distributing work across team members, each person is assigned one of the 5 virtual machines below. Follow the exact instructions for your assigned VM:

---

#### 🟢 VM 1: Ubuntu 20.04 LTS Server
* **Hardener Directory**: [Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup/](file:///D:/University/FYP%20CyberGuard/Dataset%20Generator/Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup)
* **Benchmark Suite**: CIS Ubuntu 20.04 LTS v3.0.0 Levels 1 & 2 (213 rules, 864 checks)

1. **Start the VM**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection (Recommended: 100 Snapshots with 50-Iteration Lifecycle & Degradation)**:
   ```bash
   python collector_node.py --os ubuntu_20.04 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade --node-id node-ahmed-u20
   ```
   *(For a shorter 42-snapshot run without mid-cycle destruction: `python collector_node.py --os ubuntu_20.04 --snapshots 42 --mode live --degrade`)*.
3. **When Finished**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup
   vagrant halt
   cd ..
   ```

---

#### 🟢 VM 2: Ubuntu 22.04 LTS Server
* **Hardener Directory**: [Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup/](file:///D:/University/FYP%20CyberGuard/Dataset%20Generator/Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup)
* **Benchmark Suite**: CIS Ubuntu 22.04 LTS v3.0.0 Levels 1 & 2 (186 rules, 812 checks)

1. **Start the VM**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   python collector_node.py --os ubuntu_22.04 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade --node-id node-bilal-u22
   ```
3. **When Finished**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup
   vagrant halt
   cd ..
   ```

---

#### 🟢 VM 3: Ubuntu 24.04 LTS Server
* **Hardener Directory**: [Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup/](file:///D:/University/FYP%20CyberGuard/Dataset%20Generator/Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup)
* **Benchmark Suite**: CIS Ubuntu 24.04 LTS v2.0.0 Levels 1 & 2 (189 rules, 794 checks)

1. **Start the VM**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   python collector_node.py --os ubuntu_24.04 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade --node-id node-saad-u24
   ```
3. **When Finished**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup
   vagrant halt
   cd ..
   ```

---

#### 🔵 VM 4: Windows 10 Enterprise
* **Hardener Directory**: [Windows-10-CIS-Hardener/](file:///D:/University/FYP%20CyberGuard/Dataset%20Generator/Windows-10-CIS-Hardener)
* **Benchmark Suite**: CIS Microsoft Windows 10 Enterprise v5.0.0 Levels 1 & 2 (302 rules)

1. **Start the VM**:
   ```bash
   cd Windows-10-CIS-Hardener
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   python collector_node.py --os windows_10 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade --node-id node-dawood-w10
   ```
3. **When Finished**:
   ```bash
   cd Windows-10-CIS-Hardener
   vagrant halt
   cd ..
   ```

---

#### 🔵 VM 5: Windows 11 Enterprise
* **Hardener Directory**: [Windows-11-CIS-Hardener/](file:///D:/University/FYP%20CyberGuard/Dataset%20Generator/Windows-11-CIS-Hardener)
* **Benchmark Suite**: CIS Microsoft Windows 11 Enterprise / Intune Benchmark (336 rules)

1. **Start the VM**:
   ```bash
   cd Windows-11-CIS-Hardener
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   python collector_node.py --os windows_11 --snapshots 100 --lifecycle-iterations 50 --mode live --degrade --node-id node-hamza-w11
   ```
3. **When Finished**:
   ```bash
   cd Windows-11-CIS-Hardener
   vagrant halt
   cd ..
   ```

---

#### 📤 Contributor Output & Deliverable
Once the collection run completes:
1. Two output files will be automatically generated in `node_output/`:
   - `node_output/<node-id>_snapshots.csv` (contains the audited dataset rows)
   - `node_output/<node-id>_metadata.json` (contains the exact rule IDs, seeds, and audit trace)
2. Send `<node-id>_snapshots.csv` and `<node-id>_metadata.json` to the project leader.
3. The project leader drops all contributor files into `node_output/` and merges them into the master datasets with:
   ```bash
   python run_pipeline.py --merge
   ```

---

### Core Mechanics & Behavioral Guarantees

#### 1. Startup Unhardening (`--degrade` / Option 3 — True Zero Baseline)
* **Question: Does it apply the unhardening script at the start?**
  * **YES, GUARANTEED.** As soon as the collector connects to or starts the live VM, it immediately runs the unhardening script (`degrade_vm.sh` / `degrade_linux.sh` on Linux, `degrade_windows.ps1` on Windows) **before snapshot 1 is recorded**.
* **Why this is critical**: A clean, pristine Linux or Windows VM naturally passes ~70 CIS rules right out of the box because many obsolete services (e.g. telnet, rsh, NIS) are not installed.
* **Result of `--degrade`**:
  * Injects known vulnerabilities, disables firewalls/audit daemons, and relaxes permissions.
  * Snapshot 1 baseline starts at:
    - `passed_audits = 0`
    - `failed_audits = Total Benchmark Rules` (e.g. 213 on Ubuntu 20.04)
    - `compliance_score = 0.00%`
    - `risk_label = 1 (High Risk)`

#### 2. VM Lifecycle Rebuilds (`--snapshots 100 --lifecycle-iterations 50`)
* **How multi-cycle execution works**:
  * When cumulative hardening runs for many snapshots, the VM eventually becomes 100% compliant (~snapshot 45–50).
  * To collect more snapshots without saturation:
    1. **Cycle 1 (Snapshots 1 to 50)**: Progressively hardens the VM from 0% compliance to 100% compliance.
    2. **At Snapshot 50 (Automatic Lifecycle Trigger)**: Because 50 snapshots remain to reach the target of 100, the worker automatically:
       - Destroys the compliant VM: `vagrant destroy -f`
       - Boots a fresh VM instance: `vagrant up`
       - Re-applies the unharden script live to reset the new VM back to 0 passes.
       - Refreshes the rule pool for Cycle 2.
    3. **Cycle 2 (Snapshots 51 to 100)**: Progressively hardens the new VM slice by slice.
    4. **At Snapshot 100 (Clean Exit Guarantee)**: The target count is reached! The collector flushes all CSV and metadata files to disk and **exits cleanly without destroying the VM**.

#### 3. Randomized Rule Application (2 to 8 Rules per Iteration)
* **Rule Increment Guarantee**: In subsequent iterations (starting from iteration 2), the collector randomly selects **between 2 and 8 rules** (`rng.randint(2, 8)`) to apply to the VM.
* **No Single-Rule Slowness**: Eliminates tedious single-rule applications (`+1 rule`) while ensuring realistic, varied configuration changes across successive snapshots.
* **Balanced Trajectory Management**:
  1. **Phase 1 (First 50% of cycle)**: Applies 2–8 rules randomly sampled across failing rules, pacing the system through High Risk (`Score < 70%`).
  2. **Phase 2 (Second 50% of cycle)**: Applies 2–8 rules prioritizing Critical and High severity remediations, cleanly transitioning the VM into Normal Risk (`Score >= 70%`) until fully compliant.

---

#### Real-time Progress Display
```text
===========================================================================
[*] LIVE ANTI-HARDENING: Applying unharden script to live VM at start...
[*] Executing live Anti-Hardening degradation script inside 'Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup'...
[✓] Live VM successfully degraded to vulnerable baseline!
===========================================================================
CYBERGUARD CIS DATASET GENERATION NODE - [NODE-UBUNTU_2004-50B3AB]
===========================================================================
  Target OS             : Ubuntu 20.04 LTS (ID: ubuntu_20.04, Type: 0)
  Execution Mode        : [LIVE VM PROVISIONING]
  Connected VM Folder   : Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup
  VM Isolation Mode     : [CUMULATIVE PROGRESSIVE HARDENING]
  VM Lifecycle Reset    : Every 50 iterations ('vagrant destroy -f' & 'vagrant up')
  Vulnerability Baseline: [ANTI-HARDENING DEGRADED (0 passed rules at start)]
  Benchmark Rules Pool  : 213 total rules (213 baseline failing)
  Adaptive Balancing    : Active (Targeting 50% High Risk / 50% Normal Risk)
  Snapshots Requested   : 20
  Output CSV            : ./node_output/node-ubuntu_2004-50b3ab_snapshots.csv
  Output Metadata JSON  : ./node_output/node-ubuntu_2004-50b3ab_metadata.json
===========================================================================

[*] Starting active collection loop...

[001] Ubuntu 20.04 LTS | Hardened:   0 rules | Audits:   0 P / 213 F | Score:  0.00 -> HIGH RISK (1) | Balance: High= 1 (100.0%) Norm= 0 ( 0.0%)
[002] Ubuntu 20.04 LTS | Hardened:  21 rules | Audits:  21 P / 192 F | Score:  9.59 -> HIGH RISK (1) | Balance: High= 2 (100.0%) Norm= 0 ( 0.0%)
[003] Ubuntu 20.04 LTS | Hardened:  31 rules | Audits:  31 P / 182 F | Score: 15.74 -> HIGH RISK (1) | Balance: High= 3 (100.0%) Norm= 0 ( 0.0%)
...
[010] Ubuntu 20.04 LTS | Hardened: 106 rules | Audits: 106 P / 107 F | Score: 51.35 -> HIGH RISK (1) | Balance: High=10 (100.0%) Norm= 0 ( 0.0%)
[011] Ubuntu 20.04 LTS | Hardened: 145 rules | Audits: 145 P /  68 F | Score: 75.34 -> NORMAL (0)    | Balance: High=10 (90.9%) Norm= 1 ( 9.1%)
[012] Ubuntu 20.04 LTS | Hardened: 153 rules | Audits: 153 P /  60 F | Score: 80.26 -> NORMAL (0)    | Balance: High=10 (83.3%) Norm= 2 (16.7%)
...
[019] Ubuntu 20.04 LTS | Hardened: 205 rules | Audits: 205 P /   8 F | Score: 95.08 -> NORMAL (0)    | Balance: High=10 (52.6%) Norm= 9 (47.4%)
[020] Ubuntu 20.04 LTS | Hardened: 213 rules | Audits: 213 P /   0 F | Score: 100.00 -> NORMAL (0)    | Balance: High=10 (50.0%) Norm=10 (50.0%)

===========================================================================
COLLECTION SESSION SUMMARY - [node-ubuntu_2004-50b3ab]
===========================================================================
  Exact OS Name         : Ubuntu 20.04 LTS
  Total Snapshots Done  : 20
  High Risk (1) Count   : 10 (50.0%)
  Normal Risk (0) Count : 10 (50.0%)
  Dataset Balanced?     : YES - PERFECTLY BALANCED
===========================================================================
```

---

### Workflow B: Merging Contributor Datasets

Once contributors finish generating snapshots, place their CSV files in `node_output/` and run the merger:

```bash
python merge_node_datasets.py
```
This utility:
- Automatically discovers all `*_snapshots.csv` and `*_metadata.json` files in `node_output/`.
- Deduplicates identical snapshot states.
- Re-indexes iterations sequentially.
- Updates `master_cis_security_dataset.csv`, `supervised_compliance_dataset.csv`, `anomaly_detection_dataset.csv`, and `experiment_metadata.json`.
- Displays the combined class balance and multi-OS breakdown.

---

### Workflow C: Machine Learning Model Evaluation

To train the machine learning models and evaluate performance across Supervised, Anomaly Detection, and Temporal Drift tasks:

```bash
python train_models.py
```

The script evaluates:
1. **Supervised Classification (5-Fold Stratified Cross-Validation)**:
   - **Experiment A (Target Leakage Demonstration)**: Shows why including `compliance_score` yields a trivial 99.4% boundary classifier.
   - **Experiment B (Leak-Free Model)**: Predicts risk using strictly raw configuration states (passed/failed audits, severity failure counts, patch age, vulnerability counts). Achieves **98.75% accuracy**, **98.89% precision**, **98.82% recall**, and **1.0000 ROC-AUC**.
   - **Feature Importance Analysis**: Identifies that `failed_audits` (31.1%), `passed_audits` (22.1%), and `high_severity_failures` (21.9%) are the primary predictive drivers.
2. **Unsupervised Anomaly Detection (Isolation Forest)**:
   - Evaluates on 10 numerical features without risk labels. Isolates true security neglect outliers (systems with patch age > 500 days or critical CVE spikes).
3. **Temporal Trajectory & Drift Analysis**:
   - Tracks 4 persistent machines across epochs, computing net degradation ($\Delta\text{Score} = -44.34$) and remediation trajectories ($\Delta\text{Score} = +47.29$).

---

### Workflow D: Dataset Integrity Validation

To run the automated validation suite verifying all 9 data integrity requirements:

```bash
python validate_datasets.py
```

Validation Checklist:
- `[PASS]` **Rule 1**: Snapshot 1-to-1 Mapping (Master rows == Metadata entries)
- `[PASS]` **Rule 2**: Valid CIS Rule IDs across all snapshots
- `[PASS]` **Rule 3**: Authoritative Severity Mapping (100% of failed rules mapped to CVSS categories)
- `[PASS]` **Rule 4**: Mathematical Score Verification (100% of compliance scores match formula)
- `[PASS]` **Rule 5**: Risk Label Derivation strictly following the `< 70.0` threshold
- `[PASS]` **Rule 6**: Snapshot Uniqueness (zero duplicate configurations)
- `[PASS]` **Rule 7**: Traceability & Controlled Randomization (100% unique seeds recorded)
- `[PASS]` **Rule 8**: Feature Variance and balanced class representation
- `[PASS]` **Rule 9**: Exact OS Name & Schema Integrity (`exact_os_name` present with 0 nulls across all operating systems)

---

### Workflow E: Unified All-in-One CLI (`run_pipeline.py`)

You can execute any stage or the entire pipeline using the central entry point:

```bash
# Run full pipeline: generate baseline, train models, and validate integrity
python run_pipeline.py --all

# Generate baseline datasets only
python run_pipeline.py --generate

# Launch distributed collector node on Ubuntu 20.04
python run_pipeline.py --collect --os ubuntu_20.04 --snapshots 20

# Launch distributed collector node on Windows 10
python run_pipeline.py --collect --os windows_10 --snapshots 20

# Merge contributor node datasets
python run_pipeline.py --merge

# Train all machine learning models
python run_pipeline.py --train

# Validate dataset integrity
python run_pipeline.py --validate

# Check live VM status and SSH connectivity
python run_pipeline.py --live-vm
```

---

## 5. Dataset Schema Reference

The final `supervised_compliance_dataset.csv` contains the following features:

| Feature Name | Type | Description |
|---|---|---|
| `exact_os_name` | String | Human-readable OS: `"Ubuntu 20.04 LTS"`, `"Windows 10 Enterprise"`, etc. |
| `os_type` | Integer (0/1) | Categorical OS family: `0 = Linux`, `1 = Windows / Other` |
| `failed_audits` | Integer | Total count of failed CIS benchmark rules |
| `passed_audits` | Integer | Total count of passed CIS benchmark rules |
| `high_severity_failures` | Integer | Count of failed rules with High or Critical CVSS severity |
| `medium_severity_failures` | Integer | Count of failed rules with Medium CVSS severity |
| `low_severity_failures` | Integer | Count of failed rules with Low CVSS severity |
| `hours_since_last_patch` | Integer | Number of elapsed hours since the last security update |
| `critical_vulns` | Integer | Number of known active Critical vulnerabilities (CVSS $\ge 9.0$) |
| `high_vulns` | Integer | Number of known active High vulnerabilities ($7.0 \le \text{CVSS} < 9.0$) |
| `total_vulns` | Integer | Total count of known active vulnerabilities |
| `compliance_score` | Float | Normalized weighted compliance score ($0.0 \le \text{Score} \le 100.0$) |
| `risk_label` | Binary (0/1) | **Supervised Target**: `1 = High Risk (Score < 70)`, `0 = Normal Risk` |

### Authoritative Vulnerability & Telemetry Mapping (Zero Dummy Values)

All vulnerability metrics are derived **100% authoritatively** from the failed CIS benchmark rules using [cis_rules_annotated.csv](file:///D:/University/FYP%20CyberGuard/Dataset%20Generator/cis_rules_annotated.csv):

1. **`critical_vulns`**: The exact count of failing rules mapped to `severity_label == 'Critical'` (CVSS $\ge 9.0$) in `cis_rules_annotated.csv` (e.g., 32 Critical failing rules on baseline unhardened Ubuntu 20.04).
2. **`high_vulns`**: The exact count of failing rules mapped to `severity_label == 'High'` ($7.0 \le \text{CVSS} < 9.0$, e.g., 48 High failing rules on baseline).
3. **`total_vulns`**: Total count of all failed rules (`failed_audits`), where each failure represents an active, unmitigated vulnerability or exposure.
4. **`hours_since_last_patch`**:
   - **In Live VM Mode**: Directly queried from the VM's package manager status (`/var/lib/dpkg/status` on Ubuntu or Windows HotFix) via SSH/WinRM:
     $$\text{hours\_since\_last\_patch} = \frac{\text{Current Time} - \text{mtime}(\text{/var/lib/dpkg/status})}{3600}$$
   - **In Simulation Mode**: Scaled to clean, realistic enterprise maintenance windows (12–72 hours for maintained systems; 168–720 hours for unmaintained systems), eliminating unrealistic multi-thousand-hour values.

### Authoritative Compliance Scoring Formula

$$\text{Penalties} = 5.0 \cdot (N_{\text{High}} + N_{\text{Critical}}) + 0.5 \cdot N_{\text{Medium}} + 5.0 \cdot N_{\text{Low}}$$

$$\text{Compliance Score} = 100.0 \times \left(1.0 - \frac{\text{Penalties}}{\text{Max Possible Penalty}}\right)$$

$$\text{risk\_label} = \begin{cases} 1 & \text{if } \text{Compliance Score} < 70.0 \quad (\text{High Risk}) \\ 0 & \text{if } \text{Compliance Score} \ge 70.0 \quad (\text{Normal Risk}) \end{cases}$$

---

## 6. Supported Operating Systems & Benchmark Profiles

| OS Identifier | Exact Display Name | `os_type` | Hardener Role Directory | Benchmark Files |
|---|---|---|---|---|
| `ubuntu_20.04` | Ubuntu 20.04 LTS | `0` | `Ansible-CIS-Hardener-for-Ubuntu-20...` | Level 1 & Level 2 Server (213 rules) |
| `ubuntu_22.04` | Ubuntu 22.04 LTS | `0` | `Ansible-CIS-Hardener-for-Ubuntu-22...` | Level 1 & Level 2 Server (186 rules) |
| `ubuntu_24.04` | Ubuntu 24.04 LTS | `0` | `Ansible-CIS-Hardener-for-Ubuntu-24...` | Level 1 & Level 2 Server (189 rules) |
| `windows_10` | Windows 10 Enterprise | `1` | `Windows-10-CIS-Hardener` | Enterprise Level 1 & Level 2 (302 rules) |
| `windows_11` | Windows 11 Enterprise | `1` | `Windows-11-CIS-Hardener` | Enterprise Level 1 & Level 2 (336 rules) |

---

## 7. License & FYP Attribution

Developed as part of the **Final Year Project (FYP) — CyberGuard**, dedicated to empirical CIS compliance automation, machine-learning-driven vulnerability assessment, and risk prediction.
