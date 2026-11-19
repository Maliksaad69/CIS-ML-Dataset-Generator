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

### Workflow A: Contributor Guide — Step-by-Step for Every VM

When distributing work across team members, each person is assigned one of the 5 virtual machines below. Follow the exact instructions for your assigned VM:

---

#### 🟢 VM 1: Ubuntu 20.04 LTS Server
* **Hardener Directory**: `Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup/`
* **Benchmark Suite**: CIS Ubuntu 20.04 LTS v3.0.0 Levels 1 & 2 (213 rules, 864 checks)

1. **Start the VM**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   # Standard clean baseline (~31% natural passes):
   python collector_node.py --os ubuntu_20.04 --snapshots 20 --node-id node-ahmed-u20 --mode live

   # Or with Anti-Hardening Degradation (starts at 0 rules passed / Option 3):
   python collector_node.py --os ubuntu_20.04 --snapshots 42 --node-id node-ahmed-u20 --mode live --degrade
   ```
   *(Note: If running without VirtualBox/Vagrant in offline benchmark evaluation mode, simply omit `--mode live`).*

---

#### 🟢 VM 2: Ubuntu 22.04 LTS Server
* **Hardener Directory**: `Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup/`
* **Benchmark Suite**: CIS Ubuntu 22.04 LTS STIG / Server Benchmark (60 rules)

1. **Start the VM**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   # Standard clean baseline:
   python collector_node.py --os ubuntu_22.04 --snapshots 20 --node-id node-bilal-u22 --mode live

   # Or with Anti-Hardening Degradation (0 rules passed):
   python collector_node.py --os ubuntu_22.04 --snapshots 42 --node-id node-bilal-u22 --mode live --degrade
   ```

---

#### 🟢 VM 3: Ubuntu 24.04 LTS Server
* **Hardener Directory**: `Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup/`
* **Benchmark Suite**: CIS Ubuntu 24.04 LTS v2.0.0 Server / Workstation (74 rules)

1. **Start the VM**:
   ```bash
   cd Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   # Standard clean baseline:
   python collector_node.py --os ubuntu_24.04 --snapshots 20 --node-id node-saad-u24 --mode live

   # Or with Anti-Hardening Degradation (0 rules passed):
   python collector_node.py --os ubuntu_24.04 --snapshots 42 --node-id node-saad-u24 --mode live --degrade
   ```

---

#### 🔵 VM 4: Windows 10 Enterprise
* **Hardener Directory**: `Windows-10-CIS-Hardener/`
* **Benchmark Suite**: CIS Microsoft Windows 10 Enterprise v5.0.0 Levels 1 & 2 (302 rules)

1. **Start the VM**:
   ```bash
   cd Windows-10-CIS-Hardener
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   # Standard clean baseline:
   python collector_node.py --os windows_10 --snapshots 20 --node-id node-dawood-w10 --mode live

   # Or with Anti-Hardening Degradation (0 rules passed):
   python collector_node.py --os windows_10 --snapshots 42 --node-id node-dawood-w10 --mode live --degrade
   ```

---

#### 🔵 VM 5: Windows 11 Enterprise
* **Hardener Directory**: `Windows-11-CIS-Hardener/`
* **Benchmark Suite**: CIS Microsoft Windows 11 Enterprise / Intune Benchmark (336 rules)

1. **Start the VM**:
   ```bash
   cd Windows-11-CIS-Hardener
   vagrant up
   cd ..
   ```
2. **Run Snapshot Collection**:
   ```bash
   # Standard clean baseline:
   python collector_node.py --os windows_11 --snapshots 20 --node-id node-hamza-w11 --mode live

   # Or with Anti-Hardening Degradation (0 rules passed):
   python collector_node.py --os windows_11 --snapshots 42 --node-id node-hamza-w11 --mode live --degrade
   ```

---

#### 📤 Contributor Output & Deliverable
Once the collection run completes:
1. Two output files will be saved in `node_output/`:
   - `node_output/<node-id>_snapshots.csv` (contains the audited dataset rows)
   - `node_output/<node-id>_metadata.json` (contains the exact rule IDs and audit trace)
2. Send `<node-id>_snapshots.csv` to the project leader.
3. The project leader drops all contributor CSVs into `node_output/` and merges them with:
   ```bash
   python run_pipeline.py --merge
   ```

---

#### VM Isolation, Snapshot Count & Lifecycle Modes

1. **Defining Any Number of Snapshots (`--snapshots N` or `-n N`)**:
   - You can choose any number of snapshots for your session (e.g. `--snapshots 10`, `--snapshots 20`, `--snapshots 42`, `--snapshots 100`).
   - **Immediate Session Completion**: As soon as the requested `N` snapshots are captured, the worker **immediately finishes**, flushes the CSV and metadata JSON to disk, prints the final session summary, and exits back to your terminal prompt.
   - It will **never** destroy or recreate the VM on your final requested snapshot.

2. **Cumulative Hardening & The 55-Iteration VM Lifecycle (Default)**:
   - Command: `python collector_node.py --os <os_id> --snapshots 100 --mode live --degrade`
   - Progressively accumulates hardening rules on the same VM across iterations.
   - **How a Multi-Cycle Run Works (e.g. `--snapshots 100`)**:
     - **Iterations 1 to 55 (Cycle 1)**: Starts at 0 rules passed (with `--degrade`), progressively hardening rules slice by slice.
     - **At Iteration 55 (Automatic Lifecycle Reset)**: Because 45 snapshots remain to reach 100, the worker automatically:
       1. Destroys the saturated VM: `vagrant destroy -f`
       2. Boots a fresh VM instance: `vagrant up`
       3. Re-runs the anti-hardening unharden script (`degrade_vm.sh` / `degrade_windows.ps1`) to degrade the VM back to 0 passed rules.
       4. Resets the rule pool and initializes Cycle 2.
     - **Iterations 56 to 100 (Cycle 2)**: Collects the remaining 45 snapshots, starting from the unhardened baseline and progressively hardening the new VM.
     - **At Iteration 100 (Clean Finish)**: Upon capturing the 100th snapshot, the worker flushes all CSV and metadata files, displays the session summary, and **exits cleanly without destroying or rebuilding the VM**.
   - **Configurable Threshold**: The default recreation threshold is 55 iterations, but you can set any interval with `--lifecycle-iterations <N>` (e.g. `--lifecycle-iterations 55`). If you request $\le 55$ snapshots (e.g. `--snapshots 50`), it finishes and exits at snapshot 50 without rebuilding the VM.

3. **Anti-Hardening Degradation Mode (`--degrade` / Option 3 - True Zero Baseline)**:
   - Command: `python collector_node.py --os ubuntu_20.04 --snapshots 42 --mode live --degrade`
   - **Why this exists**: A pristine, out-of-the-box Ubuntu/Windows server naturally passes ~66 rules (because obsolete daemons like telnet/rsh/GUI are absent). If your research requires a **true zero baseline (0 rules passed at start)**, passing `--degrade` executes an anti-hardening script (`degrade_vm.sh` / `degrade_windows.ps1`) directly on the VM.
   - **Baseline at Start**: `passed_audits = 0`, `hardened_rule_count = 0`, `failed_audits = 213`, `compliance_score = 0.00%`, `risk_label = 1 (High Risk)`.
   - **Progressive Remediation**: Hardens progressively across iterations, climbing from 0.00% up toward 100% compliance.
   - **Automatic Re-degradation**: If a multi-cycle run is executed (e.g. `--snapshots 84`), every freshly recreated VM is automatically degraded again so Cycle 2 also starts cleanly at 0 passes.

4. **Clean Reset Mode (`--reset`)**:
   - Command: `python collector_node.py --os <os_id> --snapshots 20 --reset`
   - Automatically runs `vagrant snapshot restore clean_baseline --no-provision` before each snapshot for independent, isolated baseline experiments.

#### Why Active Adaptive Balancing Matters
In fresh or degraded systems, baseline compliance scores are naturally low (< 35), which would produce an 85–90% skew towards High Risk if rules are added in small random increments. 

To eliminate class imbalance in both clean reset mode and cumulative mode:
* **In Clean Reset Mode (`--reset`)**: The adaptive feedback controller strictly alternates rule sample sizes between High Risk ranges and Normal Risk ranges to maintain exact 50/50 balance.
* **In Cumulative Hardening Mode**: The **Adaptive Cumulative Trajectory Planner** partitions each collection cycle into two equal halves:
  1. **Phase 1 (High Risk Phase - First 50% of cycle)**: Paces rule hardening across the High Risk zone (Scores 0% to ~55%), guaranteeing that the first half of snapshots are `risk_label = 1`.
  2. **Phase 2 (Normal Risk Phase - Second 50% of cycle)**: Applies a prioritizing slice of critical/high rules to cross into Normal Risk (Score $\ge 70\%$), pacing the remaining rules up to 100%, guaranteeing that the second half of snapshots are `risk_label = 0`.
* **Result**: Any collection run (e.g. 20, 42, 50, 100 snapshots) achieves a **50% High Risk / 50% Normal Risk balance (1:1 ratio)**!

#### Real-time Progress Display
```text
===========================================================================
CYBERGUARD CIS DATASET GENERATION NODE - [NODE-AHMED-U20]
===========================================================================
  Target OS             : Ubuntu 20.04 LTS (ID: ubuntu_20.04, Type: 0)
  Execution Mode        : [LIVE VM PROVISIONING] or [BENCHMARK EVALUATION]
  VM Isolation Mode     : [CUMULATIVE PROGRESSIVE HARDENING]
  Benchmark Rules Pool  : 213 total rules (160 baseline failing)
  Adaptive Balancing    : Active (Targeting 50% High Risk / 50% Normal Risk)
  Snapshots Requested   : 20
  Output CSV            : ./node_output/node-ahmed-u20_snapshots.csv
  Output Metadata JSON  : ./node_output/node-ahmed-u20_metadata.json
===========================================================================

[*] Starting active collection loop...

[001] Ubuntu 20.04 LTS | Hardened:   6 rules | Audits:  72 P / 154 F | Score: 27.43 -> HIGH RISK (1) | Balance: High= 1 (100.0%) Norm= 0 ( 0.0%)
[002] Ubuntu 20.04 LTS | Hardened:  18 rules | Audits:  84 P / 142 F | Score: 36.10 -> HIGH RISK (1) | Balance: High= 2 (100.0%) Norm= 0 ( 0.0%)
[003] Ubuntu 20.04 LTS | Hardened:  88 rules | Audits: 154 P /  72 F | Score: 68.45 -> HIGH RISK (1) | Balance: High= 3 (100.0%) Norm= 0 ( 0.0%)
[004] Ubuntu 20.04 LTS | Hardened: 132 rules | Audits: 198 P /  28 F | Score: 87.21 -> NORMAL (0)    | Balance: High= 3 ( 75.0%) Norm= 1 ( 25.0%)
...
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
| `ubuntu_22.04` | Ubuntu 22.04 LTS | `0` | `Ansible-CIS-Hardener-for-Ubuntu-22...` | Level 1 & Level 2 Server |
| `ubuntu_24.04` | Ubuntu 24.04 LTS | `0` | `Ansible-CIS-Hardener-for-Ubuntu-24...` | Level 1 & Level 2 Server |
| `windows_10` | Windows 10 Enterprise | `1` | `Windows-10-CIS-Hardener` | Enterprise Level 1 & Level 2 (302 rules) |
| `windows_11` | Windows 11 Enterprise | `1` | `Windows-11-CIS-Hardener` | Enterprise Level 1 & Level 2 (336 rules) |

---

## 7. License & FYP Attribution

Developed as part of the **Final Year Project (FYP) — CyberGuard**, dedicated to empirical CIS compliance automation, machine-learning-driven vulnerability assessment, and risk prediction.
