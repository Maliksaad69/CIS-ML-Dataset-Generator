import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR
SEVERITY_CSV_PATH = BASE_DIR / "cis_rules_annotated.csv"
if not SEVERITY_CSV_PATH.exists():
    SEVERITY_CSV_PATH = BASE_DIR / "cis_rules_annotated (1).csv"

BENCHMARK_JSON_PATH = BASE_DIR / "CIS-Auditor-Linux-with-Vagrant-Environment" / "benchmarks" / "cis_ubuntu_linux_2004_lts_benchmark_v300.json"
ANSIBLE_DIR = BASE_DIR / "Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup"
AUDITOR_DIR = BASE_DIR / "CIS-Auditor-Linux-with-Vagrant-Environment"

# Directory Paths for Multi-OS Hardeners & Auditors (All self-contained in project root)
UBUNTU_20_DIR = BASE_DIR / "Ansible-CIS-Hardener-for-Ubuntu-20-with-Vagrant-Setup"
UBUNTU_22_DIR = BASE_DIR / "Ansible-CIS-Hardener-for-Ubuntu-22-with-Vagrant-Setup"
UBUNTU_24_DIR = BASE_DIR / "Ansible-CIS-Hardener-for-Ubuntu-24-with-Vagrant-Setup"
WINDOWS_10_DIR = BASE_DIR / "Windows-10-CIS-Hardener"
WINDOWS_11_DIR = BASE_DIR / "Windows-11-CIS-Hardener"
WINDOWS_AUDITOR_DIR = BASE_DIR / "CIS-Auditor-Windows"
LINUX_AUDITOR_DIR = BASE_DIR / "CIS-Auditor-Linux-with-Vagrant-Environment"

# Level 1 and Level 2 Official Audit Files for Ubuntu 20.04 LTS v3.0.0
AUDIT_L1_PATH = UBUNTU_20_DIR / "CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L1_Server.audit"
AUDIT_L2_PATH = UBUNTU_20_DIR / "CIS_Ubuntu_Linux_20.04_LTS_v3.0.0_L2_Server.audit"

# Python interpreter in virtual environment
VENV_PYTHON = Path("D:/University/FYP CyberGuard/CyberGuard-Backend/.venv/Scripts/python.exe")

# Scoring Weights (Configurable according to FYP methodology)
# High/Critical = 5.0 points, Medium = 0.5 points, Low = 5.0 points
DEFAULT_SCORING_WEIGHTS = {
    "Critical": 5.0,
    "High": 5.0,
    "Medium": 0.5,
    "Low": 5.0
}

# Risk Threshold: Compliance Score < 70 -> High Risk (1), else Normal (0)
RISK_THRESHOLD = 70.0

# OS Type Encoding: 0 = Linux, 1 = Other OS
OS_TYPE_LINUX = 0
OS_TYPE_OTHER = 1

# Exact OS Name mappings and type definitions
EXACT_OS_NAMES = {
    "ubuntu_20.04": "Ubuntu 20.04 LTS",
    "ubuntu_22.04": "Ubuntu 22.04 LTS",
    "ubuntu_24.04": "Ubuntu 24.04 LTS",
    "windows_10": "Windows 10 Enterprise",
    "windows_11": "Windows 11 Enterprise"
}

OS_TYPE_MAP = {
    "ubuntu_20.04": OS_TYPE_LINUX,
    "ubuntu_22.04": OS_TYPE_LINUX,
    "ubuntu_24.04": OS_TYPE_LINUX,
    "windows_10": OS_TYPE_OTHER,
    "windows_11": OS_TYPE_OTHER
}

# Default Output directory for distributed collection nodes
DEFAULT_NODE_OUTPUT_DIR = BASE_DIR / "node_output"

# Output Dataset Paths
OUTPUT_MASTER_DATASET = BASE_DIR / "master_cis_security_dataset.csv"
OUTPUT_SUPERVISED_DATASET = BASE_DIR / "supervised_compliance_dataset.csv"
OUTPUT_ANOMALY_DATASET = BASE_DIR / "anomaly_detection_dataset.csv"
OUTPUT_TEMPORAL_DATASET = BASE_DIR / "temporal_compliance_dataset.csv"
OUTPUT_METADATA_JSON = BASE_DIR / "experiment_metadata.json"
OUTPUT_VALIDATION_REPORT = BASE_DIR / "validation_report.md"

# SSH and Vagrant Settings
DEFAULT_SSH_HOST = "127.0.0.1"
DEFAULT_SSH_PORT = 2222
DEFAULT_SSH_USER = "vagrant"
DEFAULT_SSH_KEY = ANSIBLE_DIR / ".vagrant" / "machines" / "default" / "virtualbox" / "private_key"
