#!/usr/bin/env python3
"""
CyberGuard Unified Project CLI.
===============================
Central orchestrator for Final Year Project (FYP) CIS Compliance Dataset Generation:
- Dataset Generation (Level 1 + Level 2 benchmarks across all 213 rules)
- Distributed Node Snapshot Collection (Continuous / Multi-OS)
- Node Dataset Merging & Class Balancing
- Machine Learning Model Training (Supervised, Anomaly Detection, Temporal Trajectories)
- Comprehensive 9-Rule Data Integrity Validation
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from generate_datasets import run_experiment_pipeline
from train_models import evaluate_supervised_learning, evaluate_anomaly_detection, evaluate_temporal_analysis
from validate_datasets import run_validation
from merge_node_datasets import merge_datasets

def main():
    parser = argparse.ArgumentParser(
        description="CyberGuard CIS Compliance & Security Risk Dataset Pipeline CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  # 1. Run full end-to-end pipeline (generate baseline, train models, validate integrity):
  python run_pipeline.py --all

  # 2. Run distributed collection worker on Ubuntu 20.04 for 25 balanced snapshots:
  python run_pipeline.py --collect --os ubuntu_20.04 --snapshots 25

  # 3. Run distributed collection worker on Windows 10:
  python run_pipeline.py --collect --os windows_10 --snapshots 20

  # 4. Merge all contributor snapshots into the master datasets:
  python run_pipeline.py --merge

  # 5. Train all Machine Learning models:
  python run_pipeline.py --train

  # 6. Validate dataset integrity across all 9 requirements:
  python run_pipeline.py --validate
        """
    )
    # Primary actions
    parser.add_argument("--all", action="store_true", help="Run full pipeline: generate baseline datasets, train models, and validate")
    parser.add_argument("--generate", action="store_true", help="Generate Master, Supervised, Anomaly, and Temporal baseline datasets")
    parser.add_argument("--collect", action="store_true", help="Launch the distributed collector node for VM snapshot generation")
    parser.add_argument("--merge", action="store_true", help="Merge contributor snapshot CSVs from node_output/ into central datasets")
    parser.add_argument("--train", action="store_true", help="Train and evaluate Supervised ML, Isolation Forest, and Temporal Drift")
    parser.add_argument("--validate", action="store_true", help="Validate all 9 data integrity rules and create markdown report")
    parser.add_argument("--live-vm", action="store_true", help="Check live Vagrant VM status and verify SSH/WinRM connectivity")

    # Options for collection node
    parser.add_argument("--os", dest="os_id", type=str, default="ubuntu_20.04",
                        choices=["ubuntu_20.04", "ubuntu_22.04", "ubuntu_24.04", "windows_10", "windows_11"],
                        help="Operating system for collector node (default: ubuntu_20.04)")
    parser.add_argument("--snapshots", "-n", dest="snapshots", type=int, default=20,
                        help="Number of snapshots to collect (default: 20, 0 for continuous)")
    parser.add_argument("--continuous", dest="continuous", action="store_true",
                        help="Run continuous random hardening in an infinite loop until Ctrl+C")
    parser.add_argument("--mode", dest="mode", type=str, default="auto", choices=["auto", "live", "simulation"],
                        help="Collector execution mode: auto, live, or simulation")
    parser.add_argument("--node-id", dest="node_id", type=str, default=None,
                        help="Custom worker/contributor node identifier")
    parser.add_argument("--vagrant-dir", dest="vagrant_dir", type=str, default=None,
                        help="Custom Vagrant directory if VM is in another folder")
    parser.add_argument("--reset", dest="reset", action="store_true",
                        help="Reset VM before each snapshot (default is cumulative progressive patching on same VM)")
    parser.add_argument("--cumulative", "--no-reset", dest="cumulative", action="store_true", default=True,
                        help="Cumulative mode (default): do NOT reset VM between snapshots; progressively accumulate hardening rules")
    parser.add_argument("--lifecycle-iterations", "--recreate-after", dest="lifecycle_iterations", type=int, default=55,
                        help="Number of cumulative iterations before destroying and recreating the VM from scratch (default: 55)")
    parser.add_argument("--degrade", "--vulnerable-baseline", dest="degrade", action="store_true", default=False,
                        help="Anti-hardening mode: degrade the VM at start so it starts with 0 passed CIS rules (Option 3)")

    # Options for generation
    parser.add_argument("--iterations", type=int, default=104, help="Number of independent VM iterations for --generate (default: 104)")
    parser.add_argument("--seed", type=int, default=42, help="Base random seed for reproducibility (default: 42)")

    args = parser.parse_args()

    if not any([args.all, args.generate, args.collect, args.merge, args.train, args.validate, args.live_vm]):
        parser.print_help()
        sys.exit(0)

    # 1. Collect
    if args.collect:
        print("[*] Launching CyberGuard Collection Node Worker...")
        from collector_node import CollectionNodeWorker
        target_count = 0 if args.continuous else args.snapshots
        worker = CollectionNodeWorker(
            os_id=args.os_id,
            node_id=args.node_id,
            mode=args.mode,
            vagrant_dir=Path(args.vagrant_dir) if args.vagrant_dir else None,
            reset_between_snapshots=args.reset,
            lifecycle_iterations=args.lifecycle_iterations,
            random_seed=args.seed,
            degrade=args.degrade
        )
        worker.run(max_snapshots=target_count)
        return

    # 2. Merge
    if args.merge:
        print("[*] Merging Contributor Datasets...")
        merge_datasets()

    # 3. Generate Baseline
    if args.all or args.generate:
        print("\n[*] STEP 1: Running Dataset Generation Pipeline...")
        run_experiment_pipeline(num_independent=args.iterations, base_seed=args.seed)

    # 4. Train Models
    if args.all or args.train:
        print("\n[*] STEP 2: Running ML Models & Temporal Trajectory Analysis...")
        evaluate_supervised_learning()
        evaluate_anomaly_detection()
        evaluate_temporal_analysis()

    # 5. Validate Integrity
    if args.all or args.validate:
        print("\n[*] STEP 3: Running Comprehensive Dataset Validation...")
        run_validation()

    # 6. Live VM Connectivity
    if args.live_vm:
        print("\n[*] Checking Live VM Environment...")
        from pipeline.vm_manager import VagrantVMManager
        vm = VagrantVMManager()
        st = vm.status()
        print(f"[+] Vagrant VM Status: {st}")
        ssh_cfg = vm.get_ssh_config()
        print(f"[+] SSH Host: {ssh_cfg.get('hostname')}:{ssh_cfg.get('port')} (User: {ssh_cfg.get('user')})")

    print("\n[+] CyberGuard Command Execution Complete!")

if __name__ == "__main__":
    main()
