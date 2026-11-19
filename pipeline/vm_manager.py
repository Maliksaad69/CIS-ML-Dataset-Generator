"""
Vagrant Virtual Machine Lifecycle Manager.
Handles VM spin-up, status checks, snapshot creation, and clean resets for independent experiments.
"""

import os
import subprocess
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from pipeline.config import ANSIBLE_DIR

class VagrantVMManager:
    """
    Manages the Ubuntu 20.04 Vagrant virtual machine.
    """
    def __init__(self, vagrant_dir: Path = ANSIBLE_DIR):
        self.vagrant_dir = Path(vagrant_dir)
        self.clean_snapshot_name = "clean_baseline"

    def _run_vagrant_command(self, args: list, timeout: int = 120) -> Tuple[int, str, str]:
        cmd = ["vagrant"] + args
        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.vagrant_dir),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return 1, "", str(e)

    def status(self) -> str:
        """Returns the current state of the Vagrant VM (e.g. running, poweroff, not_created)."""
        code, out, _ = self._run_vagrant_command(["status"])
        if "running" in out.lower():
            return "running"
        if "poweroff" in out.lower():
            return "poweroff"
        if "not created" in out.lower():
            return "not_created"
        return "unknown"

    def snapshot_save(self, snapshot_name: Optional[str] = None) -> bool:
        """Saves a named Vagrant snapshot."""
        name = snapshot_name or self.clean_snapshot_name
        code, out, err = self._run_vagrant_command(["snapshot", "save", name, "--force"])
        return code == 0

    def snapshot_restore(self, snapshot_name: Optional[str] = None) -> bool:
        """Restores a named Vagrant snapshot."""
        name = snapshot_name or self.clean_snapshot_name
        code, out, err = self._run_vagrant_command(["snapshot", "restore", name, "--no-provision"])
        return code == 0

    def reset_clean(self) -> bool:
        """
        Resets the VM to clean unhardened state to prevent cross-experiment contamination.
        Tries snapshot restore first; falls back to reload or provision reset.
        """
        # Try snapshot restore
        success = self.snapshot_restore()
        if not success:
            # Fall back to reload
            code, _, _ = self._run_vagrant_command(["reload", "--no-provision"])
            return code == 0
        return True

    def get_ssh_config(self) -> Dict[str, Any]:
        """Parses vagrant ssh-config to extract connection details."""
        code, out, _ = self._run_vagrant_command(["ssh-config"])
        if code != 0 or not out:
            # Fallback to defaults
            return {
                "hostname": "127.0.0.1",
                "port": 2222,
                "user": "vagrant",
                "identityfile": str(self.vagrant_dir / ".vagrant" / "machines" / "default" / "virtualbox" / "private_key")
            }

        config = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                k, v = parts[0].lower(), parts[1].strip().strip('"\'')
                config[k] = v

        return {
            "hostname": config.get("hostname", "127.0.0.1"),
            "port": int(config.get("port", 2222)),
            "user": config.get("user", "vagrant"),
            "identityfile": config.get("identityfile", "")
        }
