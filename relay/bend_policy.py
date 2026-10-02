"""Narrow process boundary to the checked, compiled Bend admission function."""
import subprocess
from pathlib import Path


class BendPolicy:
    def __init__(self, executable):
        self.executable = str(Path(executable).resolve(strict=True))

    def admit(self, granted, hop):
        if type(hop) is not int or not 0 <= hop <= 100:
            return False
        try:
            result = subprocess.run([self.executable], env={"RELAY_GRANTED": "yes" if granted else "no", "RELAY_HOP": str(hop)}, capture_output=True, timeout=2, check=True)
            return result.stdout == b"allow\n"
        except (OSError, subprocess.SubprocessError):
            return False  # Missing, failing or hanging executable never grants access.
