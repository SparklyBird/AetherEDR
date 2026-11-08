"""Builds the one-folder distributable: python scripts/build_exe.py"""
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
npm = shutil.which("npm")
if not (root / "frontend" / "dist" / "index.html").exists():
    if not npm:
        sys.exit("frontend/dist is missing and npm is not installed - build the UI on a machine with Node first.")
    subprocess.check_call([npm, "install", "--no-audit", "--no-fund"], cwd=root / "frontend")
    subprocess.check_call([npm, "run", "build"], cwd=root / "frontend")
subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
subprocess.check_call([sys.executable, "-m", "PyInstaller", "--noconfirm", "aetheredr.spec"], cwd=root)
print("\nBuilt:", root / "dist" / "AetherEDR")
