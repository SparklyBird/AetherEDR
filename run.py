#!/usr/bin/env python
"""Starts everything: DB migrate, collector, API and UI.

    python run.py
"""
import multiprocessing
import sys

from aether.launcher import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # needed for PyInstaller on Windows
    sys.exit(main())
