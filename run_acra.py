#!/usr/bin/env python3
"""
ACRA Runner Script
This script makes it easy to run ACRA from the project root.
"""

import sys
import os
from pathlib import Path

# Add src to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Now import and run main
from main import main

if __name__ == "__main__":
    main()

