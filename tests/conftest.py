"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

# Add tests to path for azure_mock imports
tests_path = Path(__file__).parent
sys.path.insert(0, str(tests_path))
