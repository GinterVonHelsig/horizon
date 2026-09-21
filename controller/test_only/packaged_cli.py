"""SIMULATED service identity, actual staged CLI; private pytest namespaces only."""
import os
from pathlib import Path
import runpy
import sys

import pytest  # Explicit existing test seam; never a production entry point.
target = Path(sys.argv[1]).resolve(strict=True)
if target.name not in {'goal_cli.py', 'worker_cli.py'}:
    raise ValueError('unsupported test CLI')
sys.path.insert(0, str(target.parent))
from test_only.isolation import require_isolation
from test_only.disposable_harness import enable_disposable_harness
import authority_test_seam
assert Path(authority_test_seam.__file__).resolve() == target.parent/'authority_test_seam.py'
require_isolation(os.environ['TOP_DELIVERY_PG_ADMIN_URL'])
enable_disposable_harness()
sys.argv = sys.argv[1:]
runpy.run_path(str(target), run_name='__main__')
