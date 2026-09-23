"""Real mount-boundary regression; the 'exposed host store' is disposable."""
import os
from pathlib import Path
import subprocess
import sys

from test_only.isolation import require_isolation
REPO_ROOT=Path(__file__).resolve().parents[1]


def test_exposed_store_blocks_actual_child_submission_fixture(tmp_path, controller_test_support):
    ADMIN_URL=controller_test_support.ADMIN_URL
    require_isolation(ADMIN_URL)
    exposed=tmp_path/'stand-in-host-store'
    exposed.mkdir()
    sentinel=exposed/'existing-consumer-bundle'
    sentinel.write_text('must remain unchanged')
    result=subprocess.run([
        'unshare','--mount','--fork','sh','-c',
        'mount --make-rprivate / && mount --bind "$1" /var/lib/top-delivery-submission-bundles && exec "$2" -m pytest -q -p no:cacheprovider --tb=short controller/test_goal_completion.py::test_child_graph_completion_is_not_whole_parent',
        'test-isolation',str(exposed),sys.executable,
    ],cwd=REPO_ROOT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),capture_output=True,text=True,timeout=60)
    assert result.returncode==1,result.stdout+result.stderr
    assert 'privileged tests require private tmpfs: /var/lib/top-delivery-submission-bundles' in result.stdout
    assert list(exposed.iterdir())==[sentinel]
    assert sentinel.read_text()=='must remain unchanged'
    # The outer private mount remains valid after the child namespace exits.
    require_isolation(ADMIN_URL)
