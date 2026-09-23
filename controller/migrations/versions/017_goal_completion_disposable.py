"""Disposable legacy-stack projection of the identical reviewed completion schema."""
from pathlib import Path
import runpy
from alembic import op
from migration_source_anchor import verify_migration_source_anchor

revision = "017_goal_completion_disposable"
down_revision = "016_horizon_prereq_corr"
branch_labels = None
depends_on = None


def upgrade():
    name = str(op.get_bind().exec_driver_sql("SELECT current_database()").scalar_one())
    if not name.startswith("td_test_"):
        raise RuntimeError("legacy projection is disposable only")
    verify_migration_source_anchor(revision, source_path=__file__)
    source = Path(__file__).with_name("021_goal_completion.py")
    verify_migration_source_anchor("021_goal_completion", source_path=source)
    runpy.run_path(str(source))["upgrade"]()


def downgrade():
    raise RuntimeError("retain goal audit state; reviewed preservation procedure required")
