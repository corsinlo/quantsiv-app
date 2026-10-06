"""scans: which uploads are default-branch baselines (WP12)

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-06 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("branch", sa.String(length=200), nullable=True))
        batch_op.add_column(
            sa.Column("baseline", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    # Before WP12 every CBOM upload was compared against, so every one counts as a baseline
    op.execute("UPDATE scans SET baseline = TRUE WHERE scan_type = 'cbom'")


def downgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_column("baseline")
        batch_op.drop_column("branch")
