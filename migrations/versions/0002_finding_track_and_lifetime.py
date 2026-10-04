"""finding track and lifetime: dual-track scoring results (WP6)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-04 06:49:31.967980
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("track", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("lifetime_years", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("reason", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("reason")
        batch_op.drop_column("lifetime_years")
        batch_op.drop_column("track")
