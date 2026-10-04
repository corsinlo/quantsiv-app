"""api tokens and cbom provenance: CI uploads (WP7)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-04 06:57:13.903243
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("prefix", sa.String(length=12), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["installation_id"], ["installations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    with op.batch_alter_table("api_tokens", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_api_tokens_installation_id"), ["installation_id"], unique=False
        )

    with op.batch_alter_table("cbom_snapshots", schema=None) as batch_op:
        batch_op.add_column(sa.Column("producer", sa.String(length=200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cbom_snapshots", schema=None) as batch_op:
        batch_op.drop_column("producer")

    with op.batch_alter_table("api_tokens", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_api_tokens_installation_id"))

    op.drop_table("api_tokens")
