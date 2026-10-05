"""domains: DNS-verified domains for hosted TLS scans (A17)

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-05 13:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=140), nullable=False),
        sa.Column("verification_token", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidentiality_lifetime_years", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["installation_id"], ["installations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("installation_id", "domain"),
    )
    with op.batch_alter_table("domains", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_domains_installation_id"), ["installation_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("domains", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_domains_installation_id"))

    op.drop_table("domains")
