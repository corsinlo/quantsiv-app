"""initial schema: the spec §3 tables plus share_links (WP4)

Revision ID: 0001
Revises:
Create Date: 2026-10-04 06:37:22.255262
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("github_user_id", sa.BigInteger(), nullable=False),
        sa.Column("github_login", sa.String(length=39), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("plan", sa.String(length=20), nullable=False),
        sa.Column("stripe_customer_id", sa.String(length=255), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("github_user_id"),
    )
    op.create_table(
        "installations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("github_installation_id", sa.BigInteger(), nullable=False),
        sa.Column("account_name", sa.String(length=39), nullable=False),
        sa.Column("account_type", sa.String(length=20), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("store_code_snippets", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("github_installation_id"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.Integer(), nullable=False),
        sa.Column("repo_full_name", sa.String(length=140), nullable=False),
        sa.Column("scan_type", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("triggered_by", sa.String(length=10), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["installation_id"], ["installations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_scans_installation_id"), ["installation_id"], unique=False
        )

    op.create_table(
        "cbom_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("cbom_json", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("algorithm", sa.String(length=50), nullable=False),
        sa.Column("algorithm_family", sa.String(length=20), nullable=True),
        sa.Column("primitive", sa.String(length=20), nullable=True),
        sa.Column("key_size", sa.Integer(), nullable=True),
        sa.Column("quantum_safe", sa.Boolean(), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("context_label", sa.String(length=100), nullable=True),
        sa.Column("raw_match", sa.Text(), nullable=True),
        sa.Column("snippet_hash", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_findings_scan_id"), ["scan_id"], unique=False)

    op.create_table(
        "share_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    with op.batch_alter_table("share_links", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_share_links_scan_id"), ["scan_id"], unique=False)

    op.create_table(
        "tls_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("cert_subject", sa.Text(), nullable=True),
        sa.Column("cert_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cert_algorithm", sa.String(length=50), nullable=True),
        sa.Column("cert_key_bits", sa.Integer(), nullable=True),
        sa.Column("cipher_suites", sa.JSON(), nullable=True),
        sa.Column("tls_version", sa.String(length=20), nullable=True),
        sa.Column("quantum_safe", sa.Boolean(), nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("tls_scans", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_tls_scans_scan_id"), ["scan_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("tls_scans", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tls_scans_scan_id"))

    op.drop_table("tls_scans")
    with op.batch_alter_table("share_links", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_share_links_scan_id"))

    op.drop_table("share_links")
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_scan_id"))

    op.drop_table("findings")
    op.drop_table("cbom_snapshots")
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scans_installation_id"))

    op.drop_table("scans")
    op.drop_table("installations")
    op.drop_table("users")
