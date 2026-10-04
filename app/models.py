"""SQLAlchemy 2.0 models for the spec §3 tables, plus share_links (A03, A23, A39, A51).

Postgres in deployment, SQLite only for local tests: no dialect-specific types.
"""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class ScanStatus(StrEnum):
    """The one scan status vocabulary for the worker, the API and the templates (A32)."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    github_user_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    github_login: Mapped[str] = mapped_column(String(39))
    email: Mapped[str | None] = mapped_column(String(320))
    plan: Mapped[str] = mapped_column(String(20), default="free")
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255))
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    installations: Mapped[list["Installation"]] = relationship(back_populates="user")


class Installation(Base):
    __tablename__ = "installations"

    id: Mapped[int] = mapped_column(primary_key=True)
    github_installation_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    account_name: Mapped[str] = mapped_column(String(39))
    account_type: Mapped[str] = mapped_column(String(20))  # "User" | "Organization"
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Raw code snippets are opt-in per tenant; by default only a hash is kept (A39)
    store_code_snippets: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User | None] = relationship(back_populates="installations")
    scans: Mapped[list["Scan"]] = relationship(back_populates="installation")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    installation_id: Mapped[int] = mapped_column(
        ForeignKey("installations.id", ondelete="CASCADE"), index=True
    )
    repo_full_name: Mapped[str] = mapped_column(String(140))
    scan_type: Mapped[str] = mapped_column(String(10), default="source")  # source|tls|both
    status: Mapped[str] = mapped_column(String(10), default=ScanStatus.QUEUED)
    triggered_by: Mapped[str] = mapped_column(String(10))  # push|manual|scheduled|action
    # Only ScanError messages are stored here; anything else is "Internal error" (A15)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    installation: Mapped[Installation] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Finding.id"
    )
    cbom: Mapped["CbomSnapshot | None"] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    tls_scans: Mapped[list["TlsScan"]] = relationship(cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    file_path: Mapped[str | None] = mapped_column(Text)  # NULL for TLS findings
    line_number: Mapped[int | None] = mapped_column(Integer)
    algorithm: Mapped[str] = mapped_column(String(50))
    algorithm_family: Mapped[str | None] = mapped_column(String(20))
    # CycloneDX crypto primitive (signature, key-agree, kem, pke, ...); WP6 fills it
    primitive: Mapped[str | None] = mapped_column(String(20))
    # Dual-track scoring (WP6): "HNDL", "signature deadline" or "severity"
    track: Mapped[str | None] = mapped_column(String(20))
    lifetime_years: Mapped[int | None] = mapped_column(Integer)
    reason: Mapped[str | None] = mapped_column(Text)
    key_size: Mapped[int | None] = mapped_column(Integer)
    quantum_safe: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[float | None] = mapped_column(Float)
    context_label: Mapped[str | None] = mapped_column(String(100))
    raw_match: Mapped[str | None] = mapped_column(Text)  # only if store_code_snippets (A39)
    snippet_hash: Mapped[str | None] = mapped_column(String(64))

    scan: Mapped[Scan] = relationship(back_populates="findings")


class CbomSnapshot(Base):
    __tablename__ = "cbom_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), unique=True)
    cbom_json: Mapped[dict] = mapped_column(JSON)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    # Provenance (WP7): the tool that produced the CBOM, from metadata.tools
    producer: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="cbom")


class TlsScan(Base):
    __tablename__ = "tls_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(253))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer, default=443)
    cert_subject: Mapped[str | None] = mapped_column(Text)
    cert_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cert_algorithm: Mapped[str | None] = mapped_column(String(50))
    cert_key_bits: Mapped[int | None] = mapped_column(Integer)
    cipher_suites: Mapped[list | None] = mapped_column(JSON)
    tls_version: Mapped[str | None] = mapped_column(String(20))
    quantum_safe: Mapped[bool] = mapped_column(Boolean, default=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiToken(Base):
    """Organisation API tokens for CI uploads (WP7): `qsv_` + 32 random bytes, stored only as
    SHA-256, shown once, revocable. Scoped to one installation."""

    __tablename__ = "api_tokens"
    __table_args__ = (UniqueConstraint("token_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    installation_id: Mapped[int] = mapped_column(
        ForeignKey("installations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    prefix: Mapped[str] = mapped_column(String(12))  # shown in the list, e.g. "qsv_AbCd"
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    installation: Mapped[Installation] = relationship()


class ShareLink(Base):
    """Revocable share links (A23): a random 32-byte token, stored only as its SHA-256."""

    __tablename__ = "share_links"
    __table_args__ = (UniqueConstraint("token_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


async def upsert_user(db: AsyncSession, github_user_id: int, github_login: str) -> User:
    """The users row for a GitHub user; logins can be renamed on GitHub, so keep it current."""
    user = await db.scalar(select(User).where(User.github_user_id == github_user_id))
    if user is None:
        user = User(github_user_id=github_user_id, github_login=github_login)
        db.add(user)
    else:
        user.github_login = github_login
    return user
