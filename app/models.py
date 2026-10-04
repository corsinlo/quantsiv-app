"""Placeholder models.

WP4 replaces these with SQLAlchemy 2.0 declarative models for the spec §3 tables (A03). Until
then they are plain classes so that `app.api` imports.
"""

from enum import StrEnum


class ScanStatus(StrEnum):
    """The one scan status vocabulary for the worker, the API and the templates (A32)."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class User:
    pass


class Installation:
    pass


class Scan:
    pass
