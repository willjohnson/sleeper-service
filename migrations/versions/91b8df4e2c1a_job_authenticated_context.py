"""Add server-derived authenticated context to jobs.

Revision ID: 91b8df4e2c1a
Revises: 2adce1965843
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "91b8df4e2c1a"
down_revision: str | None = "2adce1965843"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "jobs", sa.Column("auth_ctx", postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("jobs", "auth_ctx")
