"""drop event_sources.config

The column was transcribed from the schema sketch in BUILD_PLAN and never
given a meaning: it was written by POST /v1/tenants/{id}/event-sources and
read by nothing — ingest resolves a source entirely through payload_template,
dedup_key_path and secret_hash. Keeping it round-tripping through
EventSourceOut would have turned an inert field into a compatibility
obligation now that the repo is public. If per-source configuration is ever
needed (per-source webhook signature verification is the plausible case), it
should arrive as named, validated columns the way its two siblings did.

Revision ID: d3f5a91c07be
Revises: 560d0a73c748
Create Date: 2026-08-24 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "d3f5a91c07be"
down_revision: Union[str, Sequence[str], None] = "560d0a73c748"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_column("event_sources", "config")


def downgrade() -> None:
    """Downgrade schema."""
    # The original column is NOT NULL with no server default, which existing
    # rows cannot satisfy on the way back. Add it with a default so the
    # backfill is '{}' — the value every row held anyway, since nothing wrote
    # anything else — then drop the default to restore the original shape.
    op.add_column(
        "event_sources",
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.alter_column("event_sources", "config", server_default=None)
