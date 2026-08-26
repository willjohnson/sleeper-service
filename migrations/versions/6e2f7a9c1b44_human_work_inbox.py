"""human work inbox and escalation

Revision ID: 6e2f7a9c1b44
Revises: b4a1f2e83c67
Create Date: 2026-08-26 06:55:00.000000
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "6e2f7a9c1b44"
down_revision: str | None = "b4a1f2e83c67"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "work_items",
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("team_id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.UUID(), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("memory_version_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), server_default="open", nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("resolution", sa.String(), nullable=True),
        sa.Column("response", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("resolved_by_user_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('memory_approval', 'human_escalation')",
            name=op.f("ck_work_items_kind_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'resolved', 'dismissed')",
            name=op.f("ck_work_items_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_work_items_agent_id_agents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["jobs.id"], name=op.f("fk_work_items_job_id_jobs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["memory_version_id"],
            ["memory_versions.id"],
            name=op.f("fk_work_items_memory_version_id_memory_versions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by_user_id"],
            ["users.id"],
            name=op.f("fk_work_items_resolved_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["team_id"], ["teams.id"], name=op.f("fk_work_items_team_id_teams"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_work_items_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_work_items")),
        sa.UniqueConstraint("memory_version_id", name=op.f("uq_work_items_memory_version_id")),
    )
    op.create_index("ix_work_items_team_status", "work_items", ["team_id", "status"], unique=False)
    op.create_index(
        "ix_work_items_tenant_status_created",
        "work_items",
        ["tenant_id", "status", "created_at"],
        unique=False,
    )

    # Existing pending memory changes should appear in the new inbox on the
    # first boot after upgrade. IDs are generated here because UUID primary
    # keys intentionally have no server-side default in this schema.
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                """
            SELECT mv.id AS memory_version_id, mv.source_job_id, mv.version_no,
                   mv.created_at, a.id AS agent_id, a.tenant_id, a.team_id, a.name
            FROM memory_versions mv
            JOIN agents a ON a.id = mv.agent_id
            WHERE mv.status = 'pending'
            """
            )
        )
        .mappings()
    )
    inbox = sa.table(
        "work_items",
        sa.column("id", sa.UUID()),
        sa.column("tenant_id", sa.UUID()),
        sa.column("team_id", sa.UUID()),
        sa.column("agent_id", sa.UUID()),
        sa.column("job_id", sa.UUID()),
        sa.column("memory_version_id", sa.UUID()),
        sa.column("kind", sa.String()),
        sa.column("status", sa.String()),
        sa.column("title", sa.Text()),
        sa.column("details", postgresql.JSONB()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    pending = [
        {
            "id": uuid.uuid4(),
            "tenant_id": row["tenant_id"],
            "team_id": row["team_id"],
            "agent_id": row["agent_id"],
            "job_id": row["source_job_id"],
            "memory_version_id": row["memory_version_id"],
            "kind": "memory_approval",
            "status": "open",
            "title": f"Review memory v{row['version_no']} for {row['name']}",
            "details": {"memory_version_no": row["version_no"]},
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    if pending:
        op.bulk_insert(inbox, pending)


def downgrade() -> None:
    op.drop_index("ix_work_items_tenant_status_created", table_name="work_items")
    op.drop_index("ix_work_items_team_status", table_name="work_items")
    op.drop_table("work_items")
