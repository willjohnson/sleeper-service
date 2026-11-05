"""versioned tenant and team system prompts

Tenant prompts move out of tenants.system_prompt into prompt_versions, which
also holds team prompts (team_id set). Every job pins the tenant and team
prompt versions it ran with. An existing non-empty tenant prompt becomes
version 1 of that tenant's history; an empty one leaves no history, which is
what an empty prompt means.

Revision ID: e5b8c2d47a19
Revises: 6e2f7a9c1b44
Create Date: 2026-11-05 07:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e5b8c2d47a19"
down_revision: str | None = "6e2f7a9c1b44"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "prompt_versions",
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("team_id", sa.UUID(), nullable=True),
        sa.Column("version_no", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_prompt_versions_created_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["team_id"],
            ["teams.id"],
            name=op.f("fk_prompt_versions_team_id_teams"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_prompt_versions_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_prompt_versions")),
        sa.UniqueConstraint(
            "tenant_id",
            "team_id",
            "version_no",
            name=op.f("uq_prompt_versions_tenant_id_team_id_version_no"),
            postgresql_nulls_not_distinct=True,
        ),
    )
    op.execute(
        "INSERT INTO prompt_versions (id, tenant_id, version_no, content) "
        "SELECT gen_random_uuid(), id, 1, system_prompt FROM tenants WHERE system_prompt <> ''"
    )
    op.drop_column("tenants", "system_prompt")

    for column in ("tenant_prompt_version_id", "team_prompt_version_id"):
        op.add_column("jobs", sa.Column(column, sa.UUID(), nullable=True))
        op.create_foreign_key(
            op.f(f"fk_jobs_{column}_prompt_versions"),
            "jobs",
            "prompt_versions",
            [column],
            ["id"],
        )


def downgrade() -> None:
    for column in ("tenant_prompt_version_id", "team_prompt_version_id"):
        op.drop_constraint(op.f(f"fk_jobs_{column}_prompt_versions"), "jobs", type_="foreignkey")
        op.drop_column("jobs", column)

    # NOT NULL with no server default originally: add it with '' so tenants
    # without a history get the empty prompt, fill in each tenant's latest
    # version, then drop the default to restore the original shape. Team
    # prompts have no column to return to and are lost.
    op.add_column(
        "tenants",
        sa.Column("system_prompt", sa.Text(), nullable=False, server_default=""),
    )
    op.execute(
        "UPDATE tenants SET system_prompt = latest.content FROM ("
        "  SELECT DISTINCT ON (tenant_id) tenant_id, content FROM prompt_versions"
        "  WHERE team_id IS NULL ORDER BY tenant_id, version_no DESC"
        ") AS latest WHERE latest.tenant_id = tenants.id"
    )
    op.alter_column("tenants", "system_prompt", server_default=None)
    op.drop_table("prompt_versions")
