"""Agent-to-agent delegation (BUILD_PLAN § Agent-to-agent delegation).

Two built-in tools, granted when `options.delegation` is "team" or "tenant":

- `list_agents` — the rolodex: every agent the caller may delegate to, with
  name, description, and input/output schemas, so the model knows who exists
  and what payload shape they expect.
- `call_agent` — creates a child job (parent_job_id = the calling job, so the
  whole tree is auditable) and runs it inline, returning the child's output.

Guardrails: delegation depth capped (settings.max_delegation_depth, walked
via the parent_job_id chain), cycle detection over ancestor agent ids, and
each participating agent's own monthly budget applies to its jobs.
"""

import uuid

from pydantic_ai import ModelRetry
from pydantic_ai.toolsets import AbstractToolset, FunctionToolset
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.config import get_settings
from sleeper_service.db.models import Agent, AgentVersion, Job
from sleeper_service.db.session import get_sessionmaker


def delegation_scope(agent: Agent) -> str:
    scope = (agent.options or {}).get("delegation", "none")
    return scope if scope in ("team", "tenant") else "none"


async def _permitted_agents(db: AsyncSession, caller: Agent) -> list[Agent]:
    scope = delegation_scope(caller)
    if scope == "none":
        return []
    stmt = select(Agent).where(Agent.tenant_id == caller.tenant_id, Agent.id != caller.id)
    if scope == "team":
        stmt = stmt.where(Agent.team_id == caller.team_id)
    return list(await db.scalars(stmt.order_by(Agent.name)))


async def _ancestry(db: AsyncSession, job: Job) -> tuple[int, set[uuid.UUID]]:
    """Depth of this job in the tree and the set of agent ids above it."""
    depth = 0
    agent_ids: set[uuid.UUID] = {job.agent_id}
    current = job
    while current.parent_job_id is not None:
        current = await db.get(Job, current.parent_job_id)
        if current is None:
            break
        depth += 1
        agent_ids.add(current.agent_id)
    return depth, agent_ids


def build_delegation_toolset(caller: Agent, job_id: uuid.UUID) -> AbstractToolset | None:
    if delegation_scope(caller) == "none":
        return None

    async def list_agents() -> list[dict]:
        """List the agents you may delegate to: their names, what they do,
        and the input/output shapes they expect."""
        async with get_sessionmaker()() as db:
            agents = await _permitted_agents(db, caller)
            catalog = []
            for a in agents:
                version = (
                    await db.get(AgentVersion, a.current_version_id)
                    if a.current_version_id
                    else None
                )
                catalog.append(
                    {
                        "name": a.name,
                        "description": a.description,
                        "input_schema": version.input_schema if version else None,
                        "output_schema": version.output_schema if version else None,
                        "available": version is not None,
                    }
                )
            return catalog

    async def call_agent(agent_name: str, prompt: str) -> dict:
        """Delegate a task to another agent by name (see list_agents). Returns
        the child agent's output. The child runs as its own audited job."""
        from sleeper_service.runtime import runner as runner_mod

        async with get_sessionmaker()() as db:
            targets = {a.name: a for a in await _permitted_agents(db, caller)}
            if agent_name not in targets:
                raise ModelRetry(
                    f"agent {agent_name!r} is not in your delegation scope; "
                    f"available: {sorted(targets)}"
                )
            target = targets[agent_name]
            if target.current_version_id is None:
                raise ModelRetry(f"agent {agent_name!r} has no runnable version")

            job = await db.get(Job, job_id)
            depth, ancestor_agents = await _ancestry(db, job)
            max_depth = get_settings().max_delegation_depth
            if depth + 1 >= max_depth:
                raise ModelRetry(
                    f"delegation depth limit ({max_depth}) reached — handle this yourself"
                )
            if target.id in ancestor_agents:
                raise ModelRetry(
                    f"delegating to {agent_name!r} would create a cycle "
                    "(it is already in this job's call chain)"
                )

            version = await db.get(AgentVersion, target.current_version_id)
            child = Job(
                agent_id=target.id,
                agent_version_id=version.id,
                parent_job_id=job.id,
                payload={"prompt": prompt},
                user_ctx=job.user_ctx,
            )
            db.add(child)
            await db.commit()
            child_id = child.id

        try:
            await runner_mod.execute_job(child_id)
        except runner_mod.TransientJobError as e:
            # No retry budget inside a parent's run — surface it to the model.
            await runner_mod.mark_job(child_id, "failed", f"transient provider error: {e}")

        async with get_sessionmaker()() as db:
            child = await db.get(Job, child_id)
            return {
                "job_id": str(child.id),
                "agent": agent_name,
                "status": child.status,
                "output": child.output,
                "error": child.error,
            }

    return FunctionToolset([list_agents, call_agent], id="delegation")
