"""Feedback on job results (BUILD_PLAN § Memory & learning).

Authenticated by the single-job-scoped signed token from the feedback URL —
no platform key needed, because only the party that received the result holds
the URL. One vote per job; the fold into memory runs in the background.
"""

import hmac
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleeper_service.api.v1.schemas import FeedbackCreate, FeedbackOut
from sleeper_service.db.models import Agent, Feedback, Job
from sleeper_service.db.session import get_db
from sleeper_service.queue import get_pool
from sleeper_service.runtime.learning import feedback_token
from sleeper_service.runtime.memory import learning_enabled

router = APIRouter(prefix="/feedback", tags=["feedback"])


@router.post("/{job_id}", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    job_id: uuid.UUID,
    body: FeedbackCreate,
    token: str = "",
    db: AsyncSession = Depends(get_db),
) -> Feedback:
    if not token or not hmac.compare_digest(token, feedback_token(job_id)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid feedback token")
    job = await db.get(Job, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    agent = await db.get(Agent, job.agent_id)
    if not learning_enabled(agent.options or {}):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This agent does not accept feedback")
    existing = await db.scalar(select(Feedback).where(Feedback.job_id == job_id))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Feedback already recorded")

    fb = Feedback(job_id=job_id, vote=body.vote, comment=body.comment)
    db.add(fb)
    await db.commit()
    await db.refresh(fb)

    pool = await get_pool()
    await pool.enqueue_job("fold_feedback", str(fb.id))
    return fb
