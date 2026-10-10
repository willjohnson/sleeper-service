"""Typed decision routing and agent configuration validation."""

import os
from decimal import Decimal
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.usage import RunUsage

from sleeper_service.runtime import openai_decisions

Content = str | dict | list
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class NoulCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    true: Content
    false: Content


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    instructions: Content


class NoulQuestion(Question):
    type: Literal["noul"]
    criteria: NoulCriteria | None = None

    @field_validator("criteria")
    @classmethod
    def criteria_if_supplied(cls, value: NoulCriteria | None) -> NoulCriteria:
        if value is None:
            raise ValueError("Omit criteria or supply both true and false descriptions.")
        return value


class ChoiceQuestion(Question):
    type: Literal["choice"]
    criteria: Annotated[dict[str, Content | None], Field(min_length=1)]


class ScoreQuestion(Question):
    type: Literal["score"]
    criteria: Annotated[list[str | dict | list], Field(min_length=1)]


Questions = Annotated[
    dict[
        Annotated[str, Field(min_length=1)],
        Annotated[NoulQuestion | ChoiceQuestion | ScoreQuestion, Field(discriminator="type")],
    ],
    Field(min_length=1),
]
QUESTION_ADAPTER = TypeAdapter(Questions)


class NoulAnswer(BaseModel):
    type: Literal["noul"]
    noul: Probability


class ChoiceAnswer(BaseModel):
    type: Literal["choice"]
    choice: str
    confidence: Probability | None = None
    probabilities: dict[str, Probability] | None = None


class ScoreAnswer(BaseModel):
    type: Literal["score"]
    score: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    confidence: Probability | None = None
    probabilities: dict[str, Probability] | None = None
    legend: dict[str, Content] | None = None


ANSWER_ADAPTER = TypeAdapter(
    dict[str, Annotated[NoulAnswer | ChoiceAnswer | ScoreAnswer, Field(discriminator="type")]]
)


class DecisionUsage(BaseModel):
    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    cost: Annotated[Decimal, Field(ge=0, allow_inf_nan=False)] | None = None


def is_decision_model(model_string: str) -> bool:
    return model_string == openai_decisions.MODEL or model_string.startswith(
        ("openrouter:typesafe/jev-", "openrouter:~typesafe/jev-")
    )


def validate_decision_config(
    model_string: str,
    params: dict | None,
    *,
    tool_grants: list | None = None,
    data_store_grants: list | None = None,
    options: dict | None = None,
    output_schema: dict | None = None,
) -> str | None:
    if not is_decision_model(model_string):
        return None
    openai = model_string == openai_decisions.MODEL
    label = "OpenAI Decisions" if openai else "Jev"
    params = params or {}
    if set(params) != {"questions"}:
        return f"{label} Params must contain only 'questions'; chat parameters are not supported."
    try:
        if openai:
            openai_decisions.parse_questions(params["questions"])
        else:
            QUESTION_ADAPTER.validate_python(params["questions"])
    except (ValidationError, ValueError) as exc:
        return f"Invalid {label} questions: {exc}"
    if tool_grants or data_store_grants:
        return f"{label} cannot call tools; remove MCP and data store grants."
    options = options or {}
    if options.get("delegation") in ("team", "tenant") or any(
        options.get(key) is True for key in ("memory", "learning", "human_escalation")
    ):
        return f"{label} does not support delegation, memory, learning, or human escalation tools."
    if output_schema is not None:
        return f"{label} returns typed answers; leave Output schema blank and set Params.questions."
    return None


async def run_decisions(
    model_string: str,
    api_key: str | None,
    instructions: str,
    content: list,
    questions: dict | list,
) -> tuple[dict, RunUsage, Decimal | None]:
    if model_string == openai_decisions.MODEL:
        return await openai_decisions.run_decisions(api_key, instructions, content, questions)
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("Jev requires an OpenRouter credential or OPENROUTER_API_KEY.")
    if any(not isinstance(part, str) for part in content):
        raise ValueError("Jev accepts text only; binary attachments are not supported.")
    parsed_questions = QUESTION_ADAPTER.validate_python(questions)
    model_name = model_string.partition(":")[2]
    async with httpx.AsyncClient(timeout=None) as http:
        response = await http.post(
            "https://openrouter.ai/api/v1/systemone",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model_name,
                "state": {"instructions": instructions, "content": content},
                "questions": questions,
            },
        )
    if response.is_error:
        raise ModelHTTPError(response.status_code, model_name, response.text)
    data = response.json()
    answers = ANSWER_ADAPTER.validate_python(data.get("answers"))
    if answers.keys() != parsed_questions.keys():
        raise ValueError("Jev returned answers that do not match the requested questions.")
    for name, question in parsed_questions.items():
        answer = answers[name]
        if answer.type != question.type:
            raise ValueError(f"Jev returned the wrong answer type for {name!r}.")
        if isinstance(question, ChoiceQuestion) and (
            answer.choice not in question.criteria
            or (
                answer.probabilities is not None
                and answer.probabilities.keys() != question.criteria.keys()
            )
        ):
            raise ValueError(f"Jev returned unknown choices for {name!r}.")
        if isinstance(question, ScoreQuestion):
            levels = {str(i) for i in range(len(question.criteria))}
            if (
                answer.score > len(question.criteria) - 1
                or (answer.probabilities is not None and answer.probabilities.keys() != levels)
                or (
                    answer.legend is not None
                    and answer.legend
                    != {str(i): level for i, level in enumerate(question.criteria)}
                )
            ):
                raise ValueError(f"Jev returned invalid score levels for {name!r}.")
    usage = DecisionUsage.model_validate(data.get("usage"))
    return (
        {"answers": data["answers"]},
        RunUsage(requests=1, input_tokens=usage.input_tokens, output_tokens=usage.output_tokens),
        usage.cost,
    )
