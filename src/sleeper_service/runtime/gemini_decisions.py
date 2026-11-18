"""Typed questions and answers for Google's Gemini Decisions endpoint."""

import base64
import os
from decimal import Decimal
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from pydantic_ai import BinaryContent
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.usage import RunUsage

MODEL = "google:gemini-decision-1"
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/decisions"
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class NoulCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    true_description: str
    false_description: str


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    instructions: str


class NoulQuestion(Question):
    type: Literal["noul"]
    criteria: NoulCriteria | None = None


class ChoiceQuestion(Question):
    type: Literal["choice"]
    criteria: Annotated[dict[str, str | None], Field(min_length=2, max_length=255)]


class ScoreQuestion(Question):
    type: Literal["score"]
    legend: Annotated[list[str], Field(min_length=2, max_length=255)]


Questions = Annotated[
    dict[
        Annotated[str, Field(min_length=1)],
        Annotated[NoulQuestion | ChoiceQuestion | ScoreQuestion, Field(discriminator="type")],
    ],
    Field(min_length=1, max_length=1000),
]
QUESTION_ADAPTER = TypeAdapter(Questions)


def parse_questions(questions: dict) -> dict[str, NoulQuestion | ChoiceQuestion | ScoreQuestion]:
    return QUESTION_ADAPTER.validate_python(questions)


class NoulAnswer(BaseModel):
    model_config = ConfigDict(strict=True)
    type: Literal["noul"]
    noul: Probability
    confidence: Probability | None = None


class ChoiceAnswer(BaseModel):
    model_config = ConfigDict(strict=True)
    type: Literal["choice"]
    choice: str
    confidence: Probability | None = None
    probabilities: dict[str, Probability] | None = None


class ScoreAnswer(BaseModel):
    model_config = ConfigDict(strict=True)
    type: Literal["score"]
    score: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    confidence: Probability | None = None
    probabilities: dict[str, Probability] | None = None


ANSWER_ADAPTER = TypeAdapter(
    dict[str, Annotated[NoulAnswer | ChoiceAnswer | ScoreAnswer, Field(discriminator="type")]]
)


class Usage(BaseModel):
    total_input_tokens: Annotated[int, Field(ge=0)]
    total_output_tokens: Annotated[int, Field(ge=0)] = 0
    estimated_cost_usd: Annotated[Decimal, Field(ge=0, allow_inf_nan=False)] | None = None


def _encode_input(content: list) -> str | list[dict]:
    if all(isinstance(part, str) for part in content):
        return "\n\n".join(content)
    parts: list[dict] = []
    for part in content:
        if isinstance(part, str):
            parts.append({"text": part})
        elif isinstance(part, BinaryContent):
            parts.append(
                {
                    "inlineData": {
                        "mimeType": part.media_type,
                        "data": base64.b64encode(part.data).decode("ascii"),
                    }
                }
            )
        else:
            raise ValueError("Gemini Decisions accepts text and binary attachments only.")
    return parts


async def run_decisions(
    api_key: str | None,
    instructions: str,
    content: list,
    questions: dict,
) -> tuple[dict, RunUsage, Decimal | None]:
    api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError(
            "Gemini Decisions requires a Google credential or GEMINI_API_KEY / GOOGLE_API_KEY."
        )
    try:
        parsed_questions = parse_questions(questions)
    except ValidationError as exc:
        raise ValueError(f"Invalid Gemini Decisions questions: {exc}") from exc

    encoded_input = _encode_input(content)
    request_questions = {
        name: {
            **q,
            "instructions": "\n\n".join(p for p in (instructions, q["instructions"]) if p),
        }
        for name, q in questions.items()
    }
    model_name = MODEL.partition(":")[2]
    async with httpx.AsyncClient(timeout=None) as http:
        response = await http.post(
            ENDPOINT,
            headers={"x-goog-api-key": api_key},
            json={
                "model": model_name,
                "input": encoded_input,
                "questions": request_questions,
            },
        )
    if response.is_error:
        raise ModelHTTPError(response.status_code, model_name, response.text)
    data = response.json()
    answers = ANSWER_ADAPTER.validate_python(data.get("answers"))
    if answers.keys() != parsed_questions.keys():
        raise ValueError(
            "Gemini Decisions returned answers that do not match the requested questions."
        )
    for name, question in parsed_questions.items():
        answer = answers[name]
        if answer.type != question.type:
            raise ValueError(f"Gemini Decisions returned the wrong answer type for {name!r}.")
        if isinstance(question, ChoiceQuestion) and (
            answer.choice not in question.criteria
            or (
                answer.probabilities is not None
                and answer.probabilities.keys() != question.criteria.keys()
            )
        ):
            raise ValueError(f"Gemini Decisions returned unknown choices for {name!r}.")
        if isinstance(question, ScoreQuestion):
            levels = {str(i) for i in range(len(question.legend))}
            if answer.score > len(question.legend) - 1 or (
                answer.probabilities is not None and answer.probabilities.keys() != levels
            ):
                raise ValueError(f"Gemini Decisions returned invalid score levels for {name!r}.")
    usage = Usage.model_validate(data.get("usage"))
    return (
        {"answers": data["answers"]},
        RunUsage(
            requests=1,
            input_tokens=usage.total_input_tokens,
            output_tokens=usage.total_output_tokens,
        ),
        usage.estimated_cost_usd,
    )
