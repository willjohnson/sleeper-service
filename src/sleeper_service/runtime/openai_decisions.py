"""Typed questions and answers for OpenAI's Decisions endpoint."""

import os
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator
from pydantic_ai import BinaryContent
from pydantic_ai.exceptions import ModelHTTPError
from pydantic_ai.usage import RunUsage

MODEL = "openai:decisions/gpt-6-luna"
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    instructions: str
    name: str | None = None


class PredicateQuestion(Question):
    type: Literal["predicate"]


class Choice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    value: str | bool
    description: str | None = None


class ChoiceQuestion(Question):
    type: Literal["choice"]
    choices: Annotated[list[Choice], Field(min_length=2, max_length=255)]

    @field_validator("choices")
    @classmethod
    def unique_choices(cls, value: list[Choice]) -> list[Choice]:
        if len({choice.value for choice in value}) != len(value):
            raise ValueError("Each choice must be unique.")
        return value


class Level(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    label: str
    description: str | None = None


class ScoreQuestion(Question):
    type: Literal["score"]
    levels: Annotated[list[Level], Field(min_length=1)]


QUESTION_ADAPTER = TypeAdapter(
    Annotated[
        list[
            Annotated[
                PredicateQuestion | ChoiceQuestion | ScoreQuestion, Field(discriminator="type")
            ]
        ],
        Field(min_length=1),
    ]
)


def parse_questions(questions: list) -> list[PredicateQuestion | ChoiceQuestion | ScoreQuestion]:
    parsed = QUESTION_ADAPTER.validate_python(questions)
    names = [q.name for q in parsed if q.name is not None]
    if len(set(names)) != len(names):
        raise ValueError("Question names must be unique.")
    return parsed


class Answer(BaseModel):
    model_config = ConfigDict(strict=True)
    name: str | None


class PredicateAnswer(Answer):
    type: Literal["predicate"]
    probability: Probability


class ChoiceProbability(BaseModel):
    model_config = ConfigDict(strict=True)
    value: str | bool
    probability: Probability


class ChoiceAnswer(Answer):
    type: Literal["choice"]
    choice: str | bool
    confidence: Probability
    probabilities: list[ChoiceProbability]


class LevelProbability(BaseModel):
    model_config = ConfigDict(strict=True)
    value: int
    label: str
    probability: Probability


class ScoreAnswer(Answer):
    type: Literal["score"]
    score: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    confidence: Probability
    probabilities: list[LevelProbability]


class Refusal(Answer):
    type: Literal["refusal"]


ANSWER_ADAPTER = TypeAdapter(
    list[
        Annotated[
            PredicateAnswer | ChoiceAnswer | ScoreAnswer | Refusal, Field(discriminator="type")
        ]
    ]
)


class InputTokenDetails(BaseModel):
    cached_tokens: Annotated[int, Field(ge=0)] = 0
    cache_write_tokens: Annotated[int, Field(ge=0)] = 0


class Usage(BaseModel):
    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    input_tokens_details: InputTokenDetails = Field(default_factory=InputTokenDetails)


async def run_decisions(
    api_key: str | None,
    instructions: str,
    content: list,
    questions: list,
) -> tuple[dict, RunUsage, None]:
    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OpenAI Decisions requires an OpenAI credential or OPENAI_API_KEY.")
    parsed_questions = parse_questions(questions)
    parts = []
    images = 0
    for part in content:
        if isinstance(part, str):
            parts.append({"type": "input_text", "text": part})
        elif isinstance(part, BinaryContent) and part.is_image:
            parts.append({"type": "input_image", "image_url": part.data_uri})
            images += 1
        else:
            raise ValueError("OpenAI Decisions accepts text and images only.")
    if images > 128:
        raise ValueError("OpenAI Decisions accepts at most 128 images per request.")
    request_questions = [
        {**q, "instructions": "\n\n".join(p for p in (instructions, q["instructions"]) if p)}
        for q in questions
    ]
    model_name = MODEL.partition("/")[2]
    async with httpx.AsyncClient(timeout=None) as http:
        response = await http.post(
            "https://api.openai.com/v1/decisions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model_name,
                "input": [{"role": "user", "content": parts}],
                "questions": request_questions,
            },
        )
    if response.is_error:
        raise ModelHTTPError(response.status_code, model_name, response.text)
    data = response.json()
    answers = ANSWER_ADAPTER.validate_python(data.get("answers"))
    if len(answers) != len(parsed_questions):
        raise ValueError("OpenAI Decisions returned the wrong number of answers.")
    for question, answer in zip(parsed_questions, answers, strict=True):
        if answer.name != question.name or answer.type not in (question.type, "refusal"):
            raise ValueError("OpenAI Decisions returned an answer for the wrong question.")
        if isinstance(answer, ChoiceAnswer):
            values = {choice.value for choice in question.choices}
            returned = [p.value for p in answer.probabilities]
            if (
                answer.choice not in values
                or set(returned) != values
                or len(returned) != len(values)
            ):
                raise ValueError("OpenAI Decisions returned unknown or duplicate choices.")
        if isinstance(answer, ScoreAnswer):
            levels = {i: level.label for i, level in enumerate(question.levels)}
            if (
                answer.score > len(levels) - 1
                or len(answer.probabilities) != len(levels)
                or {p.value: p.label for p in answer.probabilities} != levels
            ):
                raise ValueError("OpenAI Decisions returned invalid score levels.")
    usage = Usage.model_validate(data.get("usage"))
    return (
        {"answers": data["answers"]},
        RunUsage(
            requests=1,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.input_tokens_details.cached_tokens,
            cache_write_tokens=usage.input_tokens_details.cache_write_tokens,
        ),
        None,
    )
