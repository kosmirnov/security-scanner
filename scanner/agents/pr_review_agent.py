from typing import List, Literal

from pydantic import BaseModel
from pydantic_ai import Agent


# --- Output models ---

class QuestionsResult(BaseModel):
    questions: List[str]  # 2-3 targeted questions about the diff


class PRVerdict(BaseModel):
    decision: Literal["APPROVE", "REQUEST CHANGES"]  # final gate decision
    feedback: str                                     # explanation of the decision


# --- Agent 1: generate questions from the diff ---

questions_agent = Agent(
    "claude-sonnet-4-6",
    output_type=QuestionsResult,
    defer_model_check=True,  # don't validate API key at import time, only when agent is called
    system_prompt=(
        "You are a senior security-focused code reviewer conducting a viva voce (oral exam) "
        "before a pull request is merged. "
        "Analyse the git diff provided and generate exactly 2-3 targeted questions that test "
        "whether the developer truly understands what they changed. "
        "Focus on: security implications, why a particular approach was chosen, "
        "and any risks or edge cases introduced by the change. "
        "Questions should be specific to the diff — not generic."
    ),
)


# --- Agent 2: evaluate answers and return a verdict ---

verdict_agent = Agent(
    "claude-sonnet-4-6",
    output_type=PRVerdict,
    defer_model_check=True,  # same as above
    system_prompt=(
        "You are a senior code reviewer evaluating a developer's answers during a PR viva voce. "
        "You will receive the original diff, the questions asked, and the developer's answers. "
        "Decide whether the answers demonstrate genuine understanding of the changes. "
        "Be strict: vague or incorrect answers should result in REQUEST CHANGES. "
        "APPROVE only if the developer clearly understands the security implications and reasoning "
        "behind their changes."
    ),
)


# --- Public API ---

async def generate_questions(diff: str) -> List[str]:
    """Analyse a git diff and return 2-3 targeted review questions."""
    result = await questions_agent.run(f"Here is the git diff to review:\n\n{diff}")
    return result.output.questions


async def generate_verdict(diff: str, questions: List[str], answers: List[str]) -> PRVerdict:
    """Evaluate the developer's answers and return an APPROVE or REQUEST CHANGES verdict."""
    # format questions and answers as a readable Q&A block
    qa_block = "\n".join(
        f"Q{i+1}: {q}\nA{i+1}: {a}"
        for i, (q, a) in enumerate(zip(questions, answers))
    )
    prompt = (
        f"Git diff:\n\n{diff}\n\n"
        f"Questions and answers:\n\n{qa_block}"
    )
    result = await verdict_agent.run(prompt)
    return result.output