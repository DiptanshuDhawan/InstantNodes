"""API response models for the native NetSimX runtime."""

from typing import List, Optional, Union

from pydantic import BaseModel, Field


class LabSummary(BaseModel):
    id: int
    slug: str
    title: str
    topic: str
    difficulty: str
    description: str
    estimated_time_minutes: int


class NodeStatus(BaseModel):
    name: str
    status: str
    kind: str
    cli_profile: str


class LinkStatus(BaseModel):
    node_a: str
    interface_a: str
    node_b: str
    interface_b: str
    status: str


class NodeGradeResult(BaseModel):
    node: str
    passed: bool
    missing_lines: List[str]
    error: str = ""


class GradeFinding(BaseModel):
    """One student-facing problem the grader found."""

    node: str = ""
    kind: str  # config | state | check | error | requires
    title: str = ""
    message: str
    expected: List[str] = Field(default_factory=list)  # IOS lines that fix it
    found: List[str] = Field(default_factory=list)  # related lines configured now


class TaskGradeResult(BaseModel):
    id: Optional[Union[int, str]] = None  # None for "Other requirements"
    description: str
    graded: bool
    passed: bool
    points: float
    earned: float
    requirements: int
    satisfied: int
    findings: List[GradeFinding] = Field(default_factory=list)


class GradeSummary(BaseModel):
    tasks_graded: int
    tasks_passed: int
    requirements: int
    satisfied: int


class GradeReport(BaseModel):
    lab_id: str
    lab_title: str
    total_earned: int
    total_possible: int
    percentage: float
    passed: bool
    node_results: List[NodeGradeResult]
    tasks: List[TaskGradeResult] = Field(default_factory=list)
    summary: Optional[GradeSummary] = None


class SessionStartResponse(BaseModel):
    session_id: int
    runtime_id: str
    engine: str = "native"
    status: str
    generation: int
    message: str
    # Temporary migration alias for clients created before the native runtime.
    gns3_project_id: Optional[str] = None


class SessionStatusResponse(BaseModel):
    session_id: int
    runtime_id: Optional[str] = None
    engine: str = "native"
    status: str
    generation: Optional[int] = None
    nodes: List[NodeStatus] = Field(default_factory=list)
    links: List[LinkStatus] = Field(default_factory=list)
    error: Optional[str] = None
