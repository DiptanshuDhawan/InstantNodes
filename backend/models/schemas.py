"""API response models for the native NetSimX runtime."""

from typing import List, Optional

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


class GradeReport(BaseModel):
    lab_id: str
    lab_title: str
    total_earned: int
    total_possible: int
    percentage: float
    passed: bool
    node_results: List[NodeGradeResult]


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
