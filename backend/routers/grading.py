from pathlib import Path
import json
import os
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from db.database import get_db
from services.grading_service import grade_session
from simulator import InvalidRuntimeState, RuntimeNotFound, SimulatorError, manager


router = APIRouter(prefix="/api/grade", tags=["grading"])
LABS_DIR = os.getenv(
    "LABS_DIR", str(Path(__file__).resolve().parents[2] / "labs")
)


def _get_session(session_id: int) -> dict:
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT s.*, l.slug AS lab_slug, l.id AS lab_id
            FROM lab_sessions s
            JOIN labs l ON s.lab_id = l.id
            WHERE s.id = ?
            """,
            (session_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    session = dict(row)
    if session["status"] not in ("running", "graded"):
        raise HTTPException(status_code=400, detail="Lab is not running")
    runtime_id = session.get("runtime_id") or session.get("gns3_project_id")
    runtime = manager.find(runtime_id)
    if runtime is None or runtime.status != "running":
        conn = get_db()
        try:
            conn.execute(
                "UPDATE lab_sessions SET status = 'stopped', "
                "stopped_at = COALESCE(stopped_at, CURRENT_TIMESTAMP) WHERE id = ?",
                (session_id,),
            )
            conn.commit()
        finally:
            conn.close()
        raise HTTPException(
            status_code=409, detail="Simulator runtime is no longer available"
        )
    session["resolved_runtime_id"] = runtime_id
    return session


def _run_grade(session: dict, skip_tasks: list = None) -> dict:
    yaml_path = os.path.join(LABS_DIR, session["lab_slug"], "lab.yaml")
    try:
        return grade_session(
            yaml_path,
            session["resolved_runtime_id"],
            skip_tasks=skip_tasks,
        )
    except RuntimeNotFound as exc:
        raise HTTPException(
            status_code=409, detail="Simulator runtime is no longer available"
        ) from exc
    except InvalidRuntimeState as exc:
        raise HTTPException(status_code=400, detail="Lab is not running") from exc
    except SimulatorError as exc:
        raise HTTPException(status_code=500, detail=f"Grading failed: {exc}") from exc


@router.post("/{session_id}")
async def grade_lab(session_id: int):
    session = _get_session(session_id)
    report = _run_grade(session)

    conn = get_db()
    try:
        conn.execute(
            """
            INSERT INTO lab_results (session_id, lab_id, score, max_score, results_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                session["lab_id"],
                report["total_earned"],
                report["total_possible"],
                json.dumps(report),
            ),
        )
        conn.execute(
            "UPDATE lab_sessions SET status = 'graded' WHERE id = ?", (session_id,)
        )
        conn.commit()
    finally:
        conn.close()
    return report


@router.get("/incremental/{session_id}")
async def grade_incremental(
    session_id: int,
    already_passed: Optional[List[int]] = Query(None),
):
    session = _get_session(session_id)
    return _run_grade(session, skip_tasks=already_passed or [])
