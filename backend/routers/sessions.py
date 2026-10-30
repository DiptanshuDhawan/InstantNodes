from pathlib import Path
import os

from fastapi import APIRouter, HTTPException

from db.database import get_db
from simulator import InvalidRuntimeState, SimulatorError, manager


router = APIRouter(prefix="/api/session", tags=["sessions"])
LABS_DIR = os.getenv(
    "LABS_DIR", str(Path(__file__).resolve().parents[2] / "labs")
)


def _row_runtime_id(row) -> str:
    keys = row.keys() if hasattr(row, "keys") else row
    if "runtime_id" in keys and row["runtime_id"]:
        return row["runtime_id"]
    return row["gns3_project_id"]


def _mark_stopped(session_id: int) -> None:
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


def _stopped_status(session_id: int, runtime_id: str = None, generation: int = None) -> dict:
    result = {
        "session_id": session_id,
        "runtime_id": runtime_id,
        "gns3_project_id": runtime_id,
        "engine": "native",
        "status": "stopped",
        "nodes": [],
        "links": [],
    }
    if generation is not None:
        result["generation"] = generation
    return result


@router.post("/start/{lab_slug}")
async def start_lab(lab_slug: str):
    conn = get_db()
    try:
        lab_row = conn.execute(
            "SELECT * FROM labs WHERE slug = ?", (lab_slug,)
        ).fetchone()
    finally:
        conn.close()
    if not lab_row:
        raise HTTPException(status_code=404, detail="Lab not found")

    lab = dict(lab_row)
    lab_yaml_path = os.path.join(LABS_DIR, lab_slug, "lab.yaml")
    try:
        runtime = manager.create(slug=lab_slug, yaml_path=lab_yaml_path)
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to start native simulator: {exc}"
        ) from exc

    conn = None
    try:
        conn = get_db()
        cursor = conn.execute(
            """
            INSERT INTO lab_sessions (
                lab_id, gns3_project_id, runtime_id, generation, status
            )
            VALUES (?, ?, ?, ?, 'running')
            """,
            (lab["id"], runtime.runtime_id, runtime.runtime_id, runtime.generation),
        )
        session_id = cursor.lastrowid
        conn.commit()
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        manager.remove(runtime.runtime_id)
        raise HTTPException(
            status_code=500, detail=f"Failed to persist simulator session: {exc}"
        ) from exc
    finally:
        if conn is not None:
            conn.close()

    return {
        "session_id": session_id,
        "runtime_id": runtime.runtime_id,
        "gns3_project_id": runtime.runtime_id,
        "engine": "native",
        "status": "running",
        "generation": runtime.generation,
        "message": "Lab started. Terminals are connecting.",
    }


@router.post("/stop/{session_id}")
async def stop_lab(session_id: int):
    conn = get_db()
    try:
        session_row = conn.execute(
            "SELECT * FROM lab_sessions WHERE id = ?", (session_id,)
        ).fetchone()
    finally:
        conn.close()
    if not session_row:
        raise HTTPException(status_code=404, detail="Session not found")

    manager.remove(_row_runtime_id(session_row))
    _mark_stopped(session_id)
    return {"message": "Lab stopped. Server resources freed."}


@router.get("/status/{session_id}")
async def get_session_status(session_id: int):
    conn = get_db()
    try:
        session_row = conn.execute(
            "SELECT * FROM lab_sessions WHERE id = ?", (session_id,)
        ).fetchone()
    finally:
        conn.close()
    if not session_row:
        raise HTTPException(status_code=404, detail="Session not found")

    session = dict(session_row)
    runtime_id = _row_runtime_id(session_row)
    runtime = manager.find(runtime_id)
    stored_generation = session.get("generation")
    if session["status"] not in ("running", "graded"):
        return _stopped_status(
            session_id,
            runtime_id,
            runtime.generation if runtime is not None else stored_generation,
        )
    if runtime is None or runtime.status != "running":
        _mark_stopped(session_id)
        return _stopped_status(
            session_id,
            runtime_id,
            runtime.generation if runtime is not None else stored_generation,
        )

    report = manager.status(runtime_id)
    report["session_id"] = session_id
    report["status"] = session["status"]
    report["runtime_id"] = runtime_id
    report["gns3_project_id"] = runtime_id
    report["engine"] = "native"
    return report


@router.post("/reset/{session_id}")
async def reset_session(session_id: int):
    conn = get_db()
    try:
        session_row = conn.execute(
            """
            SELECT s.*, l.slug AS lab_slug
            FROM lab_sessions s JOIN labs l ON s.lab_id = l.id
            WHERE s.id = ?
            """,
            (session_id,),
        ).fetchone()
    finally:
        conn.close()
    if not session_row:
        raise HTTPException(status_code=404, detail="Session not found")

    session = dict(session_row)
    if session["status"] not in ("running", "graded"):
        raise HTTPException(status_code=400, detail="Lab is not running")
    runtime_id = _row_runtime_id(session_row)
    runtime = manager.find(runtime_id)
    if runtime is None:
        _mark_stopped(session_id)
        raise HTTPException(
            status_code=409, detail="Simulator runtime is no longer available"
        )
    try:
        generation = manager.reset(runtime_id)
    except InvalidRuntimeState as exc:
        _mark_stopped(session_id)
        raise HTTPException(status_code=400, detail="Lab is not running") from exc
    except SimulatorError as exc:
        raise HTTPException(status_code=500, detail=f"Reset failed: {exc}") from exc

    conn = get_db()
    try:
        conn.execute(
            "UPDATE lab_sessions SET status = 'running', stopped_at = NULL, "
            "generation = ? WHERE id = ?",
            (generation, session_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "message": "Lab reset successfully.",
        "runtime_id": runtime_id,
        "gns3_project_id": runtime_id,
        "engine": "native",
        "status": "running",
        "generation": generation,
    }
