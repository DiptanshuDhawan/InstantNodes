"""Per-account progress: grade history per lab and the lab that is running now."""

from fastapi import APIRouter, Depends

from db.database import get_db
from services.auth import current_user, iso_utc
from simulator import manager

router = APIRouter(prefix="/api/progress", tags=["progress"])


@router.get("")
def get_progress(user: dict = Depends(current_user)):
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT l.slug AS slug,
                   COUNT(r.id) AS attempts,
                   MAX(COALESCE(r.percentage, 0)) AS best_percentage,
                   MAX(COALESCE(r.passed, 0)) AS completed,
                   MAX(r.graded_at) AS last_graded_at,
                   MIN(CASE WHEN r.passed = 1 THEN r.graded_at END) AS completed_at
            FROM lab_results r
            JOIN labs l ON l.id = r.lab_id
            WHERE r.user_id = ?
            GROUP BY l.slug
            """,
            (user["id"],),
        ).fetchall()
        running = conn.execute(
            """
            SELECT s.id, s.generation, s.started_at, s.runtime_id, s.gns3_project_id,
                   l.slug AS lab_slug
            FROM lab_sessions s
            JOIN labs l ON l.id = s.lab_id
            WHERE s.user_id = ? AND s.status IN ('running', 'graded')
            ORDER BY s.id DESC
            """,
            (user["id"],),
        ).fetchall()

        active_session = None
        stale = []
        for row in running:
            runtime = manager.find(row["runtime_id"] or row["gns3_project_id"])
            if runtime is None or runtime.status != "running":
                stale.append((row["id"],))
            elif active_session is None:
                active_session = {
                    "session_id": row["id"],
                    "lab_slug": row["lab_slug"],
                    "generation": runtime.generation,
                    "started_at": iso_utc(row["started_at"]),
                }
        if stale:
            conn.executemany(
                "UPDATE lab_sessions SET status = 'stopped', "
                "stopped_at = COALESCE(stopped_at, CURRENT_TIMESTAMP) WHERE id = ?",
                stale,
            )
            conn.commit()
    finally:
        conn.close()

    labs = {
        row["slug"]: {
            "attempts": row["attempts"],
            "best_percentage": row["best_percentage"],
            "completed": bool(row["completed"]),
            "last_graded_at": iso_utc(row["last_graded_at"]),
            "completed_at": iso_utc(row["completed_at"]),
        }
        for row in rows
    }
    return {"labs": labs, "active_session": active_session}
