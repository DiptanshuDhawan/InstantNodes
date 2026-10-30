import logging

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from db.database import get_db
from routers import grading, labs, sessions, terminal

logger = logging.getLogger(__name__)

app = FastAPI(
    title="NetLabX API",
    description="Backend API for the NetLabX native network lab simulator",
    version="1.0.0",
)

# Allow the browser-based frontend to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers.
app.include_router(labs.router)
app.include_router(sessions.router)
app.include_router(grading.router)
app.include_router(terminal.router)


def _live_payload() -> dict[str, str]:
    return {"status": "ok", "service": "NetLabX API", "engine": "native"}


@app.get("/health")
async def health_check():
    """Compatibility health endpoint for existing clients."""
    return _live_payload()


@app.get("/health/live")
async def liveness_check():
    """Report whether the API process is serving requests."""
    return _live_payload()


@app.get("/health/ready")
async def readiness_check():
    """Report whether SQLite is accessible and at least one lab is loaded."""
    connection = None
    try:
        connection = get_db()
        connection.execute("SELECT 1").fetchone()
        row = connection.execute("SELECT COUNT(*) AS count FROM labs").fetchone()
        lab_count = int(row["count"])
    except Exception:
        logger.exception("Readiness check could not access the database")
        return JSONResponse(
            status_code=503,
            content={
                **_live_payload(),
                "status": "not_ready",
                "checks": {"database": "unavailable", "labs": "unknown"},
                "labs_loaded": 0,
            },
        )
    finally:
        if connection is not None:
            connection.close()

    if lab_count == 0:
        return JSONResponse(
            status_code=503,
            content={
                **_live_payload(),
                "status": "not_ready",
                "checks": {"database": "ok", "labs": "empty"},
                "labs_loaded": 0,
            },
        )

    return {
        **_live_payload(),
        "checks": {"database": "ok", "labs": "ok"},
        "labs_loaded": lab_count,
    }
