import logging

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from db.database import get_db
from routers import auth, grading, labs, progress, sessions, terminal
from services.auth import ALLOWED_ORIGINS, browser_origin_allowed

logger = logging.getLogger(__name__)

app = FastAPI(
    title="NetLabX API",
    description="Backend API for the NetLabX native network lab simulator",
    version="1.0.0",
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


# Requests that change data must come from a listed frontend origin when a browser sends
# them (the sign-in cookie is attached automatically, so this blocks cross-site forms).
# Registered before CORSMiddleware, so CORS stays the outer layer and answers preflights.
@app.middleware("http")
async def reject_unlisted_origins(request: Request, call_next):
    if request.method not in _SAFE_METHODS and not browser_origin_allowed(
        request.headers.get("origin")
    ):
        return JSONResponse(
            status_code=403, content={"detail": "This website is not allowed to use the API."}
        )
    return await call_next(request)


# The browser frontend calls this API with the sign-in cookie, so origins are listed
# explicitly (CORS_ORIGINS); a wildcard cannot be combined with credentials safely.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# Register all routers.
app.include_router(auth.router)
app.include_router(progress.router)
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
