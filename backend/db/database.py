import logging
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_DATABASE_PATH = Path(__file__).resolve().parent / "netlabx.db"
_DEFAULT_LABS_DIR = Path(__file__).resolve().parents[2] / "labs"
_NATIVE_RUNTIME_PREFIXES = ("sim-", "native:", "native-", "native_", "native/")
_LEGACY_IMPORT_LOCK = threading.Lock()


def _configured_path(environment_name: str, default: Path) -> Path:
    raw_value = os.environ.get(environment_name)
    if raw_value and raw_value.strip():
        path = Path(os.path.expandvars(raw_value.strip())).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve(strict=False)
    return default


def _legacy_database_path() -> Path | None:
    raw_value = os.environ.get("LEGACY_DATABASE_PATH", "").strip()
    if not raw_value:
        return None
    path = Path(os.path.expandvars(raw_value)).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve(strict=False)


def _import_legacy_database(database_path: Path) -> None:
    """Atomically import a legacy SQLite database into an empty data volume."""
    legacy_path = _legacy_database_path()
    if legacy_path is None or legacy_path == database_path:
        return

    with _LEGACY_IMPORT_LOCK:
        if database_path.exists() or not legacy_path.exists():
            return
        if not legacy_path.is_file() or legacy_path.stat().st_size == 0:
            raise RuntimeError(
                f"Legacy database '{legacy_path}' exists but is not a non-empty file"
            )

        temporary_path = database_path.with_name(
            f".{database_path.name}.{os.getpid()}.importing"
        )
        source = None
        destination = None
        try:
            if temporary_path.exists():
                temporary_path.unlink()
            source = sqlite3.connect(f"{legacy_path.as_uri()}?mode=ro", uri=True)
            destination = sqlite3.connect(temporary_path)
            source.backup(destination)
            result = destination.execute("PRAGMA quick_check").fetchone()
            destination.commit()
            destination.close()
            destination = None
            source.close()
            source = None
            if not result or result[0] != "ok":
                raise RuntimeError(f"SQLite integrity check returned: {result!r}")
            if database_path.exists():
                temporary_path.unlink(missing_ok=True)
                return
            os.replace(temporary_path, database_path)
            logger.info(
                "Imported legacy SQLite database from %s to %s",
                legacy_path,
                database_path,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Could not import legacy database '{legacy_path}' into "
                f"'{database_path}': {exc}"
            ) from exc
        finally:
            if destination is not None:
                destination.close()
            if source is not None:
                source.close()
            temporary_path.unlink(missing_ok=True)


def get_database_path() -> Path:
    """Return the configured SQLite path, importing legacy history once."""
    database_path = _configured_path("DATABASE_PATH", _DEFAULT_DATABASE_PATH)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    _import_legacy_database(database_path)
    return database_path


def get_labs_dir() -> Path:
    """Return the configured directory containing YAML lab definitions."""
    return _configured_path("LABS_DIR", _DEFAULT_LABS_DIR)


def get_db() -> sqlite3.Connection:
    """Open a SQLite connection with dictionary-like rows and FK enforcement."""
    connection = sqlite3.connect(get_database_path(), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def _lab_session_columns(cursor: sqlite3.Cursor) -> set[str]:
    return {row["name"] for row in cursor.execute("PRAGMA table_info(lab_sessions)")}


def _table_columns(cursor: sqlite3.Cursor, table: str) -> set[str]:
    return {row["name"] for row in cursor.execute(f"PRAGMA table_info({table})")}


def _migrate_lab_sessions(cursor: sqlite3.Cursor) -> None:
    """Add native-runtime fields without removing legacy project metadata."""
    columns = _lab_session_columns(cursor)
    if "runtime_id" not in columns:
        cursor.execute("ALTER TABLE lab_sessions ADD COLUMN runtime_id TEXT")
    if "generation" not in columns:
        cursor.execute(
            "ALTER TABLE lab_sessions "
            "ADD COLUMN generation INTEGER NOT NULL DEFAULT 1"
        )
    if "user_id" not in columns:
        cursor.execute(
            "ALTER TABLE lab_sessions "
            "ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
        )


def _migrate_lab_results(cursor: sqlite3.Cursor) -> None:
    """Link grade results to accounts; rows from before accounts keep NULL users."""
    columns = _table_columns(cursor, "lab_results")
    if "user_id" not in columns:
        cursor.execute(
            "ALTER TABLE lab_results "
            "ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
        )
    if "passed" not in columns:
        cursor.execute("ALTER TABLE lab_results ADD COLUMN passed INTEGER")
    if "percentage" not in columns:
        cursor.execute("ALTER TABLE lab_results ADD COLUMN percentage REAL")


def _is_clearly_native_runtime_id(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return any(normalized.startswith(prefix) for prefix in _NATIVE_RUNTIME_PREFIXES)


def _stop_stale_native_sessions(cursor: sqlite3.Cursor) -> int:
    """Stop active sessions whose identifiers clearly belong to native memory."""
    rows = cursor.execute(
        """
        SELECT id, runtime_id, gns3_project_id
        FROM lab_sessions
        WHERE status IN ('running', 'graded')
        """
    ).fetchall()

    stale_ids = []
    for row in rows:
        runtime_id = row["runtime_id"] or row["gns3_project_id"]
        if _is_clearly_native_runtime_id(runtime_id):
            stale_ids.append((row["id"],))

    if stale_ids:
        cursor.executemany(
            """
            UPDATE lab_sessions
            SET status = 'stopped',
                stopped_at = COALESCE(stopped_at, CURRENT_TIMESTAMP)
            WHERE id = ?
            """,
            stale_ids,
        )
    return len(stale_ids)


def _load_lab_definition(lab_path: Path) -> dict[str, Any]:
    with lab_path.open("r", encoding="utf-8") as lab_file:
        document = yaml.safe_load(lab_file) or {}
    if not isinstance(document, dict):
        raise ValueError("lab.yaml must contain a YAML mapping")
    lab_definition = document.get("lab") or {}
    if not isinstance(lab_definition, dict):
        raise ValueError("the 'lab' value must be a YAML mapping")
    return lab_definition


def _sync_labs(cursor: sqlite3.Cursor) -> int:
    """Upsert lab metadata from each immediate child lab.yaml file."""
    labs_dir = get_labs_dir()
    if not labs_dir.is_dir():
        logger.warning("Labs directory %s not found; no labs loaded", labs_dir)
        return 0

    synced_count = 0
    for lab_path in sorted(labs_dir.glob("*/lab.yaml")):
        lab_slug = lab_path.parent.name
        try:
            lab_definition = _load_lab_definition(lab_path)
            cursor.execute(
                """
                INSERT INTO labs (
                    slug,
                    title,
                    topic,
                    difficulty,
                    description,
                    yaml_path,
                    estimated_time_minutes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    title = excluded.title,
                    topic = excluded.topic,
                    difficulty = excluded.difficulty,
                    description = excluded.description,
                    yaml_path = excluded.yaml_path,
                    estimated_time_minutes = excluded.estimated_time_minutes
                """,
                (
                    lab_slug,
                    lab_definition.get("title")
                    or lab_slug.replace("-", " ").title(),
                    lab_definition.get("topic") or "Networking",
                    lab_definition.get("difficulty") or "Beginner",
                    lab_definition.get("objective")
                    or "Complete the lab objectives.",
                    str(lab_path),
                    lab_definition.get("estimated_time_minutes") or 30,
                ),
            )
            synced_count += 1
        except Exception:
            logger.exception("Error loading lab definition %s", lab_path)
    return synced_count


def init_db() -> None:
    """Create, migrate, reconcile, and synchronize the SQLite database."""
    connection = get_db()
    try:
        cursor = connection.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS labs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                topic TEXT NOT NULL,
                difficulty TEXT NOT NULL DEFAULT 'Beginner',
                description TEXT,
                gns3_project_path TEXT,
                yaml_path TEXT,
                estimated_time_minutes INTEGER DEFAULT 30,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS lab_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id INTEGER REFERENCES labs(id) ON DELETE CASCADE,
                gns3_project_id TEXT,
                runtime_id TEXT,
                generation INTEGER NOT NULL DEFAULT 1,
                status TEXT DEFAULT 'running',
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                stopped_at DATETIME
            );

            CREATE TABLE IF NOT EXISTS lab_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES lab_sessions(id) ON DELETE CASCADE,
                lab_id INTEGER REFERENCES labs(id) ON DELETE CASCADE,
                score INTEGER NOT NULL,
                max_score INTEGER NOT NULL,
                results_json TEXT,
                graded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Accounts.  Emails are stored lower-case; passwords as scrypt hashes.
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login_at DATETIME
            );

            -- Sign-in sessions.  Only the SHA-256 hash of the cookie token is stored.
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            );
            """
        )
        _migrate_lab_sessions(cursor)
        _migrate_lab_results(cursor)
        cursor.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_lab_sessions_user ON lab_sessions(user_id, status);
            CREATE INDEX IF NOT EXISTS idx_lab_results_user ON lab_results(user_id, lab_id);
            """
        )
        cursor.execute("DELETE FROM auth_sessions WHERE expires_at <= datetime('now')")
        stopped_count = _stop_stale_native_sessions(cursor)
        synced_count = _sync_labs(cursor)
        connection.commit()
        if stopped_count:
            logger.info("Stopped %d stale native simulator session(s)", stopped_count)
        logger.info("Synchronized %d lab definition(s)", synced_count)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# Preserve the existing import-time initialization contract used by the routers.
init_db()
