import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from db.database import get_db
from services.auth import COOKIE_NAME, browser_origin_allowed, user_for_token
from simulator import InvalidRuntimeState, NodeNotFound, RuntimeNotFound, SimulatorError, manager
from simulator.console import STOP_SENTINEL


router = APIRouter(tags=["terminal"])


async def _policy_close(websocket: WebSocket, reason: str) -> None:
    try:
        await websocket.close(code=1008, reason=reason[:120])
    except RuntimeError:
        pass


async def _send_output(websocket: WebSocket, queue: "asyncio.Queue") -> None:
    """Push console output to the browser.

    Waits for the next chunk, coalesces whatever else is already queued into one
    text frame, and closes the socket with 1008 when the runtime stops.
    """
    try:
        while True:
            chunk = await queue.get()
            parts = []
            stopped = False
            while True:
                if chunk is STOP_SENTINEL:
                    stopped = True
                    break
                parts.append(chunk)
                if queue.empty():
                    break
                chunk = queue.get_nowait()
            if parts:
                await websocket.send_text("".join(parts))
            if stopped:
                await _policy_close(websocket, "Simulator runtime is not running")
                return
    except asyncio.CancelledError:
        raise
    except Exception:
        # The socket went away; the receive loop notices and cleans up.
        return


async def _stop_sender(sender) -> None:
    if sender is None or sender.done():
        return
    sender.cancel()
    try:
        await sender
    except (asyncio.CancelledError, Exception):
        pass


@router.websocket("/ws/terminal/{session_id}/{node_name}")
async def terminal_websocket(
    websocket: WebSocket,
    session_id: int,
    node_name: str,
):
    await websocket.accept()
    # Browsers send cookies with WebSocket handshakes and CORS does not apply to them, so
    # check the page origin here (cross-site WebSocket hijacking) and then the account.
    if not browser_origin_allowed(websocket.headers.get("origin")):
        await _policy_close(websocket, "Origin not allowed")
        return
    user = await asyncio.to_thread(user_for_token, websocket.cookies.get(COOKIE_NAME))
    if user is None:
        await _policy_close(websocket, "Sign in to continue")
        return

    conn = get_db()
    try:
        session_row = conn.execute(
            "SELECT gns3_project_id, runtime_id, status "
            "FROM lab_sessions WHERE id = ? AND user_id = ?",
            (session_id, user["id"]),
        ).fetchone()
    finally:
        conn.close()

    if not session_row:
        await _policy_close(websocket, "Session not found")
        return
    if session_row["status"] not in ("running", "graded"):
        await _policy_close(websocket, "Session is not running")
        return

    runtime_id = session_row["runtime_id"] or session_row["gns3_project_id"]
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
        await _policy_close(websocket, "Simulator runtime is not available")
        return

    # Push model: the node's persistent console calls ``sink`` (from whichever
    # thread runs the simulator) with every output chunk -- echo, command
    # output, other viewers' activity, syslog, reset notices.  A sender task
    # forwards the chunks; the receive loop only feeds keystrokes.
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def sink(chunk) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, chunk)

    attachment = None
    sender = None
    try:
        attachment = await asyncio.to_thread(manager.attach, runtime_id, node_name, sink)
        await websocket.send_text(attachment.initial_output)
        sender = asyncio.create_task(_send_output(websocket, queue))
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            data = message.get("text")
            if data is None:
                raw = message.get("bytes")
                if not raw:
                    continue
                data = raw.decode("utf-8", errors="replace")
            if not data:
                continue
            # The return value is ignored: the sink already carries the output.
            await asyncio.to_thread(manager.execute, attachment, data)
    except WebSocketDisconnect:
        pass
    except NodeNotFound as exc:
        await _stop_sender(sender)
        await _policy_close(websocket, str(exc))
    except (RuntimeNotFound, InvalidRuntimeState) as exc:
        await _stop_sender(sender)
        await _policy_close(websocket, str(exc))
    except SimulatorError as exc:
        await _stop_sender(sender)
        try:
            await websocket.close(code=1011, reason=str(exc)[:120])
        except RuntimeError:
            pass
    except RuntimeError:
        # Starlette raises RuntimeError when receiving on a closed socket.
        # (Must stay after the SimulatorError clauses: those subclass it.)
        pass
    finally:
        await _stop_sender(sender)
        if attachment is not None:
            manager.detach(attachment)
