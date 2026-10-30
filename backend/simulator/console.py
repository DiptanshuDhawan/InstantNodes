"""Persistent per-node consoles (Phase 2, A3b).

A :class:`NodeConsole` is the simulated console port of one node.  It is created
on the first terminal attach, survives WebSocket detach/attach, and is rebuilt
on ``reset``/``reload``.  Any number of viewers can watch one console: every
output chunk is pushed to every viewer's sink (fan-out), whichever viewer typed
the input; :meth:`NodeConsole.feed` additionally returns the output of its own
input (the synchronous API the tests use).

Structure
---------
One :class:`~simulator.ios.terminal.TerminalSession` per console session drives a
small facade shell (:class:`_ConsoleShell`) that routes ``prompt``/``run``/
``help_text``/``complete``/``interrupt`` to the *top* of a stack of shells:

* ``stack[0]`` -- the root shell (``IosShell`` on ``con 0`` or ``VpcsShell``);
* ``stack[1:]`` -- nested VTY sessions opened with ``ssh``/``telnet``
  (:meth:`NodeConsole.open_session`).  When the top session closes it is popped
  and ``[Connection to <target> closed by foreign host]`` is printed before the
  parent prompt.

Console states: ``new`` (not started), ``starting``/``gate`` (start banner and
login dialog running in the terminal), ``active`` (shell stack live) and
``idle`` (``Press RETURN to get started.`` after logout/reload; the console
itself consumes input until Return).

Input is fed to the terminal one character at a time so that work which must
not happen inside a running command generator -- restarting an aborted login,
leaving the root session, node reloads (``runtime._run_deferred``) and syslog
delivery -- runs between keystrokes, right after the command that caused it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .ios.protocol import Prompt
from .ios.terminal import TerminalSession, to_crlf

__all__ = ["NodeConsole", "SessionFrame", "STOP_SENTINEL", "outgoing_frame", "vty_frames"]

#: Pushed once to every viewer sink when the runtime stops (not a ``str``).
STOP_SENTINEL = object()

#: Text printed when the root session on ``con 0`` ends.
_LOGOUT_TEMPLATE = (
    "\r\n{host} con0 is now available\r\n\r\n\r\n\r\n"
    "\r\n\r\nPress RETURN to get started.\r\n"
)
_PRESS_RETURN = "\r\nPress RETURN to get started.\r\n"
_LOG_QUEUE_LIMIT = 200

Sink = Callable[[str], None]


@dataclass(eq=False)
class SessionFrame:
    """One shell on a console's session stack."""

    shell: object
    node_name: str
    #: Target as typed by the user (``[Connection to <label> closed ...]``).
    label: str = ""
    #: ``""`` for the root shell, else ``"ssh"`` / ``"telnet"``.
    transport: str = ""
    remote_address: Optional[str] = None
    username: Optional[str] = None
    #: The parent's terminal history while this frame is on top.
    saved_history: Optional[Tuple[List[str], int]] = None
    opened_at: float = 0.0
    #: Negotiated SSH protocol major version (1 or 2) of an ``ssh`` session.
    ssh_version: Optional[int] = None


def vty_frames(runtime, node_name: str) -> List[SessionFrame]:
    """Every open nested (ssh/telnet) session *into* ``node_name``, whichever
    console it was opened from (read-only view for ``show users``/``show ssh``
    and VTY line allocation)."""
    frames: List[SessionFrame] = []
    for console in list(getattr(runtime, "consoles", {}).values()):
        for frame in console.nested_frames():
            if frame.node_name == node_name:
                frames.append(frame)
    return frames


def outgoing_frame(runtime, frame: SessionFrame) -> Optional[SessionFrame]:
    """The session opened *from* ``frame``'s shell -- the frame right above it
    on its console stack -- or ``None`` (read-only)."""
    for console in list(getattr(runtime, "consoles", {}).values()):
        stack = console.stack
        for index, candidate in enumerate(stack[:-1]):
            if candidate is frame:
                return stack[index + 1]
    return None


def _text(text: str):
    """A command generator that just prints ``text``."""
    if text:
        yield text


def _empty():
    return
    yield  # pragma: no cover - makes this a generator


def banner_text(value: Optional[str]) -> str:
    """Banner body as displayed (surrounding blank lines trimmed)."""
    if not value:
        return ""
    return value.replace("\r\n", "\n").strip("\n")


class _ConsoleShell:
    """``ShellProtocol`` facade routing to the top shell of a console."""

    def __init__(self, console: "NodeConsole") -> None:
        self._console = console
        #: Set by the TerminalSession.
        self.terminal = None

    def _top(self):
        console = self._console
        if console.state != "active" or not console.stack:
            return None
        return console.stack[-1].shell

    def prompt(self) -> str:
        if self._console._prompt_suppressed():
            return ""
        top = self._top()
        return top.prompt() if top is not None else ""

    def help_text(self, buffer: str) -> str:
        top = self._top()
        return top.help_text(buffer) if top is not None else "\n"

    def complete(self, buffer: str) -> Optional[str]:
        top = self._top()
        return top.complete(buffer) if top is not None else None

    def run(self, line: str):
        return self._console._run_top(lambda shell: shell.run(line))

    def interrupt(self, key: str):
        return self._console._run_top(lambda shell: shell.interrupt(key))

    @property
    def terminal_length(self) -> int:
        top = self._top()
        if top is None:
            return 0
        try:
            return int(top.terminal_length)
        except Exception:
            return 0

    @property
    def history_size(self) -> int:
        top = self._top()
        if top is not None:
            try:
                return int(top.history_size)
            except Exception:
                pass
        return self._console._default_history_size()

    @property
    def logging_synchronous(self) -> bool:
        top = self._top()
        if top is not None:
            try:
                return bool(top.logging_synchronous)
            except Exception:
                return False
        line = self._console._console_line()
        return bool(line is not None and line.logging_synchronous)

    @property
    def closed(self) -> bool:
        return self._console._prompt_suppressed()


class NodeConsole:
    """The persistent console of one node (see the module docstring)."""

    def __init__(self, runtime, node_name: str) -> None:
        self.runtime = runtime
        self.node_name = node_name
        #: connection id -> optional sink receiving every output chunk.
        self.viewers: Dict[str, Optional[Sink]] = {}
        self.state = "new"
        self.stack: List[SessionFrame] = []
        self.terminal: Optional[TerminalSession] = None
        self._shell = _ConsoleShell(self)
        self._busy = 0
        self._collectors: List[List[str]] = []
        self._log_queue: List[Tuple[str, Optional[SessionFrame]]] = []
        self._swallow_lf = False
        self._last_char = ""
        self._start_output = ""
        #: True once anything happened after the start output (input/output).
        self._touched = False

    # ------------------------------------------------------------------ #
    # Basic accessors                                                     #
    # ------------------------------------------------------------------ #
    @property
    def node(self):
        return self.runtime.nodes[self.node_name]

    @property
    def is_vpcs(self) -> bool:
        return self.node.cli_profile == "vpcs"

    @property
    def busy(self) -> bool:
        """True while this console is processing input."""
        return self._busy > 0

    def _console_line(self):
        try:
            return self.node.lines.get("con 0")
        except KeyError:  # pragma: no cover - node vanished
            return None

    def _default_history_size(self) -> int:
        if self.is_vpcs:
            return 20
        line = self._console_line()
        return int(line.history_size) if line is not None else 10

    def top_frame(self) -> Optional[SessionFrame]:
        return self.stack[-1] if self.stack else None

    # ------------------------------------------------------------------ #
    # Viewers                                                             #
    # ------------------------------------------------------------------ #
    def attach(self, connection_id: str, sink: Optional[Sink] = None) -> str:
        """Register a viewer and return what its terminal should show first.

        The first attach starts the console (full start output).  Later
        attaches get a short redraw of the current input context -- or the
        start output again while nothing has happened since it was printed
        (for example right after a reset).
        """
        if self.state == "new":
            initial = self.start()
        elif not self._touched:
            initial = self._start_output
        else:
            initial = self.redraw()
        self.viewers[connection_id] = sink
        return initial

    def detach(self, connection_id: str) -> None:
        self.viewers.pop(connection_id, None)

    def redraw(self) -> str:
        if self.state == "idle":
            return _PRESS_RETURN
        if self.terminal is None:
            return "\r\n"
        return self.terminal.redraw() or "\r\n"

    def notify_stopped(self) -> None:
        for sink in list(self.viewers.values()):
            if sink is not None:
                try:
                    sink(STOP_SENTINEL)  # type: ignore[arg-type]
                except Exception:
                    pass

    def _broadcast(self, text: str, touch: bool = True) -> None:
        if not text:
            return
        if touch:
            self._touched = True
        if self._collectors:
            self._collectors[-1].append(text)
        for sink in list(self.viewers.values()):
            if sink is not None:
                try:
                    sink(text)
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Start / rebuild                                                     #
    # ------------------------------------------------------------------ #
    def start(self) -> str:
        """(Re)start the console session from scratch; return the start output."""
        self._discard_terminal()
        self.stack = []
        self.terminal = TerminalSession(self._shell)
        if self.is_vpcs:
            generator = self._vpcs_start()
        else:
            self.state = "starting"
            generator = self._ios_start()
        output = self.terminal.run_command(generator)
        self._start_output = output
        self._touched = False
        return output

    def rebuild(self, notice: str = "") -> None:
        """Restart after a reset and push ``notice`` + the start output."""
        self._log_queue.clear()
        output = self.start()
        self._broadcast(notice + output, touch=False)

    def show_boot(self, text: str) -> None:
        """The node reloaded: print the boot text and wait for Return."""
        self._enter_idle(text)

    def _discard_terminal(self) -> None:
        if self.terminal is not None:
            self.terminal.cancel_command()
        self.terminal = None

    def _enter_idle(self, text: str) -> None:
        for frame in list(self.stack):
            self._drain_syslog(frame)
        self._discard_terminal()
        self.stack = []
        self.state = "idle"
        if self._busy and self._last_char == "\r":
            self._swallow_lf = True
        self._broadcast(text)

    def _vpcs_start(self):
        from .vpcs.shell import VpcsShell

        node = self.node
        shell = VpcsShell(node, runtime=self.runtime)
        self._wire(shell)
        self.stack = [SessionFrame(shell=shell, node_name=self.node_name)]
        self.state = "active"
        yield shell.welcome_text()

    def _ios_start(self):
        node = self.node
        yield "\n"
        motd = banner_text(node.banner_motd)
        if motd:
            yield motd + "\n"
        yield from self._login_sequence(header=True)

    def _login_mode(self) -> str:
        line = self._console_line()
        if line is None:
            return "none"
        if line.login_local:
            return "local"
        if line.login and line.password is not None:
            return "line"
        return "none"

    def _login_sequence(self, header: bool):
        """Console login gate (contract s2), then the exec banner."""
        node = self.node
        mode = self._login_mode()
        if mode == "none":
            self._activate_root(None)
        else:
            self.state = "gate"
            if header:
                login_banner = banner_text(node.banner_login)
                if login_banner:
                    yield login_banner + "\n"
                yield "\nUser Access Verification\n\n"
            while True:
                node = self.node
                if mode == "local":
                    username = yield Prompt("Username: ")
                    password = yield Prompt("Password: ", echo=False)
                    if node.verify_user(username or "", password or ""):
                        self._activate_root(username or "")
                        break
                else:
                    password = yield Prompt("Password: ", echo=False)
                    line = self._console_line()
                    if line is not None and line.password is not None and password == line.password:
                        self._activate_root(None)
                        break
                yield "% Login invalid\n"
        exec_banner = banner_text(self.node.banner_exec)
        if exec_banner:
            yield exec_banner + "\n"

    def _activate_root(self, username: Optional[str]) -> None:
        from .ios.shell import Session

        node = self.node
        line = self._console_line()
        privilege = 1
        if line is not None and line.privilege_level is not None:
            privilege = int(line.privilege_level)
        if username is not None and username in node.user_privilege:
            privilege = int(node.user_privilege[username])
        session = Session(
            privilege=privilege,
            line_type="console",
            line_name="con 0",
            terminal_length=_line_length(line),
            history_size=int(line.history_size) if line is not None else 10,
            username=username,
        )
        shell = self.make_ios_shell(node, session)
        self.stack = [SessionFrame(shell=shell, node_name=self.node_name, username=username)]
        self.state = "active"

    def _wire(self, shell) -> None:
        shell.runtime = self.runtime
        shell.engine_provider = self.runtime.engines
        shell.console = self
        shell.terminal = self.terminal

    def make_ios_shell(self, node, session):
        """An ``IosShell`` wired to the runtime, its engines and this console."""
        from .ios.shell import IosShell

        shell = IosShell(node, session=session)
        self._wire(shell)
        return shell

    # ------------------------------------------------------------------ #
    # Nested sessions                                                     #
    # ------------------------------------------------------------------ #
    def open_session(
        self,
        node_name: str,
        session,
        label: str,
        transport: str,
        remote_address: Optional[str] = None,
        username: Optional[str] = None,
        ssh_version: Optional[int] = None,
    ) -> SessionFrame:
        """Push a VTY shell for ``node_name`` on top of the stack (ssh/telnet).

        Called from inside the running ``ssh``/``telnet`` command; the new
        shell's prompt is drawn when that command finishes.
        """
        node = self.runtime.nodes[node_name]
        shell = self.make_ios_shell(node, session)
        saved = self.terminal.export_history() if self.terminal is not None else None
        frame = SessionFrame(
            shell=shell,
            node_name=node_name,
            label=label,
            transport=transport,
            remote_address=remote_address,
            username=username,
            saved_history=saved,
            opened_at=self.runtime.now(),
            ssh_version=ssh_version,
        )
        self.stack.append(frame)
        if self.terminal is not None:
            self.terminal.import_history([], getattr(session, "history_size", 10))
        return frame

    def nested_frames(self) -> List[SessionFrame]:
        return self.stack[1:]

    def frame_of(self, shell) -> Optional[SessionFrame]:
        """The stack frame running ``shell`` (``None`` if not on this console)."""
        return next((frame for frame in self.stack if frame.shell is shell), None)

    def root_session(self):
        """The ``Session`` logged in on this console's own line (``con 0``), or
        ``None`` while nobody is: not started, at the login prompt, logged out
        (``Press RETURN``) or a VPCS console."""
        if self.state != "active" or not self.stack:
            return None
        shell = self.stack[0].shell
        if getattr(shell, "closed", False):
            return None
        session = getattr(shell, "session", None)
        if session is None or getattr(session, "line_type", None) != "console":
            return None
        return session

    def _pop_frames(self, index: int) -> None:
        """Remove ``stack[index:]`` and restore the parent's history."""
        if index <= 0 or index >= len(self.stack):
            return
        first = self.stack[index]
        for frame in self.stack[index:]:
            if self.runtime.nodes.get(frame.node_name) is getattr(frame.shell, "node", None):
                self._drain_syslog(frame)
        del self.stack[index:]
        if first.saved_history is not None and self.terminal is not None:
            self.terminal.import_history(*first.saved_history)

    def close_sessions_into(self, node_name: str) -> None:
        """The node went away (reload): close every nested session into it."""
        index = next(
            (i for i, frame in enumerate(self.stack) if i > 0 and frame.node_name == node_name),
            None,
        )
        if index is None or self.state != "active":
            return
        label = self.stack[index].label
        terminal = self.terminal
        if terminal is not None and not terminal.is_idle:
            terminal.cancel_command()
        self._pop_frames(index)
        if terminal is not None:
            message = f"\n[Connection to {label} closed by foreign host]\n"
            self._broadcast(terminal.run_command(_text(message)))

    # ------------------------------------------------------------------ #
    # Command execution (called through the facade shell)                 #
    # ------------------------------------------------------------------ #
    def _run_top(self, make):
        frame = self.top_frame()
        if self.state != "active" or frame is None:
            return _empty()
        return self._run_in_frame(frame, make(frame.shell))

    def _run_in_frame(self, frame: SessionFrame, inner):
        checkpoint = getattr(self.runtime, "oper_checkpoint", None)
        if checkpoint is not None:
            checkpoint()
        if inner is not None:
            yield from inner
        report = getattr(self.runtime, "oper_report", None)
        if report is not None:
            report()
        self._drain_syslog(frame)
        if frame in self.stack:
            index = self.stack.index(frame)
            if index > 0 and getattr(frame.shell, "closed", False):
                label = frame.label
                self._pop_frames(index)
                yield f"\n[Connection to {label} closed by foreign host]\n"

    def _drain_syslog(self, frame: SessionFrame) -> None:
        take = getattr(frame.shell, "take_config_syslog", None)
        if take is None:
            return
        for message in take():
            self.runtime.emit_log(frame.node_name, message)

    def _prompt_suppressed(self) -> bool:
        """Facade ``closed``: no prompt outside an active session, after the
        root session ended, or while this node's reload is pending."""
        if self.state != "active" or not self.stack:
            return True
        if getattr(self.stack[0].shell, "closed", False):
            return True
        pending = getattr(self.runtime, "reload_pending", None)
        return bool(pending is not None and pending(self.node_name))

    # ------------------------------------------------------------------ #
    # Input                                                               #
    # ------------------------------------------------------------------ #
    def feed(self, data) -> str:
        """Process input from any viewer; return the output it produced.

        The same output is also pushed to every viewer's sink.
        """
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8", errors="replace")
        collected: List[str] = []
        self._collectors.append(collected)
        self._busy += 1
        try:
            for char in data:
                self._feed_char(char)
                self._after_input()
        finally:
            self._busy -= 1
            self._collectors.pop()
        return "".join(collected)

    def _feed_char(self, char: str) -> None:
        self._touched = True
        last, self._last_char = self._last_char, char
        if self._swallow_lf:
            self._swallow_lf = False
            if char == "\n" and last == "\r":
                return
        if self.state == "idle":
            if char in ("\r", "\n"):
                if char == "\r":
                    self._swallow_lf = True
                self._broadcast(self.start())
                self._touched = True
            return
        terminal = self.terminal
        if terminal is None:
            return
        if self.state == "gate" and char in ("\x03", "\x1a"):
            # Ctrl-C / Ctrl-Z restart the login challenge (the terminal aborts
            # the pending Prompt on Ctrl-C; _after_input restarts the dialog).
            output = terminal.feed("\x03")
            if terminal.is_idle:
                output = ("^C" if char == "\x03" else "^Z") + output
            self._broadcast(output)
            return
        self._broadcast(terminal.feed(char))

    def _after_input(self) -> None:
        for frame in list(self.stack):
            self._drain_syslog(frame)
        terminal = self.terminal
        if terminal is not None and terminal.is_idle:
            if self.state == "gate":
                self._broadcast(terminal.run_command(self._login_sequence(header=False)))
            elif self.state == "active" and self.stack:
                root = self.stack[0].shell
                pending = getattr(self.runtime, "reload_pending", None)
                reloading = bool(pending is not None and pending(self.node_name))
                if getattr(root, "closed", False) and not reloading:
                    self._enter_idle(_LOGOUT_TEMPLATE.format(host=self.node.hostname))
        self._flush_logs()
        run_deferred = getattr(self.runtime, "_run_deferred", None)
        if run_deferred is not None:
            run_deferred()
            self._flush_logs()

    # ------------------------------------------------------------------ #
    # Syslog delivery                                                     #
    # ------------------------------------------------------------------ #
    def monitor_frames(self, node_name: str) -> List[SessionFrame]:
        """Nested VTY frames on ``node_name`` that have ``terminal monitor``."""
        result = []
        for frame in self.stack[1:]:
            session = getattr(frame.shell, "session", None)
            if frame.node_name == node_name and session is not None and session.terminal_monitor:
                result.append(frame)
        return result

    def deliver_log(self, line: str, frame: Optional[SessionFrame] = None) -> None:
        """Queue a rendered syslog line; shown as soon as it cannot interleave
        with command output (immediately when the console is not busy)."""
        self._log_queue.append((line, frame))
        if len(self._log_queue) > _LOG_QUEUE_LIMIT:
            del self._log_queue[0]
        if not self._busy:
            self._flush_logs()

    def _flush_logs(self) -> None:
        if not self._log_queue:
            return
        # Drop lines meant for a VTY session that has gone away.
        self._log_queue = [
            (line, frame)
            for line, frame in self._log_queue
            if frame is None or any(frame is live for live in self.stack)
        ]
        if not self._log_queue:
            return
        if self.state == "idle":
            text = "".join(to_crlf(line) + "\r\n" for line, _frame in self._log_queue)
            self._log_queue.clear()
            self._broadcast(text)
            return
        terminal = self.terminal
        if self.state != "active" or terminal is None:
            return  # login dialog / start in progress: hold
        if not terminal.is_idle and self._shell.logging_synchronous:
            return  # logging synchronous: wait for the prompt
        # Messages that arrived together are printed together, followed by a
        # single prompt reprint (IOS ``logging synchronous`` behaviour).
        lines = [line for line, _frame in self._log_queue]
        self._log_queue.clear()
        self._broadcast(terminal.inject_message("\n".join(lines)))


def _line_length(line) -> int:
    """Console/VTY page length: ``length N`` when configured, else no paging."""
    if line is None or line.length is None:
        return 0
    try:
        return max(0, int(line.length))
    except (TypeError, ValueError):
        return 0


def line_length(line) -> int:
    """Public alias of the page-length rule (used by nested VTY sessions)."""
    return _line_length(line)
