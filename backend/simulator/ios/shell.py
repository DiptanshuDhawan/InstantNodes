"""The IOS command shell (Agent A1).

:class:`IosShell` implements :class:`simulator.ios.protocol.ShellProtocol`.  It
owns command *semantics* only -- modes, prompts, privilege, parsing, dispatch,
parent-mode fallback, ``do`` and output pipes.  All character I/O (echo, line
editing, history storage, ``--More--`` paging, driving ``Sleep``/``Prompt``) is
the terminal's job (Agent A2); the shell merely exposes ``run`` / ``help_text``
/ ``complete`` / ``interrupt`` / ``prompt`` and the ``ShellProtocol``
properties, and may read ``self.terminal.history``.

Modes and prompts (``prompt()`` returns the hostname + suffix, no trailing
space)::

    exec (privilege 1)   R1>
    exec (privilege 15)  R1#
    config               R1(config)#
    config-if            R1(config-if)#
    config-subif         R1(config-subif)#
    config-if-range      R1(config-if-range)#
    config-line          R1(config-line)#
    config-router        R1(config-router)#
    dhcp-config          R1(dhcp-config)#
    config-vlan          R1(config-vlan)#

Error strings produced by :meth:`run` (exact IOS wording):

* ambiguous   -> ``% Ambiguous command:  "<input>"``
* invalid     -> a caret line (``^`` under the first char of the bad token,
  offset by the prompt length) followed by
  ``% Invalid input detected at '^' marker.``
* incomplete  -> ``% Incomplete command.`` (or, for a bare ``show``,
  ``% Type "show ?" for a list of subcommands``)

Like IOS, a line with an output modifier (``show ... | include x``) is parsed
in full before anything runs: a command that does not parse reports its own
error (never filtered), a malformed modifier is reported without running the
command (caret under the bad filter keyword, or ``% Incomplete command.``).

Config-exit syslog hook: whenever the shell leaves configuration mode it
enqueues ``%SYS-5-CONFIG_I: Configured from console by <origin>`` (without a
timestamp), where ``<origin>`` is :func:`session_origin` -- ``console``,
``admin on console`` (``login local``), ``vty1 (10.0.0.3)`` or
``admin on vty1 (10.0.0.3)``.  The console drains it with
:meth:`take_config_syslog` and the runtime prepends the service timestamp.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from ..models import NodeState
from .commands import ensure_registered
from .parser import (
    CONFIG,
    CONFIG_IF,
    CONFIG_IF_RANGE,
    CONFIG_LINE,
    CONFIG_ROUTER,
    CONFIG_SUBIF,
    CONFIG_SUBMODES,
    CONFIG_VLAN,
    DHCP_CONFIG,
    EXEC,
    INCOMPLETE,
    INVALID,
    REGISTRY,
    SHOW_SUBCOMMAND_HINT,
    CommandContext,
    ambiguous_message,
    format_help_rows,
)
from .protocol import Prompt, Sleep  # noqa: F401  (Sleep re-exported for handlers)

#: Suffix shown by ``prompt()`` for each configuration mode.
_MODE_SUFFIX = {
    CONFIG: "(config)",
    CONFIG_IF: "(config-if)",
    CONFIG_SUBIF: "(config-subif)",
    CONFIG_IF_RANGE: "(config-if-range)",
    CONFIG_LINE: "(config-line)",
    CONFIG_ROUTER: "(config-router)",
    DHCP_CONFIG: "(dhcp-config)",
    CONFIG_VLAN: "(config-vlan)",
}

CONFIG_I_MESSAGE = "%SYS-5-CONFIG_I: Configured from console by console"


class ParseErrorText(str):
    """The text of a parse error (caret + ``% Invalid input``, ``% Ambiguous``
    or ``% Incomplete``).

    Marked so an output filter never removes it: IOS reports a command that
    does not parse as is, whatever ``| include ...`` follows it (this also
    covers ``do <bad command> | include x`` in configuration modes).
    """


def vty_number(line_name: Optional[str]) -> Optional[int]:
    """Number of a single VTY line name (``"vty 3"`` -> 3), else ``None``."""
    parts = (line_name or "").split()
    if len(parts) == 2 and parts[0] == "vty" and parts[1].isdigit():
        return int(parts[1])
    return None


def vty_block_range(block_name: Optional[str]) -> Optional[Tuple[int, int]]:
    """``(first, last)`` of a configured VTY block (``node.lines`` key).

    ``"vty 0 4"`` -> ``(0, 4)``, ``"vty 5"`` -> ``(5, 5)``; ``None`` for
    console/aux lines.
    """
    parts = (block_name or "").split()
    if not parts or parts[0] != "vty" or len(parts) not in (2, 3):
        return None
    if not all(part.isdigit() for part in parts[1:]):
        return None
    first = int(parts[1])
    last = int(parts[2]) if len(parts) == 3 else first
    return (first, last) if first <= last else (last, first)


def vty_blocks(node) -> List[Tuple[str, int, int]]:
    """Configured VTY blocks of ``node`` as ``(name, first, last)``, ordered by
    first line number (configuration order among equal starts)."""
    blocks = []
    for name in list(getattr(node, "lines", {}) or {}):
        span = vty_block_range(name)
        if span is not None:
            blocks.append((name, span[0], span[1]))
    blocks.sort(key=lambda block: block[1])
    return blocks


def session_line(node, session):
    """The configured ``LineConfig`` a session runs under, or ``None``.

    A session on one VTY line (``line_name="vty 1"``) is governed by the
    configured block covering that line; ``session.line_block`` (e.g.
    ``"vty 0 4"``) is the fallback, since ``line vty`` can split blocks while
    the session is open.
    """
    lines = getattr(node, "lines", None) or {}
    number = vty_number(getattr(session, "line_name", None))
    if number is not None:
        for name, first, last in vty_blocks(node):
            if first <= number <= last:
                return lines[name]
    for name in (getattr(session, "line_block", None), getattr(session, "line_name", None)):
        if name and name in lines:
            return lines[name]
    return None


def session_origin(session) -> str:
    """Who and where a session is, as IOS words it in syslog ("... by X").

    Console: ``console``, or ``admin on console`` after a ``login local``
    login.  VTY: ``vty1 (10.0.0.3)`` or ``admin on vty1 (10.0.0.3)``.
    """
    username = getattr(session, "username", None) or None
    if getattr(session, "is_vty", False):
        parts = (getattr(session, "line_name", None) or "vty 0").split()
        label = parts[0] + (parts[1] if len(parts) > 1 else "0")
        address = getattr(session, "remote_address", None)
        where = f"{label} ({address})" if address else label
    else:
        where = "console"
    return f"{username} on {where}" if username else where


@dataclass
class Frame:
    """One entry on the mode stack: a mode plus its submode target."""

    mode: str
    target: object = None


@dataclass
class Session:
    """Mutable per-connection state the shell operates on.

    The terminal/runtime constructs one of these per console/VTY connection in
    Phase 2; in Phase 1 the default (an enabled-capable console at privilege 1)
    is sufficient for the engine and its tests.
    """

    privilege: int = 1
    stack: List[Frame] = field(default_factory=lambda: [Frame(EXEC, None)])
    terminal_length: int = 24
    terminal_width: int = 80
    terminal_monitor: bool = False
    history_size: int = 10
    line_type: str = "console"  # console | vty | aux
    line_name: str = "con 0"
    closed: bool = False
    pending_syslog: List[str] = field(default_factory=list)
    #: Phase 2: login identity of a VTY session (``login local`` username) and
    #: the peer address it came from; used for "Configured from ... by ...".
    username: Optional[str] = None
    remote_address: Optional[str] = None
    #: The configured line block (``node.lines`` key) when ``line_name`` is a
    #: single line inside it, e.g. ``"vty 0 4"`` for ``line_name="vty 1"``;
    #: ``None`` means ``line_name`` itself is the configured line.
    line_block: Optional[str] = None

    @property
    def mode(self) -> str:
        return self.stack[-1].mode

    @property
    def target(self) -> object:
        return self.stack[-1].target

    def in_config(self) -> bool:
        return len(self.stack) > 1

    @property
    def is_vty(self) -> bool:
        return self.line_type == "vty"


class IosShell:
    """A Cisco IOS command interpreter bound to one :class:`NodeState`."""

    def __init__(
        self,
        node: NodeState,
        session: Optional[Session] = None,
        terminal: object = None,
    ) -> None:
        ensure_registered()
        self.node = node
        self.session = session if session is not None else Session()
        #: Set by the TerminalSession when the shell is attached to it.
        self.terminal = terminal
        #: Phase 2: a zero-arg callable returning a fresh
        #: :class:`simulator.engines.EngineBundle` (installed by the runtime).
        #: Command handlers reach live network state via ``ctx.engines``.
        self.engine_provider = None
        #: Phase 2: the owning ``SimulationRuntime`` (now()/emit_log/nested
        #: sessions); ``None`` in Phase 1 unit tests.
        self.runtime = None

    # ------------------------------------------------------------------ #
    # ShellProtocol: prompt / properties                                 #
    # ------------------------------------------------------------------ #
    def prompt(self) -> str:
        mode = self.session.mode
        host = self.node.hostname
        if mode == EXEC:
            return host + ("#" if self.session.privilege >= 15 else ">")
        return host + _MODE_SUFFIX.get(mode, "(config)") + "#"

    @property
    def terminal_length(self) -> int:
        return self.session.terminal_length

    @property
    def history_size(self) -> int:
        return self.session.history_size

    @property
    def logging_synchronous(self) -> bool:
        line = self.line_config()
        return bool(line and line.logging_synchronous)

    @property
    def closed(self) -> bool:
        return self.session.closed

    def line_config(self):
        """The configured ``LineConfig`` of this session's line (or ``None``)."""
        return session_line(self.node, self.session)

    # ------------------------------------------------------------------ #
    # Mode / privilege transitions (used by core command handlers)       #
    # ------------------------------------------------------------------ #
    def push_mode(self, mode: str, target: object = None) -> None:
        self.session.stack.append(Frame(mode, target))

    def do_exit(self) -> None:
        """``exit``: pop one frame; from exec this closes the session."""
        before = self.session.in_config()
        if len(self.session.stack) <= 1:
            self.session.closed = True
        else:
            self.session.stack.pop()
        self._note_config_exit(before)

    def end_to_exec(self) -> None:
        """``end`` / Ctrl-Z: drop all configuration frames (privilege kept)."""
        before = self.session.in_config()
        del self.session.stack[1:]
        self._note_config_exit(before)

    def end_to_config(self) -> None:
        """Pop submodes back to global ``config`` (parent-mode fallback)."""
        if len(self.session.stack) > 2:
            del self.session.stack[2:]

    def close(self) -> None:
        """``logout``: end the session from anywhere."""
        before = self.session.in_config()
        self.session.closed = True
        self._note_config_exit(before)

    def enter_enable(self) -> None:
        self.session.privilege = 15

    def enter_disable(self) -> None:
        self.session.privilege = 1

    def set_history_size(self, size: int) -> None:
        self.session.history_size = size
        if self.terminal is not None:
            try:
                self.terminal.set_history_size(size)
            except AttributeError:
                pass

    def _note_config_exit(self, was_in_config: bool) -> None:
        if was_in_config and not self.session.in_config():
            self.session.pending_syslog.append(self.config_message())

    def config_message(self) -> str:
        """The ``%SYS-5-CONFIG_I`` text for this session's line and login.

        Console: ``Configured from console by console`` (``by admin on
        console`` after a ``login local`` login).  VTY: ``Configured from
        console by admin on vty1 (10.0.0.3)``, or without a username
        ``Configured from console by vty1 (10.0.0.3)``.
        """
        return f"%SYS-5-CONFIG_I: Configured from console by {session_origin(self.session)}"

    def take_config_syslog(self) -> List[str]:
        """Return and clear queued ``%SYS-5-CONFIG_I`` messages."""
        messages = list(self.session.pending_syslog)
        self.session.pending_syslog.clear()
        return messages

    # ------------------------------------------------------------------ #
    # ShellProtocol: execution                                           #
    # ------------------------------------------------------------------ #
    def run(self, line: str):
        command_text, pipe_spec, pipe_offset = self._split_pipe(line)
        if pipe_spec is not None and not self._accepts_output_modifier(command_text):
            # Only display commands take "| ..." (IOS): elsewhere the "|" is
            # ordinary text, e.g. "description a | b" or "banner motd |Hi|",
            # or an invalid token after a complete command.
            command_text, pipe_spec, pipe_offset = line, None, len(line)
        stripped = command_text.strip()
        if not stripped or stripped.startswith("!"):
            return
        if pipe_spec is None:
            yield from self._dispatch(command_text)
            return
        # IOS parses the whole line before running anything.  A command that
        # does not parse reports its own error -- caret under the offending
        # token of the typed line, or ambiguous -- never filtered.  An
        # incomplete command cannot take an output modifier: the "|" itself is
        # the offending token (IOS only accepts it where <cr> is accepted).
        result, in_parent = self._resolve(command_text)
        if result.status == "incomplete":
            caret = " " * (len(self.prompt()) + pipe_offset) + "^"
            yield ParseErrorText(caret + "\n" + INVALID)
            return
        if result.status != "ok":
            yield self._format_parse_error(result, len(self.prompt()), line.strip())
            return
        # A malformed output modifier is reported without running the command.
        output_filter, error = self._parse_filter(line, pipe_spec, pipe_offset)
        if error is not None:
            yield error
            return
        collected: List[str] = []
        errors: List[str] = []
        generator = self._run_resolved(result, in_parent, command_text)
        sent = None
        try:
            while True:
                item = generator.send(sent)
                sent = None
                if isinstance(item, ParseErrorText):
                    errors.append(item)  # e.g. ``do <bad command> | include x``
                elif isinstance(item, str):
                    collected.append(item)
                # Sleep/Prompt during a piped command are ignored.
        except StopIteration:
            pass
        text = "".join(collected)
        filtered = output_filter.apply(text) if output_filter is not None else text
        parts = [part for part in [filtered] + errors if part]
        if parts:
            yield "\n".join(parts)

    def interrupt(self, key: str):
        if key == "ctrl-z" and self.session.in_config():
            self.end_to_exec()
        # "ctrl-c" at an idle prompt is a line abort (no-op here).
        return self._empty()

    def run_exec_text(self, text: str, base_offset: int = 0):
        """Run ``text`` as an exec command at privilege 15 (used by ``do``)."""
        if not text.strip():
            return
        result = REGISTRY.match(EXEC, text, self.node, 15)
        if result.status == "ok":
            yield from self._invoke(result, text)
            return
        yield self._format_parse_error(result, len(self.prompt()) + base_offset, text.strip())

    # ------------------------------------------------------------------ #
    # ShellProtocol: help / completion                                   #
    # ------------------------------------------------------------------ #
    def help_text(self, buffer: str) -> str:
        command_text, pipe_spec, _offset = self._split_pipe(buffer)
        if pipe_spec is not None and self._accepts_output_modifier(command_text):
            return self._filter_help(pipe_spec)
        return REGISTRY.help(self.session.mode, buffer if pipe_spec is not None else command_text,
                             self.node, self.session.privilege)

    def complete(self, buffer: str) -> Optional[str]:
        command_text, pipe_spec, _offset = self._split_pipe(buffer)
        if pipe_spec is not None:
            if self._accepts_output_modifier(command_text):
                return None
            command_text = buffer
        return REGISTRY.complete(
            self.session.mode, command_text, self.node, self.session.privilege
        )

    #: Commands whose output IOS lets "| include|exclude|begin|section|count" filter.
    _DISPLAY_COMMANDS = ("show", "more", "dir")

    def _accepts_output_modifier(self, command_text: str) -> bool:
        """True when ``command_text`` (the part before "|") is a display command.

        An unparsable command keeps the modifier so its own parse error is
        reported (see :meth:`run`); ``do`` is judged by the command it runs.
        """
        result, _in_parent = self._resolve(command_text)
        path = [str(part).lower() for part in (result.path or [])]
        if path and path[0] == "do":
            inner = str(result.args.get("cmd", "")) if result.status == "ok" else ""
            if not inner.strip():
                return True
            path = [str(part).lower() for part in (REGISTRY.match(EXEC, inner, self.node, 15).path or [])]
        if not path:
            return True
        return path[0] in self._DISPLAY_COMMANDS or path[:2] == ["write", "terminal"]

    # ------------------------------------------------------------------ #
    # Internal dispatch                                                  #
    # ------------------------------------------------------------------ #
    def _resolve(self, command_text: str):
        """Parse ``command_text`` in the current mode.

        Returns ``(result, in_parent)``.  ``result.status == "ok"`` when the
        command can run; ``in_parent`` is True when it parses only in global
        configuration mode (parent-mode fallback: the submode is left before it
        runs).  Otherwise ``result`` carries the current mode's parse error.
        """
        mode = self.session.mode
        result = REGISTRY.match(mode, command_text, self.node, self.session.privilege)
        if result.status == "ok":
            return result, False
        # Parent-mode fallback (IOS semantics): a command that does not parse in
        # a submode but parses in global config runs there (popping the
        # submode, and possibly pushing a new one).  This must not require the
        # first token to be unknown: ``ip dhcp pool X`` typed in config-if
        # matches ``ip`` there before failing.  When the parent cannot run it
        # either, the submode's own error is reported.
        if mode in CONFIG_SUBMODES:
            parent = REGISTRY.match(CONFIG, command_text, self.node, 15)
            if parent.status == "ok":
                return parent, True
        return result, False

    def _dispatch(self, command_text: str):
        result, in_parent = self._resolve(command_text)
        yield from self._run_resolved(result, in_parent, command_text)

    def _run_resolved(self, result, in_parent: bool, command_text: str):
        if result.status != "ok":
            yield self._format_parse_error(result, len(self.prompt()), command_text.strip())
            return
        if in_parent:
            self.end_to_config()
        yield from self._invoke(result, command_text)

    def _invoke(self, result, raw: str):
        ctx = CommandContext(
            shell=self,
            session=self.session,
            node=self.node,
            args=result.args,
            path=result.path,
            raw=raw,
            negate=bool(result.path) and result.path[0] == "no",
        )
        output = result.command.handler(ctx)
        if output is None:
            return
        if isinstance(output, str):
            if output:
                yield output
            return
        yield from output

    def _format_parse_error(self, result, base_offset: int, raw_text: str) -> str:
        if result.status == "ambiguous":
            return ParseErrorText(ambiguous_message(raw_text))
        if result.status == "incomplete":
            if result.path == ["show"]:
                return ParseErrorText(SHOW_SUBCOMMAND_HINT)
            return ParseErrorText(INCOMPLETE)
        caret = " " * (base_offset + (result.error_offset or 0)) + "^"
        return ParseErrorText(caret + "\n" + INVALID)

    @staticmethod
    def _empty():
        return
        yield  # pragma: no cover  (makes this a generator)

    # ------------------------------------------------------------------ #
    # Output pipes (filters.py is owned by Agent A2; imported lazily)    #
    # ------------------------------------------------------------------ #
    def _filters(self):
        try:
            from . import filters as module  # type: ignore
        except Exception:
            return None
        return module

    def _split_pipe(self, line: str):
        module = self._filters()
        if module is not None and hasattr(module, "split_pipe"):
            try:
                return module.split_pipe(line)
            except Exception:
                pass
        return line, None, len(line)

    def _parse_filter(self, line: str, pipe_spec: str, pipe_offset: int):
        """Parse the output modifier after ``|`` (IOS parses it before running).

        Returns ``(OutputFilter or None, None)`` or ``(None, error_text)``.  An
        unknown filter keyword (or a regular expression that does not compile)
        puts the caret under it in the typed line; a missing keyword or
        expression is ``% Incomplete command.``.
        """
        module = self._filters()
        if module is None or not hasattr(module, "parse_filter"):
            return None, None
        try:
            return module.parse_filter(pipe_spec), None
        except Exception as exc:
            kind = getattr(exc, "kind", "invalid")
            if kind == "incomplete":
                return None, ParseErrorText(INCOMPLETE)
            if kind == "ambiguous":
                return None, ParseErrorText(ambiguous_message(line.strip()))
            # The spec starts right after the "|" (filters.split_pipe).
            offset = getattr(exc, "offset", 0) or 0
            column = len(self.prompt()) + pipe_offset + 1 + offset
            return None, ParseErrorText(" " * column + "^\n" + INVALID)

    def _filter_help(self, pipe_spec: str) -> str:
        module = self._filters()
        if module is not None and hasattr(module, "filter_help"):
            try:
                return format_help_rows(list(module.filter_help(pipe_spec)))
            except Exception:
                pass
        return "\n"
