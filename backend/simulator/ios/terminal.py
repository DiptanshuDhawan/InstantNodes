"""Terminal line discipline for the IOS/VPCS shells (see ``ios/protocol.py``).

:class:`TerminalSession` owns characters in / characters out and drives any
object implementing :class:`~simulator.ios.protocol.ShellProtocol`: it echoes
input, performs line editing (cursor keys, control keys), keeps per-session
command history, paginates output with ``--More--``, collects
:class:`~simulator.ios.protocol.Prompt` input, paces
:class:`~simulator.ios.protocol.Sleep` yields, buffers typeahead, and injects
asynchronous messages.

The shell yields command output using ``\\n`` newlines; the terminal converts
them to CRLF on the wire.

Synchronous test API
--------------------
``feed(data)`` processes input and returns *all* output produced, fully draining
any running command generator without ever sleeping, so tests can assert the
exact bytes.  ``start()`` returns the initial prompt.  ``inject_message(text)``
delivers an asynchronous log line and returns the bytes it produced.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple, Union

from .protocol import Prompt, ShellProtocol, Sleep


class _Missing:
    """Sentinel meaning "no value to .send() into the command generator"."""


_MISSING = _Missing()

#: Text drawn for the ``--More--`` pager prompt.
MORE_PROMPT = "--More--"

_DEFAULT_LENGTH = 24
_DEFAULT_HISTORY = 10


def to_crlf(text: str) -> str:
    """Normalise any newline convention in ``text`` to CRLF."""
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")


class TerminalSession:
    """A line-discipline front-end driving a :class:`ShellProtocol`.

    Parameters
    ----------
    shell:
        The shell to drive.  ``shell.terminal`` is set to this session.
    realtime:
        When ``False`` (the default, used by tests) :class:`Sleep` yields are
        skipped entirely.  When ``True`` and ``sleep_hook`` is supplied, the hook
        is called for each :class:`Sleep` (a Phase-2 pacing seam); ``feed`` still
        never blocks on its own.
    on_output:
        Optional callback invoked with every chunk of output as it is produced
        (a streaming seam for the Phase-2 push model).  Output is *also*
        accumulated and returned by :meth:`feed` / :meth:`start` /
        :meth:`inject_message`.
    sleep_hook:
        Optional ``Callable[[float], None]`` used only when ``realtime`` is True.
    """

    def __init__(
        self,
        shell: ShellProtocol,
        realtime: bool = False,
        on_output: Optional[Callable[[str], None]] = None,
        sleep_hook: Optional[Callable[[float], None]] = None,
    ) -> None:
        self._shell = shell
        self._realtime = realtime
        self._on_output = on_output
        self._sleep_hook = sleep_hook
        shell.terminal = self  # type: ignore[assignment]

        # Output accumulation.
        self._out: List[str] = []

        # Pending (not yet consumed) input characters.
        self._inbuf: str = ""
        self._ignore_lf = False  # swallow the LF of a CRLF pair

        # Line-editing state.
        self._line = ""
        self._cursor = 0

        # High-level input state: idle / more / prompt_line / prompt_key.
        # 'running' is a transient marker used only while a command is being
        # pumped synchronously; the input loop never observes it.
        self._state = "idle"
        self._started = False

        # Running-command state.
        self._gen = None  # type: ignore[var-annotated]
        self._send: Union[_Missing, str] = _MISSING
        self._pending = ""  # buffered command output awaiting pagination
        self._page_count = 0
        self._midline = False  # True when output is sitting mid-line

        # Prompt collection state.
        self._prompt: Optional[Prompt] = None
        self._prompt_buf = ""

        # History.
        self._history: List[str] = []
        try:
            self._history_max = int(shell.history_size)
        except Exception:
            self._history_max = _DEFAULT_HISTORY
        if self._history_max < 0:
            self._history_max = _DEFAULT_HISTORY
        self._hist_index = 0
        self._hist_stash: Optional[str] = None

    # ------------------------------------------------------------------ #
    # TerminalProtocol
    # ------------------------------------------------------------------ #
    @property
    def history(self) -> List[str]:
        """Commands entered this session, oldest first."""
        return list(self._history)

    def set_history_size(self, size: int) -> None:
        """Apply ``terminal history size N`` / ``history size N``."""
        self._history_max = max(0, int(size))
        if self._history_max == 0:
            self._history = []
        elif len(self._history) > self._history_max:
            self._history = self._history[-self._history_max:]

    # ------------------------------------------------------------------ #
    # Public driver API
    # ------------------------------------------------------------------ #
    def start(self) -> str:
        """Emit the initial prompt (idempotent) and return the output."""
        if not self._started:
            self._start_emit()
        return self._drain()

    def feed(self, data: Union[str, bytes]) -> str:
        """Process ``data`` and return every byte of output it produced."""
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("latin-1")
        if not self._started:
            self._start_emit()
        self._inbuf += data
        self._process()
        return self._drain()

    def inject_message(self, text: str) -> str:
        """Deliver an asynchronous message (e.g. a syslog line) to the screen.

        The message is placed on its own line.  When the shell requests
        ``logging synchronous`` and the session is idle at the prompt, the prompt
        and any partially typed input are reprinted afterwards.  Returns the
        output produced.
        """
        message = to_crlf(text)
        if not message.endswith("\r\n"):
            message += "\r\n"

        synchronous = self._logging_synchronous()
        if self._state == "idle" and self._started:
            self._emit("\r\n")
            self._emit(message)
            if synchronous:
                self._emit(self._shell.prompt() + self._line)
                self._cursor = len(self._line)
        else:
            # Mid-command / mid-prompt: drop the line cleanly and print it.
            if self._midline:
                self._emit("\r\n")
                self._midline = False
            self._emit(message)
        return self._drain()

    # ------------------------------------------------------------------ #
    # Output plumbing
    # ------------------------------------------------------------------ #
    def _emit(self, text: str) -> None:
        if not text:
            return
        self._out.append(text)
        if self._on_output is not None:
            self._on_output(text)

    def _drain(self) -> str:
        out = "".join(self._out)
        self._out = []
        return out

    def _start_emit(self) -> None:
        self._started = True
        self._state = "idle"
        self._midline = False
        self._emit(self._shell.prompt())

    # ------------------------------------------------------------------ #
    # Shell attribute helpers (defensive against partial shells)
    # ------------------------------------------------------------------ #
    def _page_length(self) -> int:
        try:
            return int(self._shell.terminal_length)
        except Exception:
            return _DEFAULT_LENGTH

    def _logging_synchronous(self) -> bool:
        try:
            return bool(self._shell.logging_synchronous)
        except Exception:
            return False

    def _shell_closed(self) -> bool:
        try:
            return bool(self._shell.closed)
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Input event loop
    # ------------------------------------------------------------------ #
    def _process(self) -> None:
        while self._inbuf:
            if self._state == "running":  # pragma: no cover - safety
                break
            event = self._next_event()
            if event is None:
                break  # incomplete escape sequence; wait for more input
            kind, value = event
            if kind == "ignore":
                continue
            self._handle_event(kind, value)

    def _next_event(self) -> Optional[Tuple[str, Optional[str]]]:
        """Pop the next input event, or ``None`` if more bytes are needed."""
        buf = self._inbuf
        first = buf[0]
        if first != "\x1b":
            self._inbuf = buf[1:]
            return ("char", first)
        parsed = _parse_escape(buf)
        if parsed is None:
            return None  # partial escape sequence
        consumed, name = parsed
        self._inbuf = buf[consumed:]
        if name is None:
            return ("ignore", None)
        return ("key", name)

    def _handle_event(self, kind: str, value: Optional[str]) -> None:
        if kind == "key":
            if self._state == "idle":
                self._idle_key(value)  # type: ignore[arg-type]
            return
        char = value  # type: ignore[assignment]
        if self._state == "idle":
            self._idle_char(char)
        elif self._state == "more":
            self._more_char(char)
        elif self._state == "prompt_line":
            self._prompt_line_char(char)
        elif self._state == "prompt_key":
            self._prompt_key_char(char)

    # ------------------------------------------------------------------ #
    # Idle line editing
    # ------------------------------------------------------------------ #
    def _idle_key(self, name: str) -> None:
        if name == "left":
            self._move_left()
        elif name == "right":
            self._move_right()
        elif name == "home":
            self._move_home()
        elif name == "end":
            self._move_end()
        elif name == "delete":
            self._delete_at()
        elif name == "up":
            self._history_prev()
        elif name == "down":
            self._history_next()

    def _idle_char(self, ch: str) -> None:
        if ch == "\r":
            self._ignore_lf = True
            self._submit_line()
            return
        if ch == "\n":
            if self._ignore_lf:
                self._ignore_lf = False
                return
            self._submit_line()
            return
        self._ignore_lf = False

        if ch in ("\x08", "\x7f"):       # Backspace / Ctrl-H
            self._backspace()
        elif ch == "\t":                 # Tab
            self._tab()
        elif ch == "?":                  # context help
            self._help()
        elif ch == "\x01":               # Ctrl-A
            self._move_home()
        elif ch == "\x05":               # Ctrl-E
            self._move_end()
        elif ch == "\x02":               # Ctrl-B
            self._move_left()
        elif ch == "\x06":               # Ctrl-F
            self._move_right()
        elif ch == "\x04":               # Ctrl-D
            self._delete_at()
        elif ch == "\x0b":               # Ctrl-K
            self._kill_to_end()
        elif ch == "\x15":               # Ctrl-U
            self._erase_left(self._cursor)
        elif ch == "\x17":               # Ctrl-W
            self._kill_word()
        elif ch == "\x10":               # Ctrl-P
            self._history_prev()
        elif ch == "\x0e":               # Ctrl-N
            self._history_next()
        elif ch == "\x03":               # Ctrl-C
            self._interrupt_line("ctrl-c")
        elif ch == "\x1a":               # Ctrl-Z
            self._interrupt_line("ctrl-z")
        elif ch == "\x1e":               # Ctrl-^ (no running command at idle)
            pass
        elif ord(ch) >= 0x20:            # printable
            self._insert(ch)

    def _insert(self, ch: str) -> None:
        tail = self._line[self._cursor:]
        self._line = self._line[: self._cursor] + ch + tail
        self._cursor += 1
        self._emit(ch + tail + "\b" * len(tail))

    def _backspace(self) -> None:
        self._erase_left(1)

    def _erase_left(self, count: int) -> None:
        """Delete ``count`` characters to the left of the cursor."""
        count = min(count, self._cursor)
        if count <= 0:
            return
        tail = self._line[self._cursor:]
        self._line = self._line[: self._cursor - count] + tail
        self._cursor -= count
        self._emit("\b" * count + tail + " " * count + "\b" * (len(tail) + count))

    def _delete_at(self) -> None:
        if self._cursor >= len(self._line):
            return
        tail = self._line[self._cursor + 1:]
        self._line = self._line[: self._cursor] + tail
        self._emit(tail + " " + "\b" * (len(tail) + 1))

    def _move_left(self) -> None:
        if self._cursor > 0:
            self._cursor -= 1
            self._emit("\b")

    def _move_right(self) -> None:
        if self._cursor < len(self._line):
            self._emit(self._line[self._cursor])
            self._cursor += 1

    def _move_home(self) -> None:
        if self._cursor > 0:
            self._emit("\b" * self._cursor)
            self._cursor = 0

    def _move_end(self) -> None:
        if self._cursor < len(self._line):
            self._emit(self._line[self._cursor:])
            self._cursor = len(self._line)

    def _kill_to_end(self) -> None:
        if self._cursor >= len(self._line):
            return
        tail = self._line[self._cursor:]
        self._line = self._line[: self._cursor]
        self._emit(" " * len(tail) + "\b" * len(tail))

    def _kill_word(self) -> None:
        index = self._cursor
        while index > 0 and self._line[index - 1].isspace():
            index -= 1
        while index > 0 and not self._line[index - 1].isspace():
            index -= 1
        self._erase_left(self._cursor - index)

    def _replace_line(self, new: str) -> None:
        """Erase the visible line and redraw it as ``new`` (cursor at end)."""
        if self._cursor < len(self._line):
            self._emit(self._line[self._cursor:])
        old_len = len(self._line)
        self._emit("\b" * old_len + " " * old_len + "\b" * old_len)
        self._line = new
        self._cursor = len(new)
        self._emit(new)

    def _tab(self) -> None:
        result = self._shell.complete(self._line)
        if result is None:
            self._emit("\r\n" + self._shell.prompt() + self._line)
            self._cursor = len(self._line)
        elif result.startswith(self._line) and self._cursor == len(self._line):
            self._emit(result[len(self._line):])
            self._line = result
            self._cursor = len(result)
        else:
            self._replace_line(result)

    def _help(self) -> None:
        self._emit("?")
        self._emit("\r\n")
        self._emit(to_crlf(self._shell.help_text(self._line)))
        self._emit(self._shell.prompt() + self._line)
        self._cursor = len(self._line)

    def _interrupt_line(self, key: str) -> None:
        marker = "^C" if key == "ctrl-c" else "^Z"
        self._emit(marker + "\r\n")
        self._midline = False
        self._line = ""
        self._cursor = 0
        self._ignore_lf = False
        self._reset_history_nav()
        self._page_count = 1
        self._gen = self._shell.interrupt(key)
        self._send = _MISSING
        self._pump()

    def _submit_line(self) -> None:
        line = self._line
        self._emit("\r\n")
        self._midline = False
        if line.strip():
            self._add_history(line)
        self._reset_history_nav()
        self._line = ""
        self._cursor = 0
        self._page_count = 1  # account for the prompt line on the first screen
        self._gen = self._shell.run(line)
        self._send = _MISSING
        self._pump()

    # ------------------------------------------------------------------ #
    # History
    # ------------------------------------------------------------------ #
    def _add_history(self, line: str) -> None:
        self._history.append(line)
        if self._history_max == 0:
            self._history = []
        elif len(self._history) > self._history_max:
            self._history = self._history[-self._history_max:]

    def _reset_history_nav(self) -> None:
        self._hist_index = len(self._history)
        self._hist_stash = None

    def _history_prev(self) -> None:
        if not self._history:
            return
        if self._hist_index >= len(self._history):
            self._hist_stash = self._line
        if self._hist_index > 0:
            self._hist_index -= 1
            self._replace_line(self._history[self._hist_index])

    def _history_next(self) -> None:
        if self._hist_index >= len(self._history):
            return
        self._hist_index += 1
        if self._hist_index >= len(self._history):
            self._replace_line(self._hist_stash or "")
            self._hist_stash = None
        else:
            self._replace_line(self._history[self._hist_index])

    # ------------------------------------------------------------------ #
    # Command generator pump
    # ------------------------------------------------------------------ #
    def _pump(self) -> None:
        self._state = "running"
        while self._gen is not None:
            try:
                if isinstance(self._send, _Missing):
                    item = next(self._gen)
                else:
                    value = self._send
                    self._send = _MISSING
                    item = self._gen.send(value)
            except StopIteration:
                self._finish_command()
                return
            except Exception:  # pragma: no cover - a command blew up; end it
                self._finish_command()
                return

            if isinstance(item, Sleep):
                self._do_sleep(item.seconds)
                continue
            if isinstance(item, Prompt):
                self._begin_prompt(item)
                return  # wait for input
            # Otherwise treat as output text.
            self._emit_output(item if isinstance(item, str) else str(item))
            if self._state == "more":
                return  # paused at --More--

    def _emit_output(self, chunk: str) -> None:
        self._pending += chunk.replace("\r\n", "\n").replace("\r", "\n")
        self._drain_output()

    def _drain_output(self) -> None:
        length = self._page_length()
        while self._pending:
            if length > 0 and self._page_count >= length:
                self._emit(MORE_PROMPT)
                self._state = "more"
                return
            newline = self._pending.find("\n")
            if newline == -1:
                self._emit(self._pending)
                self._midline = True
                self._pending = ""
                return
            line = self._pending[:newline]
            self._pending = self._pending[newline + 1:]
            self._emit(line + "\r\n")
            self._midline = False
            self._page_count += 1

    def _do_sleep(self, seconds: float) -> None:
        if self._realtime and self._sleep_hook is not None:
            self._sleep_hook(seconds)
        # In test mode (realtime False) sleeping is skipped entirely.

    def _finish_command(self) -> None:
        self._gen = None
        self._send = _MISSING
        self._pending = ""
        self._prompt = None
        if self._midline:
            self._emit("\r\n")
            self._midline = False
        self._state = "idle"
        self._line = ""
        self._cursor = 0
        self._reset_history_nav()
        if not self._shell_closed():
            self._emit(self._shell.prompt())

    def _abort_command(self) -> None:
        if self._gen is not None:
            try:
                self._gen.close()
            except Exception:  # pragma: no cover
                pass
        self._finish_command()

    # ------------------------------------------------------------------ #
    # --More-- pager
    # ------------------------------------------------------------------ #
    def _more_char(self, ch: str) -> None:
        if ch == " ":
            self._erase_more()
            self._page_count = 0
            self._resume_output()
        elif ch == "\r":
            self._ignore_lf = True
            self._erase_more()
            self._page_count = max(0, self._page_length() - 1)
            self._resume_output()
        elif ch == "\n":
            if self._ignore_lf:
                self._ignore_lf = False
                return
            self._erase_more()
            self._page_count = max(0, self._page_length() - 1)
            self._resume_output()
        else:
            # Any other key quits the pager and aborts the command.
            self._erase_more()
            self._abort_command()

    def _erase_more(self) -> None:
        self._emit("\r" + " " * len(MORE_PROMPT) + "\r")

    def _resume_output(self) -> None:
        self._state = "running"
        self._drain_output()
        if self._state == "more":
            return
        self._pump()

    # ------------------------------------------------------------------ #
    # Prompt collection
    # ------------------------------------------------------------------ #
    def _begin_prompt(self, prompt: Prompt) -> None:
        text = to_crlf(prompt.text)
        self._emit(text)
        self._midline = not text.endswith("\r\n")
        self._prompt = prompt
        self._prompt_buf = ""
        self._state = "prompt_key" if prompt.single_key else "prompt_line"

    def _prompt_line_char(self, ch: str) -> None:
        echo = self._prompt.echo if self._prompt else True
        if ch == "\r":
            self._ignore_lf = True
            self._finish_prompt_line()
            return
        if ch == "\n":
            if self._ignore_lf:
                self._ignore_lf = False
                return
            self._finish_prompt_line()
            return
        self._ignore_lf = False

        if ch in ("\x08", "\x7f"):
            if self._prompt_buf:
                self._prompt_buf = self._prompt_buf[:-1]
                if echo:
                    self._emit("\b \b")
        elif ch == "\x15":  # Ctrl-U
            if self._prompt_buf and echo:
                self._emit("\b \b" * len(self._prompt_buf))
            self._prompt_buf = ""
        elif ch in ("\x03", "\x1e"):  # Ctrl-C / Ctrl-^ abort the command
            if self._midline:
                self._emit("\r\n")
                self._midline = False
            self._abort_command()
        elif ord(ch) >= 0x20:
            self._prompt_buf += ch
            if echo:
                self._emit(ch)

    def _finish_prompt_line(self) -> None:
        answer = self._prompt_buf
        self._emit("\r\n")
        self._midline = False
        self._prompt = None
        self._prompt_buf = ""
        self._send = answer
        self._pump()

    def _prompt_key_char(self, ch: str) -> None:
        echo = self._prompt.echo if self._prompt else True
        if ch in ("\x03", "\x1e"):  # Ctrl-C / Ctrl-^ abort the command
            if self._midline:
                self._emit("\r\n")
                self._midline = False
            self._abort_command()
            return
        if ch == "\r":
            self._ignore_lf = True
            if echo:
                self._emit("\r\n")
                self._midline = False
            self._finish_prompt_key("")
            return
        if ch == "\n":
            if self._ignore_lf:
                self._ignore_lf = False
                return
            if echo:
                self._emit("\r\n")
                self._midline = False
            self._finish_prompt_key("")
            return
        self._ignore_lf = False
        # A confirmed keystroke echoes the key and advances to a new line
        # (IOS "[confirm]" behaviour).  Non-printable keys are not echoed.
        if echo and ord(ch) >= 0x20:
            self._emit(ch + "\r\n")
            self._midline = False
        self._finish_prompt_key(ch)

    def _finish_prompt_key(self, answer: str) -> None:
        self._prompt = None
        self._send = answer
        self._pump()

    # ------------------------------------------------------------------ #
    # Phase 2 console seam (A3b).  Additive helpers used by               #
    # ``simulator/console.py``; none of them changes the behaviour of the #
    # input/output paths above.                                          #
    # ------------------------------------------------------------------ #
    @property
    def started(self) -> bool:
        """True once the initial prompt (or a programmatic command) was drawn."""
        return self._started

    @property
    def is_idle(self) -> bool:
        """True when the prompt is shown and no command is running or waiting."""
        return self._started and self._state == "idle" and self._gen is None

    @property
    def input_state(self) -> str:
        """``idle`` | ``running`` | ``more`` | ``prompt_line`` | ``prompt_key``."""
        return self._state

    def redraw(self) -> str:
        """Text that repaints the current input context on a fresh line.

        Nothing is emitted; the caller sends the returned text to a terminal
        that (re)attached.  Idle: CRLF + prompt + pending input (cursor restored);
        Prompt: CRLF + the prompt's last line (+ typed text when echoed);
        pager: CRLF + ``--More--``.
        """
        if not self._started:
            return ""
        if self._state == "more":
            return "\r\n" + MORE_PROMPT
        if self._state in ("prompt_line", "prompt_key") and self._prompt is not None:
            text = to_crlf(self._prompt.text).split("\r\n")[-1]
            typed = ""
            if self._state == "prompt_line" and self._prompt.echo:
                typed = self._prompt_buf
            return "\r\n" + text + typed
        if self._state == "idle":
            back = len(self._line) - self._cursor
            return "\r\n" + self._shell.prompt() + self._line + "\b" * back
        return ""

    def run_command(self, generator) -> str:
        """Drive ``generator`` exactly like the command of an entered line.

        Used by the console to run login dialogs, boot banners and session
        notices through the normal Prompt/Sleep/paging machinery.  The prompt
        is drawn when the generator finishes (unless the shell is closed).
        Only valid while idle; returns the output produced.
        """
        if not self._started:
            self._started = True
            self._state = "idle"
            self._midline = False
        if self._state != "idle" or self._gen is not None:
            raise RuntimeError("TerminalSession.run_command: a command is already active")
        self._line = ""
        self._cursor = 0
        self._reset_history_nav()
        self._page_count = 1
        self._gen = generator
        self._send = _MISSING
        self._pump()
        return self._drain()

    def cancel_command(self) -> None:
        """Abandon a waiting command without output (the session is discarded
        or its shell went away).  Must not be called from inside the command."""
        gen = self._gen
        self._gen = None
        self._send = _MISSING
        self._pending = ""
        self._prompt = None
        self._prompt_buf = ""
        self._midline = False
        self._line = ""
        self._cursor = 0
        if self._started:
            self._state = "idle"
        if gen is not None:
            try:
                gen.close()
            except Exception:  # pragma: no cover - defensive
                pass
        self._drain()

    def export_history(self) -> Tuple[List[str], int]:
        """Return ``(history, max_size)`` so a nested session can swap it out."""
        return list(self._history), self._history_max

    def import_history(self, items: List[str], size: int) -> None:
        """Install a history list and size (inverse of :meth:`export_history`)."""
        self._history_max = max(0, int(size))
        history = list(items)
        if self._history_max == 0:
            history = []
        elif len(history) > self._history_max:
            history = history[-self._history_max:]
        self._history = history
        self._reset_history_nav()


# ---------------------------------------------------------------------- #
# Escape-sequence parsing (xterm / VT100 style)
# ---------------------------------------------------------------------- #
_SIMPLE_KEYS = {
    "A": "up",
    "B": "down",
    "C": "right",
    "D": "left",
    "H": "home",
    "F": "end",
}
_TILDE_KEYS = {
    "1": "home",
    "7": "home",
    "3": "delete",
    "4": "end",
    "8": "end",
}


def _parse_escape(buf: str) -> Optional[Tuple[int, Optional[str]]]:
    """Parse an escape sequence at the front of ``buf``.

    Returns ``(consumed, key_name)`` where ``key_name`` is ``None`` for a
    recognised-but-ignored sequence, or ``None`` (the whole return) when ``buf``
    does not yet hold a complete sequence and more input is required.
    """
    if len(buf) < 2:
        return None  # just ESC so far
    intro = buf[1]
    if intro not in ("[", "O"):
        return (2, None)  # ESC + something (e.g. Meta key); ignore
    if len(buf) < 3:
        return None
    final = buf[2]
    if final in _SIMPLE_KEYS:
        return (3, _SIMPLE_KEYS[final])
    if intro == "[" and final.isdigit():
        index = 2
        while index < len(buf) and buf[index].isdigit():
            index += 1
        if index >= len(buf):
            return None  # waiting for the terminator
        if buf[index] == "~":
            return (index + 1, _TILDE_KEYS.get(buf[2:index]))
        return (index + 1, None)  # unrecognised CSI sequence
    return (3, None)  # unrecognised final byte
