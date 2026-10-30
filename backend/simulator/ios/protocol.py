"""Types shared by the IOS shell (``ios/shell.py``) and terminal (``ios/terminal.py``).

Division of responsibility
--------------------------
The terminal (``TerminalSession``) owns characters in / characters out: echo,
line editing, history, ``?`` and Tab dispatch, ``--More--`` paging, Prompt
input collection and Sleep pacing.  The shell owns command semantics: modes,
prompts, parsing, privilege and execution.  The VPCS shell implements the
same ``ShellProtocol``.

Command execution
-----------------
``ShellProtocol.run(line)`` returns a generator (``CommandRun``) that yields:

* ``str``    output text.  Use ``"\\n"`` newlines; the terminal converts them to
             CRLF.  A command that prints nothing yields nothing.
* ``Sleep``  pause before continuing.  The terminal only waits in real time
             when it runs in realtime mode; tests never sleep.
* ``Prompt`` the terminal prints ``text`` verbatim (no newline added) and
             collects one line of input, without echo when ``echo`` is False,
             or a single keystroke when ``single_key`` is True.  It then
             resumes the generator with ``generator.send(answer)``.  The answer
             excludes the line ending; a bare Enter is ``""``.

Closing the generator (``close()``) aborts the command, e.g. Ctrl-^ during a
ping or quitting at a ``--More--`` prompt.

``?`` handling: the terminal echoes ``?``, prints CRLF, prints
``help_text(buffer)`` (which must end with a newline), then reprints the
prompt followed by ``buffer`` (without the ``?``).

Tab handling: ``complete(buffer)`` returns the new buffer (a unique keyword
prefix completed, followed by a space) or ``None``, in which case the terminal
reprints the prompt and the unchanged buffer on a new line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generator, List, Optional, Union

try:  # Protocol is available on every supported version (3.8+)
    from typing import Protocol
except ImportError:  # pragma: no cover
    Protocol = object  # type: ignore[assignment,misc]


@dataclass(frozen=True)
class Sleep:
    seconds: float


@dataclass(frozen=True)
class Prompt:
    text: str
    echo: bool = True
    single_key: bool = False


Output = Union[str, Sleep, Prompt]
CommandRun = Generator[Output, Optional[str], None]


class TerminalProtocol(Protocol):
    """What a shell may use from the terminal it is attached to."""

    @property
    def history(self) -> List[str]:
        """Commands entered in this session, oldest first (``show history``)."""
        ...

    def set_history_size(self, size: int) -> None:
        """Apply ``terminal history size N`` / ``history size N``."""
        ...


class ShellProtocol(Protocol):
    """What the terminal requires from a shell."""

    #: Set by ``TerminalSession`` when the shell is attached to it.
    terminal: Optional[TerminalProtocol]

    def prompt(self) -> str:
        """Current prompt without trailing space, e.g. ``R1(config-if)#``."""
        ...

    def help_text(self, buffer: str) -> str:
        """Output for ``?`` typed after ``buffer``."""
        ...

    def complete(self, buffer: str) -> Optional[str]:
        """Tab completion of ``buffer``; ``None`` when nothing can be completed."""
        ...

    def run(self, line: str) -> CommandRun:
        """Execute one entered line (already stripped of the line ending)."""
        ...

    def interrupt(self, key: str) -> CommandRun:
        """Handle ``"ctrl-c"`` or ``"ctrl-z"`` pressed at an idle prompt."""
        ...

    @property
    def terminal_length(self) -> int:
        """Lines per page for ``--More--``; 0 disables paging."""
        ...

    @property
    def history_size(self) -> int:
        ...

    @property
    def logging_synchronous(self) -> bool:
        """Reprint prompt and pending input after asynchronous messages."""
        ...

    @property
    def closed(self) -> bool:
        """True once the session has ended (``logout``, ``exit`` from exec)."""
        ...
