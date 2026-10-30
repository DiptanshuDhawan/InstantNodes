"""Non-interactive configuration replay on the real CLI shells (Phase 2, A3).

:func:`apply_authored_config` replaces the legacy ``cli.apply_authored_config``.
It feeds a configuration text through the same :class:`~simulator.ios.shell.IosShell`
(or :class:`~simulator.vpcs.shell.VpcsShell`) that the live console uses, so a lab's
authored startup config, ``runtime.apply_config`` fragments, ``reload`` and
``copy startup-config running-config`` all share one command implementation.

IOS replay follows what a router does when a configuration is pasted:

* every line runs in configuration mode at privilege 15; submodes are entered by
  their commands and left through parent-mode fallback, so indentation is not
  significant;
* ``end`` (and leaving config mode with ``exit``) returns to global
  configuration, so replay continues;
* a command that asks a question (``Prompt``) receives the *next* line(s) of the
  text as its answer, which is how multi-line ``banner motd`` bodies are
  collected;
* nothing is printed and no syslog is emitted.

The return value lists the lines the CLI rejected with a parse error, formatted
``"<node>: <line>: <error>"`` like the legacy function, so callers can keep
raising ``Unsupported ... command(s)`` errors.
"""

from __future__ import annotations

from typing import Iterator, List, Optional, Tuple

from .ios.parser import CONFIG
from .ios.protocol import Prompt, Sleep

__all__ = ["apply_authored_config", "PARSE_ERROR_MARKERS"]

#: Output fragments that mean the CLI rejected a line.
PARSE_ERROR_MARKERS = (
    "% Invalid input detected",
    "% Incomplete command.",
    "% Ambiguous command:",
)

#: Hard cap on Prompt answers one command may consume (defensive).
_MAX_PROMPTS_PER_COMMAND = 10000


def apply_authored_config(runtime, node_name: str, config_text: str) -> List[str]:
    """Apply ``config_text`` to ``runtime.nodes[node_name]``; return rejected lines."""
    node = runtime.nodes[node_name]
    if node.cli_profile == "vpcs":
        return _apply_vpcs(runtime, node, config_text)
    return _apply_ios(runtime, node, config_text)


# --------------------------------------------------------------------------- #
# Shared generator driver                                                     #
# --------------------------------------------------------------------------- #
def _drive(generator, answers: Iterator[str]) -> Tuple[str, Optional[str]]:
    """Run a command generator to completion without a terminal.

    ``answers`` supplies Prompt replies; when it runs dry the command is closed
    (the paste ended mid-question).  Returns ``(output, exception_text)``.
    """
    output: List[str] = []
    if generator is None:
        return "", None
    prompts = 0
    try:
        item = next(generator)
        while True:
            if isinstance(item, Prompt):
                prompts += 1
                answer = next(answers, None)
                if answer is None or prompts > _MAX_PROMPTS_PER_COMMAND:
                    generator.close()
                    break
                item = generator.send(answer)
            elif isinstance(item, Sleep):
                item = next(generator)
            else:
                output.append(item if isinstance(item, str) else str(item))
                item = next(generator)
    except StopIteration:
        pass
    except Exception as exc:  # a handler bug must surface, not vanish
        return "".join(output), f"{type(exc).__name__}: {exc}"
    return "".join(output), None


def _parse_error(text: str) -> Optional[str]:
    if not any(marker in text for marker in PARSE_ERROR_MARKERS):
        return None
    for line in text.splitlines():
        if line.lstrip().startswith("%"):
            return line.strip()
    return text.strip()


def _install_runtime(shell, runtime) -> None:
    shell.runtime = runtime
    provider = getattr(runtime, "engines", None)
    shell.engine_provider = provider if callable(provider) else None


# --------------------------------------------------------------------------- #
# IOS                                                                         #
# --------------------------------------------------------------------------- #
def _apply_ios(runtime, node, config_text: str) -> List[str]:
    from .ios.shell import IosShell, Session

    shell = IosShell(node, Session(privilege=15, terminal_length=0))
    _install_runtime(shell, runtime)
    session = shell.session

    def to_global_config() -> None:
        session.closed = False
        del session.stack[1:]
        shell.push_mode(CONFIG, None)

    to_global_config()
    lines = config_text.splitlines()
    errors: List[str] = []
    index = 0

    def remaining() -> Iterator[str]:
        nonlocal index
        while index < len(lines):
            raw = lines[index]
            index += 1
            yield raw

    while index < len(lines):
        raw = lines[index]
        index += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("!"):
            continue
        if stripped.lower() == "end":
            to_global_config()
            continue
        output, failure = _drive(shell.run(stripped), remaining())
        if failure is not None:
            errors.append(f"{node.name}: {stripped}: % Internal error ({failure})")
        else:
            message = _parse_error(output)
            if message is not None:
                errors.append(f"{node.name}: {stripped}: {message}")
        if session.closed or not session.in_config():
            to_global_config()
    shell.take_config_syslog()  # replay never logs
    return errors


# --------------------------------------------------------------------------- #
# VPCS                                                                        #
# --------------------------------------------------------------------------- #
def _apply_vpcs(runtime, node, config_text: str) -> List[str]:
    from .vpcs.shell import VpcsShell

    shell = VpcsShell(node, runtime=runtime)
    _install_runtime(shell, runtime)
    errors: List[str] = []
    for raw in config_text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        output, failure = _drive(shell.run(stripped), iter(()))
        if failure is not None:
            errors.append(f"{node.name}: {stripped}: % Internal error ({failure})")
        elif output.lstrip().startswith("Bad command"):
            errors.append(f"{node.name}: {stripped}: {output.strip()}")
    return errors
