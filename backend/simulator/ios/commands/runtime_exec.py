"""Runtime-coupled EXEC commands (Phase 2, A3b).

These commands need more than the node they run on: the persistent console
(nested ``ssh``/``telnet`` sessions), the runtime (``reload``, syslog, startup
configuration replay) and the engine bundle (VTY access policy, source address).
They reach them through ``ctx.shell.console`` (set by
:class:`simulator.console.NodeConsole`), ``ctx.runtime`` and ``ctx.engines``.

Commands: ``ssh [-v N] -l USER TARGET``, ``telnet TARGET [PORT]``, ``reload``,
``copy running-config startup-config``, ``copy startup-config running-config``,
``write [memory]``, ``write erase``, ``erase startup-config|nvram:``,
``clear counters [INTERFACE]``, ``show ssh`` and ``show sessions``.

Incoming ssh/telnet sessions land on distinct VTY lines: the lowest free line
number (across every console's open sessions into the target) among the lines
covered by the target's configured VTY blocks that accept the transport
(``line vty 0 4`` -> vty 0..4).  The session's ``line_name`` is ``"vty N"``;
``line_block`` keeps the configured block (``"vty 0 4"``) for line settings,
while the login policy comes from the services engine's decision.  When every
line is busy the connection is refused (``% Connection refused by remote
host``).
"""

from __future__ import annotations

import ipaddress
from typing import Optional, Set, Tuple

from ...models import InterfaceCounters
from ..parser import EXEC, INVALID, command
from ..protocol import Prompt

_CONFIRM_KEYS = ("", "y", "Y")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _console(ctx):
    return getattr(ctx.shell, "console", None)


def _who(ctx) -> str:
    """Originator text for syslog: ``console``, ``admin on console``
    (``login local``), ``vty1 (10.0.0.3)`` or ``admin on vty1 (10.0.0.3)``."""
    from ..shell import session_origin

    return session_origin(ctx.session)


def _save_running(ctx) -> None:
    """``copy running-config startup-config`` semantics."""
    from .. import render

    node = ctx.node
    node.saved_startup_config = render.render_running_config(node)
    node.config_dirty = False
    node.startup_saved_at = ctx.now()


def _resolve_host(node, text: str) -> Optional[str]:
    try:
        ipaddress.IPv4Address(text)
        return text
    except ValueError:
        pass
    lowered = text.lower()
    for name, address in getattr(node, "ip_hosts", {}).items():
        if name.lower() == lowered:
            return address
    return None


def _unknown_host(node, text: str) -> str:
    if getattr(node, "ip_domain_lookup", True):
        servers = list(getattr(node, "name_servers", []) or [])
        server = servers[0] if servers else "255.255.255.255"
        return f'Translating "{text}"...domain server ({server})\n% Bad IP address or host name'
    return f'Translating "{text}"\n% Bad IP address or host name'


def _transport_permitted(ctx, transport: str) -> bool:
    """Honour ``transport output`` on the line this session runs on."""
    from ..shell import session_line

    line = session_line(ctx.node, ctx.session)
    allowed = getattr(line, "transport_output", None) if line is not None else None
    return allowed is None or transport in allowed


def _source_address(bundle, source_node: str, address: str) -> Optional[str]:
    try:
        return bundle.l3.ping(source_node, address, repeat=1, dry_run=True).source_address
    except Exception:
        return None


def _login_privilege(target, line, username: Optional[str], local: bool) -> int:
    privilege = 1
    if line is not None and line.privilege_level is not None:
        privilege = int(line.privilege_level)
    if local and username is not None and username in target.user_privilege:
        privilege = int(target.user_privilege[username])
    return privilege


def _banner_lines(target, include_motd: bool):
    from ...console import banner_text

    if include_motd:
        motd = banner_text(target.banner_motd)
        if motd:
            yield motd + "\n"


def _exec_banner(target):
    from ...console import banner_text

    text = banner_text(target.banner_exec)
    if text:
        yield text + "\n"


def _vty_lines_in_use(runtime, target_name: str) -> Set[int]:
    """VTY line numbers held by open sessions into ``target_name`` (any console)."""
    from ...console import vty_frames
    from ..shell import vty_number

    used: Set[int] = set()
    for frame in vty_frames(runtime, target_name):
        session = getattr(frame.shell, "session", None)
        number = vty_number(getattr(session, "line_name", None))
        if number is not None:
            used.add(number)
    return used


def _free_vty(ctx, target, transport: str) -> Optional[Tuple[int, str]]:
    """Lowest free VTY line on ``target`` for an incoming ``transport`` session.

    Candidates are the line numbers covered by the configured VTY blocks that
    accept the transport (``line vty 0 4`` -> 0..4; the first block covering a
    number owns it).  Returns ``(number, block_name)``, or ``None`` when every
    line is busy.
    """
    from ..shell import vty_blocks

    candidates = {}
    for name, first, last in vty_blocks(target):
        line = target.lines.get(name)
        if line is None or transport not in (line.transport_input or ()):
            continue
        for number in range(first, last + 1):
            candidates.setdefault(number, name)
    used = _vty_lines_in_use(ctx.runtime, target.name)
    for number in sorted(candidates):
        if number not in used:
            return number, candidates[number]
    return None


def _ssh_version(requested: Optional[int], target) -> Optional[int]:
    """Negotiated SSH protocol major version, or ``None`` when they differ.

    The server accepts both versions (1.99) unless ``ip ssh version 1|2``
    restricts it; the client asks for ``-v N`` or, by default, takes the best
    version the server offers.
    """
    server = getattr(target, "ssh_version", None)
    offered = (server,) if server in (1, 2) else (1, 2)
    if requested is None:
        return max(offered)
    return requested if requested in offered else None


def _open_vty(ctx, target, label, transport, username, local, remote_address, ssh_version=None):
    """Push a VTY shell for ``target`` on the console (nested session).

    The session gets the lowest free VTY line (``line_name="vty N"``).
    Returns ``None`` without a console (nothing to open), ``False`` when every
    VTY line became busy meanwhile, ``True`` once the session is open.
    """
    from ...console import line_length
    from ..shell import Session

    console = _console(ctx)
    if console is None:
        return None
    allocated = _free_vty(ctx, target, transport)
    if allocated is None:
        return False
    number, block = allocated
    line = target.lines.get(block)
    session = Session(
        privilege=_login_privilege(target, line, username, local),
        line_type="vty",
        line_name=f"vty {number}",
        line_block=block,
        terminal_length=line_length(line),
        history_size=int(line.history_size) if line is not None else 10,
        username=username,
        remote_address=remote_address,
    )
    console.open_session(
        target.name,
        session,
        label=label,
        transport=transport,
        remote_address=remote_address,
        username=username,
        ssh_version=ssh_version,
    )
    return True


def _caret_error(ctx, token_index: int) -> str:
    """``^`` under token ``token_index`` of the typed command + invalid input."""
    raw = ctx.raw
    position = 0
    start = 0
    for index, token in enumerate(raw.split()):
        start = raw.find(token, position)
        position = start + len(token)
        if index == token_index:
            break
    prompt = ctx.shell.prompt() if hasattr(ctx.shell, "prompt") else ""
    return " " * (len(prompt) + start) + "^\n" + INVALID


# --------------------------------------------------------------------------- #
# ssh / telnet                                                                #
# --------------------------------------------------------------------------- #
@command(
    "ssh [-v {version:<1-2>}] -l {user:WORD} {target:WORD}",
    modes=(EXEC,),
    privilege=1,
    help={
        "ssh": "Open a secure shell client connection",
        "-v": "Specify SSH Protocol Version",
        "version": "Protocol version",
        "-l": "Log in using this user name",
        "user": "Login name",
        "target": "IP address or hostname of a remote system",
    },
)
def _ssh(ctx):
    node = ctx.node
    username = ctx.args["user"]
    target_text = ctx.args["target"]
    if not _transport_permitted(ctx, "ssh"):
        yield "% ssh connections not permitted from this terminal"
        return
    address = _resolve_host(node, target_text)
    if address is None:
        yield _unknown_host(node, target_text)
        return
    bundle = ctx.engines
    if bundle is None:
        yield "% Connection timed out; remote host not responding"
        return
    decision = bundle.services.vty_access(node.name, address, "ssh", ctx.now())
    if not decision.allowed:
        yield decision.message
        return
    target = bundle.nodes.get(decision.target_node)
    if target is None:  # pragma: no cover - engine/topology mismatch
        yield "% Connection timed out; remote host not responding"
        return
    if _free_vty(ctx, target, "ssh") is None:
        # Every VTY line on the target is in use: the connection is refused.
        yield "% Connection refused by remote host"
        return
    # Protocol version exchange (before authentication): an SSHv1 client
    # cannot talk to an ``ip ssh version 2`` server and vice versa.
    version = _ssh_version(ctx.args.get("version"), target)
    if version is None:
        yield f"[Connection to {target_text} aborted: error status 0]"
        return
    password = ""
    if decision.requires_password:
        password = yield Prompt("Password: ", echo=False)
    accepted = bundle.services.vty_authenticate(
        target, decision.login_mode, username, password or "", line=decision.target_line
    )
    if not accepted:
        yield "% Authentication failed."
        return
    if decision.requires_password:
        yield "Password authentication accepted.\n"
    motd = list(_banner_lines(target, include_motd=True))
    if motd:
        yield "\n"
        yield from motd
    yield from _exec_banner(target)
    opened = _open_vty(
        ctx,
        target,
        label=target_text,
        transport="ssh",
        username=username,
        local=decision.login_mode == "local",
        remote_address=_source_address(bundle, node.name, address),
        ssh_version=version,
    )
    if opened is False:
        yield f"\n[Connection to {target_text} closed by foreign host]"


@command(
    "telnet {target:WORD} [{port:<1-65535>}]",
    modes=(EXEC,),
    privilege=1,
    help={
        "telnet": "Open a telnet connection",
        "target": "IP address or hostname of a remote system",
        "port": "Port number",
    },
)
def _telnet(ctx):
    node = ctx.node
    target_text = ctx.args["target"]
    port = ctx.args.get("port", 23)
    if not _transport_permitted(ctx, "telnet"):
        yield "% telnet connections not permitted from this terminal"
        return
    address = _resolve_host(node, target_text)
    if address is None:
        yield _unknown_host(node, target_text)
        return
    shown = address if port == 23 else f"{address}, {port}"
    yield f"Trying {shown} ... "
    bundle = ctx.engines
    if bundle is None:
        yield "\n% Connection timed out; remote host not responding"
        return
    decision = bundle.services.vty_access(node.name, address, "telnet", ctx.now())
    if port != 23 and decision.code != "timeout":
        yield "\n% Connection refused by remote host"
        return
    if decision.allowed or decision.code == "no_password":
        # The TCP connection needs a free VTY line on the target.
        listener = bundle.nodes.get(decision.target_node)
        if listener is not None and _free_vty(ctx, listener, "telnet") is None:
            yield "\n% Connection refused by remote host"
            return
    if not decision.allowed:
        if decision.code == "no_password":
            yield "Open\n\n" + decision.message + "\n\n"
            yield f"[Connection to {target_text} closed by foreign host]"
            return
        yield "\n" + decision.message
        return
    target = bundle.nodes.get(decision.target_node)
    if target is None:  # pragma: no cover - engine/topology mismatch
        yield "\n% Connection timed out; remote host not responding"
        return
    yield "Open\n\n"
    yield from _banner_lines(target, include_motd=True)
    username = None
    services = bundle.services
    if decision.login_mode in ("line", "local"):
        yield "\nUser Access Verification\n\n"
        authenticated = False
        for _attempt in range(3):
            if decision.login_mode == "local":
                user = yield Prompt("Username: ")
                password = yield Prompt("Password: ", echo=False)
                if services.vty_authenticate(
                    target, "local", user or "", password or "", line=decision.target_line
                ):
                    username = user or ""
                    authenticated = True
                    break
                yield "\n% Login invalid\n\n"
            else:
                password = yield Prompt("Password: ", echo=False)
                if services.vty_authenticate(
                    target, "line", None, password or "", line=decision.target_line
                ):
                    authenticated = True
                    break
        if not authenticated:
            if decision.login_mode == "line":
                yield "% Bad passwords\n"
            yield f"\n[Connection to {target_text} closed by foreign host]"
            return
    yield from _exec_banner(target)
    opened = _open_vty(
        ctx,
        target,
        label=target_text,
        transport="telnet",
        username=username,
        local=decision.login_mode == "local",
        remote_address=_source_address(bundle, node.name, address),
    )
    if opened is False:
        yield f"\n[Connection to {target_text} closed by foreign host]"


@command(
    "show ssh",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ssh": "Status of SSH server connections",
    },
)
def _show_ssh(ctx):
    from ...console import vty_frames
    from ..shell import vty_number

    node = ctx.node
    frames = [frame for frame in vty_frames(ctx.runtime, node.name) if frame.transport == "ssh"]

    def connection(frame) -> int:
        # IOS numbers SSH server connections by the VTY line they occupy.
        number = vty_number(getattr(getattr(frame.shell, "session", None), "line_name", None))
        return number if number is not None else 0

    def version(frame) -> int:
        if frame.ssh_version in (1, 2):
            return frame.ssh_version
        return 1 if node.ssh_version == 1 else 2

    frames.sort(key=connection)
    rows = []
    v2 = [frame for frame in frames if version(frame) == 2]
    if v2:
        rows.append(
            "Connection Version Mode Encryption  Hmac         State                 Username"
        )
        for frame in v2:
            for mode in ("IN", "OUT"):
                rows.append(
                    f"{connection(frame):<10} {'2.0':<7} {mode:<4} {'aes128-ctr':<11} "
                    f"{'hmac-sha1':<12} {'Session started':<21} {frame.username or ''}".rstrip()
                )
    else:
        rows.append("%No SSHv2 server connections running.")
    v1 = [frame for frame in frames if version(frame) == 1]
    if v1:
        rows.append("Connection Version Encryption       State                 Username")
        for frame in v1:
            rows.append(
                f"{connection(frame):<10} {'1.5':<7} {'3DES':<16} "
                f"{'Session started':<21} {frame.username or ''}".rstrip()
            )
    else:
        rows.append("%No SSHv1 server connections running.")
    return "\n".join(rows)


@command(
    "show sessions",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "sessions": "Information about Telnet connections",
    },
)
def _show_sessions(ctx):
    """Outgoing connections opened from this terminal session.

    The shell that runs a command is always the top of its console stack, so
    in practice it has no open connection of its own: the sessions the user is
    inside of were opened by the shells below it, and suspending a connection
    (Ctrl-Shift-6 x) is not modelled.  Hence ``% No connections open``.
    """
    from ...console import outgoing_frame

    console = _console(ctx)
    frame = console.frame_of(ctx.shell) if console is not None else None
    child = outgoing_frame(ctx.runtime, frame) if frame is not None else None
    if child is None:
        return "% No connections open"
    address = _resolve_host(ctx.node, child.label) or child.label
    return "\n".join(
        [
            "Conn Host                Address             Byte  Idle Conn Name",
            f"*{1:>3} {child.label:<19} {address:<19} {0:>4} {0:>5} {child.label}",
        ]
    )


# --------------------------------------------------------------------------- #
# reload                                                                      #
# --------------------------------------------------------------------------- #
@command(
    "reload",
    modes=(EXEC,),
    privilege=15,
    help={"reload": "Halt and perform a cold restart"},
)
def _reload(ctx):
    node = ctx.node
    runtime = ctx.runtime
    if node.config_dirty:
        while True:
            answer = yield Prompt("System configuration has been modified. Save? [yes/no]: ")
            reply = (answer or "").strip().lower()
            if reply in ("yes", "y"):
                _save_running(ctx)
                yield "Building configuration...\n[OK]\n"
                break
            if reply in ("no", "n"):
                break
            yield "% Please answer 'yes' or 'no'.\n"
    key = yield Prompt("Proceed with reload? [confirm]", single_key=True)
    if key not in _CONFIRM_KEYS:
        return
    if runtime is None or not hasattr(runtime, "request_reload"):
        yield "% Reload is not available on this terminal"
        return
    ctx.emit_log(
        f"%SYS-5-RELOAD: Reload requested by {_who(ctx)}. Reload Reason: Reload Command."
    )
    runtime.request_reload(node.name)
    if getattr(ctx.session, "is_vty", False):
        # The remote end goes away: the client console sees the session close.
        ctx.shell.close()


# --------------------------------------------------------------------------- #
# copy / write / erase                                                        #
# --------------------------------------------------------------------------- #
_COPY_HELP = {
    "copy": "Copy from one file to another",
    "running-config": "Copy from current system configuration",
    "startup-config": "Copy from startup configuration",
}


@command(
    "copy running-config startup-config",
    modes=(EXEC,),
    privilege=15,
    help=_COPY_HELP,
)
def _copy_run_start(ctx):
    yield Prompt("Destination filename [startup-config]? ")
    _save_running(ctx)
    yield "Building configuration...\n[OK]"


@command(
    "copy startup-config running-config",
    modes=(EXEC,),
    privilege=15,
    help=_COPY_HELP,
)
def _copy_start_run(ctx):
    yield Prompt("Destination filename [running-config]? ")
    node = ctx.node
    saved = node.saved_startup_config or ""
    if not saved.strip():
        yield "%Error opening nvram:/startup-config (No such file or directory)"
        return
    runtime = ctx.runtime
    if runtime is not None and hasattr(runtime, "merge_config"):
        runtime.merge_config(node.name, saved)
    size = len(saved.encode("utf-8"))
    yield f"{size} bytes copied in 0.010 secs ({size * 100} bytes/sec)"
    ctx.emit_log(f"%SYS-5-CONFIG_I: Configured from memory by {_who(ctx)}")


@command(
    "write [memory]",
    modes=(EXEC,),
    privilege=15,
    help={
        "write": "Write running configuration to memory, network, or terminal",
        "memory": "Write to NV memory",
    },
)
def _write_memory(ctx):
    _save_running(ctx)
    return "Building configuration...\n[OK]"


def _erase_nvram(ctx):
    key = yield Prompt(
        "Erasing the nvram filesystem will remove all configuration files! Continue? [confirm]",
        single_key=True,
    )
    if key not in _CONFIRM_KEYS:
        return
    node = ctx.node
    node.saved_startup_config = ""
    node.startup_saved_at = None
    # The running configuration now differs from the (empty) startup-config.
    node.config_dirty = True
    yield "[OK]\nErase of nvram: complete"
    ctx.emit_log("%SYS-7-NV_BLOCK_INIT: Initialized the geometry of nvram")


@command(
    "write erase",
    modes=(EXEC,),
    privilege=15,
    help={
        "write": "Write running configuration to memory, network, or terminal",
        "erase": "Erase NV memory",
    },
)
def _write_erase(ctx):
    yield from _erase_nvram(ctx)


@command(
    "erase (startup-config|nvram:)",
    modes=(EXEC,),
    privilege=15,
    help={
        "erase": "Erase a filesystem",
        "startup-config": "Erase contents of configuration memory",
        "nvram:": "Filesystem to be erased",
    },
)
def _erase(ctx):
    yield from _erase_nvram(ctx)


# --------------------------------------------------------------------------- #
# clear counters                                                              #
# --------------------------------------------------------------------------- #
@command(
    "clear counters [{intf:INTERFACE}]",
    modes=(EXEC,),
    privilege=15,
    help={
        "clear": "Reset functions",
        "counters": "Clear counters on one or all interfaces",
        "intf": "Interface to clear",
    },
)
def _clear_counters(ctx):
    node = ctx.node
    name = ctx.args.get("intf")
    if name is not None and name not in node.interfaces:
        yield _caret_error(ctx, 2)
        return
    if name is not None:
        question = 'Clear "show interface" counters on this interface [confirm]'
    else:
        question = 'Clear "show interface" counters on all interfaces [confirm]'
    key = yield Prompt(question, single_key=True)
    if key not in _CONFIRM_KEYS:
        return
    now = ctx.now()
    targets = [node.interfaces[name]] if name is not None else list(node.interfaces.values())
    for interface in targets:
        interface.counters = InterfaceCounters(cleared_at=now)
    where = f"interface {name}" if name is not None else "all interfaces"
    ctx.emit_log(f"%CLEAR-5-COUNTERS: Clear counter on {where} by {_who(ctx)}")
