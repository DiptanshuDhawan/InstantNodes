"""Core IOS commands (Agent A1): navigation, privilege, terminal, mode entry.

These are real, working commands built on the parser DSL.  They cover session
navigation (``enable``/``disable``/``exit``/``end``/``logout``), ``configure
terminal``, the ``terminal`` line settings, ``show history``, ``show
running-config``, ``do``, and the configuration-mode *entry* commands that push
submodes (``interface``/``interface range``/``line``/``router ospf``/``vlan``/
``ip dhcp pool``) plus ``hostname``.  Per-feature configuration commands are
added by the Phase 2 modules using the same DSL and the submode targets set
here (``ctx.target``).
"""

from __future__ import annotations

from ...models import DHCPPool, OSPFProcess, interface_parent
from ..parser import (
    CONFIG,
    CONFIG_IF,
    CONFIG_IF_RANGE,
    CONFIG_LINE,
    CONFIG_MODES,
    CONFIG_ROUTER,
    CONFIG_SUBIF,
    CONFIG_VLAN,
    DHCP_CONFIG,
    EXEC,
    command,
)
from ..protocol import Prompt


# --------------------------------------------------------------------------- #
# Privilege / navigation                                                      #
# --------------------------------------------------------------------------- #
@command(
    "enable",
    modes=(EXEC,),
    privilege=1,
    help={"enable": "Turn on privileged commands"},
)
def _enable(ctx):
    session = ctx.session
    node = ctx.node
    if session.privilege >= 15:
        return
    if not node.has_enable_password():
        if session.is_vty:
            yield "% No password set"
            return
        ctx.shell.enter_enable()
        return
    answer = yield Prompt("Password: ", echo=False)
    if node.verify_enable(answer or ""):
        ctx.shell.enter_enable()
        return
    yield "% Access denied"


@command(
    "disable",
    modes=(EXEC,),
    privilege=1,
    help={"disable": "Turn off privileged commands"},
)
def _disable(ctx):
    ctx.shell.enter_disable()
    return None


@command(
    "exit",
    modes=(EXEC,) + CONFIG_MODES,
    privilege=1,
    help={"exit": "Exit from the current mode"},
)
def _exit(ctx):
    ctx.shell.do_exit()
    return None


@command(
    "end",
    modes=CONFIG_MODES,
    privilege=1,
    help={"end": "Exit to privileged EXEC mode"},
)
def _end(ctx):
    ctx.shell.end_to_exec()
    return None


@command(
    "logout",
    modes=(EXEC,),
    privilege=1,
    help={"logout": "Exit from the EXEC"},
)
def _logout(ctx):
    ctx.shell.close()
    return None


@command(
    "configure terminal",
    modes=(EXEC,),
    privilege=15,
    help={
        "configure": "Enter configuration mode",
        "terminal": "Configure from the terminal",
    },
)
def _configure_terminal(ctx):
    ctx.push_mode(CONFIG, None)
    return "Enter configuration commands, one per line.  End with CNTL/Z."


# --------------------------------------------------------------------------- #
# Terminal line settings (user EXEC)                                          #
# --------------------------------------------------------------------------- #
@command(
    "terminal length {n:<0-512>}",
    modes=(EXEC,),
    privilege=1,
    help={
        "terminal": "Set terminal line parameters",
        "length": "Set number of lines on a screen",
        "n": "Number of lines on screen (0 for no pausing)",
    },
)
def _terminal_length(ctx):
    ctx.session.terminal_length = ctx.args["n"]
    return None


@command(
    "terminal width {n:<0-512>}",
    modes=(EXEC,),
    privilege=1,
    help={
        "terminal": "Set terminal line parameters",
        "width": "Set width of the display terminal",
        "n": "Number of characters on a screen line",
    },
)
def _terminal_width(ctx):
    ctx.session.terminal_width = ctx.args["n"]
    return None


@command(
    "terminal history size {n:<0-256>}",
    modes=(EXEC,),
    privilege=1,
    help={
        "terminal": "Set terminal line parameters",
        "history": "Enable and control the command history function",
        "size": "Set history buffer size",
        "n": "Size of history buffer",
    },
)
def _terminal_history_size(ctx):
    ctx.shell.set_history_size(ctx.args["n"])
    return None


@command(
    "[no] terminal monitor",
    modes=(EXEC,),
    privilege=1,
    help={
        "no": "Negate a command or set its defaults",
        "terminal": "Set terminal line parameters",
        "monitor": "Copy debug output to the current terminal line",
    },
)
def _terminal_monitor(ctx):
    ctx.session.terminal_monitor = not ctx.negate
    return None


# --------------------------------------------------------------------------- #
# Show                                                                        #
# --------------------------------------------------------------------------- #
@command(
    "show history",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "history": "Display the session command history",
    },
)
def _show_history(ctx):
    terminal = ctx.shell.terminal
    if terminal is None:
        return None
    try:
        items = list(terminal.history)
    except Exception:
        items = []
    if not items:
        return None
    return "\n".join("  " + item for item in items)


@command(
    "show running-config [interface {intf:INTERFACE}]",
    modes=(EXEC,),
    privilege=15,
    help={
        "show": "Show running system information",
        "running-config": "Current operating configuration",
        "interface": "Show interface configuration",
        "intf": "Interface name",
    },
)
def _show_running_config(ctx):
    node = ctx.node
    interface = ctx.args.get("intf")
    try:  # Agent E owns ios/render.py; prefer it when available.
        from .. import render

        if interface is not None:
            return render.render_show_running(node, interface=interface)
        return render.render_show_running(node)
    except Exception:
        body = node.render_running_config()
        size = len(body.encode("utf-8"))
        header = f"Building configuration...\n\nCurrent configuration : {size} bytes\n"
        return header + body.rstrip("\n")


# --------------------------------------------------------------------------- #
# ``do`` (run an exec command from any config mode)                           #
# --------------------------------------------------------------------------- #
@command(
    "do {cmd:LINE}",
    modes=CONFIG_MODES,
    privilege=15,
    help={
        "do": "To run exec commands in config mode",
        "cmd": "Exec command",
    },
)
def _do(ctx):
    rest = ctx.args["cmd"]
    base = ctx.raw.find(rest)
    yield from ctx.shell.run_exec_text(rest, base if base >= 0 else 0)


# --------------------------------------------------------------------------- #
# Configuration-mode entry commands (push a submode + set its target)         #
# --------------------------------------------------------------------------- #
@command(
    "interface {intf:INTERFACE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "interface": "Select an interface to configure",
        "intf": "Interface to configure",
    },
)
def _interface(ctx):
    name = ctx.args["intf"]
    iface = ctx.node.ensure_interface(name)
    mode = CONFIG_SUBIF if interface_parent(name) else CONFIG_IF
    ctx.push_mode(mode, iface)
    ctx.mark_dirty()
    return None


@command(
    "interface range {ranges:INTERFACE_RANGE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "interface": "Select an interface to configure",
        "range": "Select an interface range to configure",
        "ranges": "Interface range (e.g. Ethernet0/0 - 3)",
    },
)
def _interface_range(ctx):
    names = ctx.args["ranges"]
    interfaces = [ctx.node.ensure_interface(name) for name in names]
    ctx.push_mode(CONFIG_IF_RANGE, interfaces)
    ctx.mark_dirty()
    return None


@command(
    "line console {n:<0-0>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "line": "Configure a terminal line",
        "console": "Primary terminal line",
        "n": "First line number",
    },
)
def _line_console(ctx):
    line = ctx.node.line(f"con {ctx.args['n']}")
    ctx.push_mode(CONFIG_LINE, [line])
    return None


@command(
    "line aux {n:<0-0>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "line": "Configure a terminal line",
        "aux": "Auxiliary line",
        "n": "First line number",
    },
)
def _line_aux(ctx):
    line = ctx.node.line(f"aux {ctx.args['n']}")
    ctx.push_mode(CONFIG_LINE, [line])
    return None


@command(
    "line vty {first:<0-15>} [{last:<0-15>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "line": "Configure a terminal line",
        "vty": "Virtual terminal",
        "first": "First line number",
        "last": "Last line number",
    },
)
def _line_vty(ctx):
    first = ctx.args["first"]
    last = ctx.args.get("last", first)
    # IOS applies the submode commands to every line of the range; the model
    # keeps non-overlapping blocks (``line vty 0 15`` -> ``vty 0 4`` + ``vty 5 15``).
    lines = ctx.node.vty_range(int(first), int(last))
    ctx.push_mode(CONFIG_LINE, lines)
    return None


@command(
    "router ospf {pid:<1-65535>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "router": "Enable a routing process",
        "ospf": "Open Shortest Path First (OSPF)",
        "pid": "Process ID",
    },
)
def _router_ospf(ctx):
    pid = ctx.args["pid"]
    process = ctx.node.ospf_processes.setdefault(pid, OSPFProcess(pid))
    ctx.push_mode(CONFIG_ROUTER, process)
    ctx.mark_dirty()
    return None


@command(
    "vlan {ids:VLAN_LIST}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "vlan": "VLAN commands",
        "ids": "ISL VLAN IDs 1-4094",
    },
)
def _vlan(ctx):
    ids = ctx.args["ids"]
    for vlan_id in ids:
        ctx.node.vlans.setdefault(vlan_id, f"VLAN{vlan_id:04d}")
    ctx.push_mode(CONFIG_VLAN, ids)
    ctx.mark_dirty()
    return None


@command(
    "ip dhcp pool {name:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "ip": "Global IP configuration subcommands",
        "dhcp": "Configure DHCP server and relay parameters",
        "pool": "Configure DHCP address pools",
        "name": "Pool name",
    },
)
def _ip_dhcp_pool(ctx):
    requested = ctx.args["name"]
    existing = next(
        (name for name in ctx.node.dhcp_pools if name.lower() == requested.lower()),
        requested,
    )
    pool = ctx.node.dhcp_pools.setdefault(existing, DHCPPool(existing))
    ctx.push_mode(DHCP_CONFIG, pool)
    ctx.mark_dirty()
    return None


@command(
    "hostname {name:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "hostname": "Set system's network name",
        "name": "This system's network name",
    },
)
def _hostname(ctx):
    ctx.node.hostname = ctx.args["name"]
    ctx.mark_dirty()
    return None
