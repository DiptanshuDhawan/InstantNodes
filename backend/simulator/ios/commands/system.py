"""System, line and file IOS commands (Agent CMD-SYS, Phase 2).

This command module (auto-discovered by :mod:`simulator.ios.commands`) covers the
device-identity / credential / logging / clock family of commands plus the
``line`` sub-configuration and the system ``show`` commands:

* **global config** -- ``enable secret``/``enable password``, ``username``,
  ``service password-encryption``, ``banner motd|login|exec`` (inline and
  multi-line), ``logging buffered|console``, ``service timestamps`` and
  ``no hostname``;
* **line config** (``ctx.target`` is the ``list[LineConfig]`` entered by core's
  ``line`` command) -- ``password``, ``login [local]``, ``exec-timeout``,
  ``transport input|output``, ``logging synchronous``, ``privilege level``,
  ``history size``, ``access-class`` and ``length``;
* **EXEC** -- ``show version``, ``show clock [detail]``, ``clock set``,
  ``show users``, ``show logging``, ``show startup-config``, ``show privilege``,
  ``show terminal``, ``show flash:`` and ``dir``.

Only this file is owned by CMD-SYS.  Live clock state comes from the services
engine via ``ctx.engines.services``; credential encodings come from
:mod:`simulator.crypto`; the running/startup renderer is
:mod:`simulator.ios.render`.  All of those are imported lazily inside handlers
so importing this module can never fail because of a sibling engine.

Credential type digits (``0`` cleartext, ``5`` MD5, ``7`` Vigenere, ``8``/``9``)
are parsed from the value text inside the handler rather than as a separate
optional parameter: an optional ``{t}`` placed *before* a trailing ``{LINE}`` is
unreachable in the matcher (the ``LINE`` edge always validates first), and real
IOS interprets a leading lone type digit the same way.
"""

from __future__ import annotations

import re

from ..parser import CONFIG, CONFIG_LINE, EXEC, command
from ..protocol import Prompt

# Full month names indexed 1..12 (the parser hands us a month *number*; the
# services clock API wants a name it can resolve).
_MONTH_NAMES = [
    "",
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]

# Credential type digits accepted per command family.
_SECRET_TYPES = frozenset({0, 5, 8, 9})     # enable/username "secret"
_PASSWORD_TYPES = frozenset({0, 7})          # enable/username/line "password"
_USER_SECRET_TYPES = frozenset({0, 5, 7, 8, 9})


# --------------------------------------------------------------------------- #
# Small helpers                                                               #
# --------------------------------------------------------------------------- #
def _split_type(value, valid):
    """Split a leading ``<digit> `` type marker off ``value``.

    Returns ``(type_int_or_None, remainder)``.  Only a lone digit that is a
    member of ``valid`` and is followed by whitespace counts as a type marker;
    everything else is treated as a cleartext value (matching IOS).
    """
    text = value if value is not None else ""
    match = re.match(r"^([0-9])\s+(.*)$", text)
    if match and int(match.group(1)) in valid:
        return int(match.group(1)), match.group(2)
    return None, text


def _each_line(ctx):
    """Return the ``LineConfig`` objects the current ``line`` submode targets."""
    target = ctx.target
    if isinstance(target, list):
        return [line for line in target if line is not None]
    if target is None:
        return []
    return [target]


def _services(ctx):
    """Return a services engine, preferring the live bundle on ``ctx``."""
    engines = ctx.engines
    services = getattr(engines, "services", None) if engines is not None else None
    if services is not None:
        return services
    # Fallback for unit tests that did not wire an engine provider: a single-node
    # engine is sufficient for clock formatting (NTP peers would be missing).
    from ... import adapters
    from ...services import ServicesEngine

    node = ctx.node
    nodes = {node.name: node}
    callbacks = adapters.legacy_callbacks(nodes, [])
    return ServicesEngine(nodes, [], callbacks, ctx.now())


def _mark(ctx):
    ctx.mark_dirty()


# --------------------------------------------------------------------------- #
# Global config: enable secret / password                                     #
# --------------------------------------------------------------------------- #
@command(
    "enable secret {secret:LINE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "enable": "Modify enable password parameters",
        "secret": "Assign the privileged level secret",
        "secret_value": "The UNENCRYPTED (cleartext) 'enable' secret",
    },
)
def _enable_secret(ctx):
    node = ctx.node
    kind, rest = _split_type(ctx.args["secret"], _SECRET_TYPES)
    if kind is None or kind == 0:
        node.enable_secret = rest
        node.enable_secret_hash = None
    else:
        node.enable_secret = None
        node.enable_secret_hash = "{} {}".format(kind, rest)
    _mark(ctx)
    return None


@command(
    "no enable secret",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "enable": "Modify enable password parameters",
        "secret": "Assign the privileged level secret",
    },
)
def _no_enable_secret(ctx):
    ctx.node.enable_secret = None
    ctx.node.enable_secret_hash = None
    _mark(ctx)
    return None


@command(
    "enable password {pw:LINE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "enable": "Modify enable password parameters",
        "password": "Assign the privileged level password",
        "pw": "The UNENCRYPTED (cleartext) 'enable' password",
    },
)
def _enable_password(ctx):
    node = ctx.node
    kind, rest = _split_type(ctx.args["pw"], _PASSWORD_TYPES)
    if kind == 7:
        from ... import crypto

        decoded = crypto.type7_decode(rest)
        node.enable_password = decoded if decoded is not None else rest
    else:
        node.enable_password = rest
    _mark(ctx)
    return None


@command(
    "no enable password",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "enable": "Modify enable password parameters",
        "password": "Assign the privileged level password",
    },
)
def _no_enable_password(ctx):
    ctx.node.enable_password = None
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Global config: local users                                                  #
# --------------------------------------------------------------------------- #
@command(
    "username {u:WORD} [privilege {p:<0-15>}] (secret|password) {v:LINE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "username": "Establish User Name Authentication",
        "u": "User name",
        "privilege": "Set user privilege level",
        "p": "User privilege level",
        "secret": "Specify the secret for the user",
        "password": "Specify the password for the user",
        "v": "The user password / secret",
    },
)
def _username(ctx):
    node = ctx.node
    name = ctx.args["u"]
    privilege = ctx.args.get("p")
    is_secret = "secret" in ctx.path
    valid = _USER_SECRET_TYPES if is_secret else _PASSWORD_TYPES
    kind, rest = _split_type(ctx.args["v"], valid)
    if is_secret:
        if kind is None or kind == 0:
            node.set_user(name, rest, kind="secret", privilege=privilege)
        else:
            node.set_user(
                name, None, kind="secret", privilege=privilege,
                encoded="{} {}".format(kind, rest),
            )
    else:
        if kind == 7:
            from ... import crypto

            decoded = crypto.type7_decode(rest)
            rest = decoded if decoded is not None else rest
        node.set_user(name, rest, kind="password", privilege=privilege)
    _mark(ctx)
    return None


@command(
    "no username {u:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "username": "Establish User Name Authentication",
        "u": "User name",
    },
)
def _no_username(ctx):
    ctx.node.remove_user(ctx.args["u"])
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Global config: service password-encryption                                  #
# --------------------------------------------------------------------------- #
@command(
    "[no] service password-encryption",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "service": "Modify use of network based services",
        "password-encryption": "Encrypt system passwords",
    },
)
def _service_password_encryption(ctx):
    ctx.node.password_encryption = not ctx.negate
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Global config: banners                                                      #
# --------------------------------------------------------------------------- #
_BANNER_KEYWORDS = ("motd", "login", "exec")


def _banner_which(ctx):
    for keyword in ctx.path:
        if keyword in _BANNER_KEYWORDS:
            return keyword
    return "motd"


def _set_banner(node, which, text):
    if which == "login":
        node.banner_login = text
    elif which == "exec":
        node.banner_exec = text
    else:
        node.banner_motd = text


@command(
    "banner (motd|login|exec) {delim:LINE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "banner": "Define a login banner",
        "motd": "Set Message of the Day banner",
        "login": "Set login banner",
        "exec": "Set EXEC process creation banner",
        "delim": "c  LINE  (delimiting character, then the message)",
    },
)
def _banner(ctx):
    which = _banner_which(ctx)
    raw = ctx.args["delim"]
    # The delimiter is one character, but this codebase (renderer, legacy parser
    # and grader) uses the literal two-character sequence ``^C`` for the ETX
    # delimiter, so honour it as a unit; otherwise it is the first character.
    delim = "^C" if raw.startswith("^C") else raw[0]
    remainder = raw[len(delim):]
    closing = remainder.find(delim)
    if closing != -1:
        # Inline form; inner spacing is preserved verbatim (IOS behaviour) so it
        # round-trips through ios.render's ``banner <kind> ^C<text>^C``.
        _set_banner(ctx.node, which, remainder[:closing])
        _mark(ctx)
        return
    # Multi-line: collect until the delimiter recurs.
    segments = [remainder] if remainder else []
    answer = yield Prompt(
        "Enter TEXT message.  End with the character '{}'.\n".format(delim)
    )
    while True:
        if answer is None:
            answer = ""
        pos = answer.find(delim)
        if pos != -1:
            segments.append(answer[:pos])
            break
        segments.append(answer)
        answer = yield Prompt("")
    _set_banner(ctx.node, which, "\n".join(segments))
    _mark(ctx)
    return


@command(
    "no banner (motd|login|exec)",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "banner": "Define a login banner",
        "motd": "Set Message of the Day banner",
        "login": "Set login banner",
        "exec": "Set EXEC process creation banner",
    },
)
def _no_banner(ctx):
    _set_banner(ctx.node, _banner_which(ctx), None)
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Global config: logging                                                      #
# --------------------------------------------------------------------------- #
@command(
    "[no] logging buffered [{size:<4096-2147483647>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "logging": "Modify message logging facilities",
        "buffered": "Set buffered logging parameters",
        "size": "Logging buffer size",
    },
)
def _logging_buffered(ctx):
    if ctx.negate:
        ctx.node.logging_buffered = None
    else:
        ctx.node.logging_buffered = ctx.args.get("size", 4096)
    _mark(ctx)
    return None


@command(
    "[no] logging console [{level:WORD}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "logging": "Modify message logging facilities",
        "console": "Set console logging parameters",
        "level": "Logging severity level",
    },
)
def _logging_console(ctx):
    ctx.node.logging_console = not ctx.negate
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Global config: service timestamps                                           #
# --------------------------------------------------------------------------- #
#: ``datetime`` options in the order IOS writes them to the running-config.
_TS_OPTIONS = ("msec", "localtime", "show-timezone", "year")


def _any_order(options):
    """Pattern DSL for any subset of ``options`` typed in any order, each once."""
    branches = []
    for option in options:
        rest = _any_order(tuple(other for other in options if other != option))
        branches.append(f"{option} [{rest}]" if rest else option)
    return "(" + "|".join(branches) + ")" if branches else ""


_TS_FORMAT = f"(uptime|datetime [{_any_order(_TS_OPTIONS)}])"
_TS_HELP = {
    "service": "Modify use of network based services",
    "timestamps": "Timestamp debug/log messages",
    "debug": "Timestamp debug messages",
    "log": "Timestamp log messages",
    "datetime": "Timestamp with date and time",
    "uptime": "Timestamp with system uptime",
    "msec": "Include milliseconds in timestamp",
    "localtime": "Use local time zone for timestamps",
    "show-timezone": "Add time zone information to timestamp",
    "year": "Include year in timestamp",
}


def _timestamp_format(path) -> str:
    words = [str(word).lower() for word in path]
    if "datetime" not in words:
        return "uptime"  # IOS: a missing format means uptime
    return " ".join(["datetime"] + [option for option in _TS_OPTIONS if option in words])


@command(
    f"service timestamps [(debug|log) [{_TS_FORMAT}]]",
    modes=(CONFIG,),
    privilege=15,
    help=_TS_HELP,
)
def _service_timestamps(ctx):
    # ``service timestamps`` alone is ``service timestamps debug uptime``.
    kind = "log" if "log" in ctx.path else "debug"
    setattr(ctx.node, f"service_timestamps_{kind}", True)
    setattr(ctx.node, f"service_timestamps_{kind}_format", _timestamp_format(ctx.path))
    _mark(ctx)
    return None


@command(
    f"no service timestamps [(debug|log) [{_TS_FORMAT}]]",
    modes=(CONFIG,),
    privilege=15,
    help={"no": "Negate a command or set its defaults", **_TS_HELP},
)
def _no_service_timestamps(ctx):
    kinds = [kind for kind in ("debug", "log") if kind in ctx.path] or ["debug", "log"]
    for kind in kinds:
        setattr(ctx.node, f"service_timestamps_{kind}", False)
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Global config: no hostname (core owns positive ``hostname``)                #
# --------------------------------------------------------------------------- #
@command(
    "no hostname",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "hostname": "Set system's network name",
    },
)
def _no_hostname(ctx):
    ctx.node.hostname = "Switch" if ctx.node.kind == "switch" else "Router"
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# Line config (ctx.target == list[LineConfig])                                #
# --------------------------------------------------------------------------- #
@command(
    "password {pw:LINE}",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "password": "Set a password",
        "pw": "The UNENCRYPTED (cleartext) line password",
    },
)
def _line_password(ctx):
    kind, rest = _split_type(ctx.args["pw"], _PASSWORD_TYPES)
    if kind == 7:
        from ... import crypto

        decoded = crypto.type7_decode(rest)
        rest = decoded if decoded is not None else rest
    for line in _each_line(ctx):
        line.password = rest
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no password",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "password": "Set a password",
    },
)
def _no_line_password(ctx):
    for line in _each_line(ctx):
        line.password = None
    _mark(ctx)
    return None


@command(
    "[no] login [local]",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "login": "Enable password checking",
        "local": "Local password checking",
    },
)
def _line_login(ctx):
    local = "local" in ctx.path
    for line in _each_line(ctx):
        if ctx.negate:
            line.login = False
            line.login_local = False
        elif local:
            line.login_local = True
            line.login = False
        else:
            line.login = True
            line.login_local = False
        line.configured = True
    _mark(ctx)
    return None


@command(
    "exec-timeout {m:<0-35791>} [{s:<0-2147483>}]",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "exec-timeout": "Set the EXEC timeout",
        "m": "Timeout in minutes",
        "s": "Timeout in seconds",
    },
)
def _exec_timeout(ctx):
    minutes = ctx.args["m"]
    seconds = ctx.args.get("s", 0)
    for line in _each_line(ctx):
        line.exec_timeout = (minutes, seconds)
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no exec-timeout",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "exec-timeout": "Set the EXEC timeout",
    },
)
def _no_exec_timeout(ctx):
    for line in _each_line(ctx):
        line.exec_timeout = (0, 0)
    _mark(ctx)
    return None


def _transport_set(ctx):
    methods = [keyword for keyword in ctx.path if keyword in ("all", "none", "ssh", "telnet")]
    if "none" in methods:
        return set()
    if "all" in methods:
        return {"ssh", "telnet"}
    return set(methods)


@command(
    "transport input (all|none|ssh|telnet) [(ssh|telnet)]",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "transport": "Define transport protocols for the line",
        "input": "Define which protocols to use when connecting to the terminal server",
        "all": "All protocols",
        "none": "No protocols",
        "ssh": "TCP/IP SSH protocol",
        "telnet": "TCP/IP Telnet protocol",
    },
)
def _transport_input(ctx):
    allowed = _transport_set(ctx)
    for line in _each_line(ctx):
        line.transport_input = set(allowed)
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no transport input",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "transport": "Define transport protocols for the line",
        "input": "Define which protocols to use when connecting to the terminal server",
    },
)
def _no_transport_input(ctx):
    for line in _each_line(ctx):
        line.transport_input = set()
    _mark(ctx)
    return None


@command(
    "transport output (all|none|ssh|telnet) [(ssh|telnet)]",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "transport": "Define transport protocols for the line",
        "output": "Define which protocols to use for outgoing connections",
        "all": "All protocols",
        "none": "No protocols",
        "ssh": "TCP/IP SSH protocol",
        "telnet": "TCP/IP Telnet protocol",
    },
)
def _transport_output(ctx):
    allowed = _transport_set(ctx)
    for line in _each_line(ctx):
        line.transport_output = set(allowed)
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no transport output",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "transport": "Define transport protocols for the line",
        "output": "Define which protocols to use for outgoing connections",
    },
)
def _no_transport_output(ctx):
    for line in _each_line(ctx):
        line.transport_output = None
    _mark(ctx)
    return None


@command(
    "[no] logging synchronous",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "logging": "Modify message logging facilities",
        "synchronous": "Synchronize logging output with solicited output",
    },
)
def _line_logging_synchronous(ctx):
    for line in _each_line(ctx):
        line.logging_synchronous = not ctx.negate
        line.configured = True
    _mark(ctx)
    return None


@command(
    "privilege level {n:<0-15>}",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "privilege": "Change privilege level for line",
        "level": "Establish a privilege level",
        "n": "Privilege level",
    },
)
def _line_privilege(ctx):
    for line in _each_line(ctx):
        line.privilege_level = ctx.args["n"]
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no privilege level",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "privilege": "Change privilege level for line",
        "level": "Establish a privilege level",
    },
)
def _no_line_privilege(ctx):
    for line in _each_line(ctx):
        line.privilege_level = None
    _mark(ctx)
    return None


@command(
    "history size {n:<0-256>}",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "history": "Enable and control the command history function",
        "size": "Set history buffer size",
        "n": "Size of history buffer",
    },
)
def _line_history_size(ctx):
    for line in _each_line(ctx):
        line.history_size = ctx.args["n"]
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no history size",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "history": "Enable and control the command history function",
        "size": "Set history buffer size",
    },
)
def _no_line_history_size(ctx):
    for line in _each_line(ctx):
        line.history_size = 10
    _mark(ctx)
    return None


@command(
    "access-class {name:WORD} (in|out)",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "access-class": "Filter connections based on an IP access list",
        "name": "Access list name/number",
        "in": "Filter incoming connections",
        "out": "Filter outgoing connections",
    },
)
def _line_access_class(ctx):
    name = ctx.args["name"]
    outgoing = "out" in ctx.path
    for line in _each_line(ctx):
        if outgoing:
            # LineConfig models only the inbound access-class; keep the outbound
            # one module-locally so it round-trips within a session.
            setattr(line, "_sys_access_class_out", name)
        else:
            line.access_class_in = name
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no access-class [{name:WORD}] (in|out)",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "access-class": "Filter connections based on an IP access list",
        "name": "Access list name/number",
        "in": "Filter incoming connections",
        "out": "Filter outgoing connections",
    },
)
def _no_line_access_class(ctx):
    outgoing = "out" in ctx.path
    for line in _each_line(ctx):
        if outgoing:
            setattr(line, "_sys_access_class_out", None)
        else:
            line.access_class_in = None
    _mark(ctx)
    return None


@command(
    "length {n:<0-512>}",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "length": "Set number of lines on a screen",
        "n": "Number of lines on screen (0 for no pausing)",
    },
)
def _line_length(ctx):
    for line in _each_line(ctx):
        line.length = ctx.args["n"]
        line.configured = True
    _mark(ctx)
    return None


@command(
    "no length",
    modes=(CONFIG_LINE,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "length": "Set number of lines on a screen",
    },
)
def _no_line_length(ctx):
    for line in _each_line(ctx):
        line.length = None
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# EXEC: show version                                                          #
# --------------------------------------------------------------------------- #
def _is_switch(node):
    return node.kind == "switch"


def _ethernet_count(node):
    from ...models import canonical_interface, is_physical_interface

    total = 0
    for name in node.interfaces:
        canonical = canonical_interface(name)
        if is_physical_interface(name) and canonical.startswith(
            ("Ethernet", "FastEthernet", "GigabitEthernet")
        ):
            total += 1
    return total


def _show_version_text(node, now):
    from ...services import ServicesEngine

    switch = _is_switch(node)
    uptime = ServicesEngine.uptime_text(max(0.0, now - (node.boot_time or 0.0)))
    if switch:
        image = "I86BI_LINUX_L2-ADVENTERPRISEK9-M"
        version = "15.2(20170321:233949)"
        release = "RELEASE SOFTWARE (fc1)"
        copyright_year = "1986-2017"
        compiled = "Compiled Tue 21-Mar-17 13:52 by prod_rel_team"
        platform = "Linux Software"
        model = "cisco IOSv_L2 (Intel-x86) processor"
        image_file = "flash:/vios_l2-adventerprisek9-m"
    else:
        image = "I86BI_LINUX-ADVENTERPRISEK9-M"
        version = "15.7(3)M3"
        release = "RELEASE SOFTWARE (fc2)"
        copyright_year = "1986-2018"
        compiled = "Compiled Wed 01-Aug-18 16:46 by prod_rel_team"
        platform = "Linux Software"
        model = "cisco IOSv (revision 1.0) with 460137K/62464K bytes of memory"
        image_file = "flash:/vios-adventerprisek9-m"

    eth = _ethernet_count(node)
    lines = [
        "Cisco IOS Software, {} ({}), Version {}, {}".format(
            platform, image, version, release
        ),
        "Technical Support: http://www.cisco.com/techsupport",
        "Copyright (c) {} by Cisco Systems, Inc.".format(copyright_year),
        compiled,
        "",
        "ROM: Bootstrap program is Linux",
        "",
        "{} uptime is {}".format(node.hostname, uptime),
        'System returned to ROM by reload',
        'System image file is "{}"'.format(image_file),
        "Last reload reason: Unknown reason",
        "",
        model,
        "Processor board ID {}".format(_board_id(node)),
        "{} Ethernet interfaces".format(eth),
        "1024K bytes of NVRAM.",
        "",
        "Configuration register is {}".format(node.config_register or "0x2102"),
        "",
    ]
    return "\n".join(lines)


def _board_id(node):
    index = getattr(node, "node_index", 0) or 0
    return "9{:08d}".format(index)


@command(
    "show version",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "version": "System hardware and software status",
    },
)
def _show_version(ctx):
    return _show_version_text(ctx.node, ctx.now())


# --------------------------------------------------------------------------- #
# EXEC: clock                                                                 #
# --------------------------------------------------------------------------- #
@command(
    "show clock [detail]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "clock": "Display the system clock",
        "detail": "Display detailed information",
    },
)
def _show_clock(ctx):
    detail = "detail" in ctx.path
    return _services(ctx).format_clock(ctx.node, now=ctx.now(), detail=detail)


@command(
    "clock set {t:HH:MM:SS} {day:<1-31>} {month:MONTH} {year:<1993-2035>}",
    modes=(EXEC,),
    privilege=15,
    help={
        "clock": "Manage the system clock",
        "set": "Set the time and date",
        "t": "Current Time",
        "day": "Day of the month",
        "month": "Month of the year",
        "year": "Year",
    },
)
def _clock_set(ctx):
    hour, minute, second = ctx.args["t"]
    day = ctx.args["day"]
    month = ctx.args["month"]
    year = ctx.args["year"]
    try:
        _services(ctx).set_clock(
            ctx.node, hour, minute, second, day, _MONTH_NAMES[month], year,
            now=ctx.now(),
        )
    except (ValueError, OverflowError):
        return "% Invalid input detected at '^' marker."
    _mark(ctx)
    return None


# --------------------------------------------------------------------------- #
# EXEC: show users                                                            #
# --------------------------------------------------------------------------- #
#: IOL absolute line numbers: CTY 0, AUX 1, then the VTY lines (vty N = 2 + N).
_VTY_TTY_BASE = 2


def _line_tty_number(name, order):
    return order


def _users_row(current, tty, line, user, host, location):
    return "{}{:>3} {:<9} {:<10} {:<20} {:>8} {}".format(
        "*" if current else " ", tty, line, user, host, "00:00:00", location
    ).rstrip()


@command(
    "show users",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "users": "Display information about terminal lines",
    },
)
def _show_users(ctx):
    """Lines with a live session on this node.

    ``con 0`` while somebody is logged in on the node's console (with the
    ``login local`` user, if any), plus one row per open ssh/telnet session
    into the node from any console, each on its own VTY line (``vty N``, peer
    address as Location).  The line running the command is marked ``*``;
    Host(s) is ``idle`` unless the line has an outgoing ssh/telnet session open
    (then the host it is connected to, as IOS shows it).
    """
    from ...console import outgoing_frame, vty_frames
    from ..shell import vty_block_range, vty_number

    node = ctx.node
    session = ctx.session
    runtime = ctx.runtime

    def host_of(frame):
        child = outgoing_frame(runtime, frame)
        return child.label if child is not None and child.label else "idle"

    entries = []  # (tty, line, user, host, location, current)
    console = (getattr(runtime, "consoles", None) or {}).get(node.name)
    root_session = getattr(console, "root_session", None)
    root = root_session() if root_session is not None else None
    if root is not None:
        entries.append(
            (0, "con 0", root.username or "", host_of(console.stack[0]), "", root is session)
        )
    for frame in vty_frames(runtime, node.name):
        frame_session = getattr(frame.shell, "session", None)
        number = vty_number(getattr(frame_session, "line_name", None))
        if number is None:
            continue
        user = frame.username or getattr(frame_session, "username", None) or ""
        entries.append(
            (
                _VTY_TTY_BASE + number,
                "vty {}".format(number),
                user,
                host_of(frame),
                frame.remote_address or "",
                frame_session is session,
            )
        )
    if not any(entry[5] for entry in entries):
        # Not on a runtime console (e.g. a bare shell): list this line only.
        if getattr(session, "is_vty", False):
            number = vty_number(session.line_name)
            if number is None:
                span = vty_block_range(session.line_name)
                number = span[0] if span is not None else 0
            entries.append(
                (
                    _VTY_TTY_BASE + number,
                    "vty {}".format(number),
                    session.username or "",
                    "idle",
                    session.remote_address or "",
                    True,
                )
            )
        else:
            entries.append((0, "con 0", session.username or "", "idle", "", True))
    entries.sort(key=lambda entry: entry[0])
    rows = ["    Line       User       Host(s)              Idle       Location"]
    for tty, line, user, host, location, current in entries:
        rows.append(_users_row(current, tty, line, user, host, location))
    rows.append("")
    rows.append(
        "  Interface    User               Mode         Idle     Peer Address"
    )
    return "\n".join(rows)


def _ordered_lines(node):
    def key(name):
        kind = 0 if name.startswith("con") else 1 if name.startswith("aux") else 2
        numbers = [int(part) for part in name.split() if part.isdigit()]
        return (kind, numbers)

    return sorted(node.lines, key=key)


def _line_display_name(name):
    parts = name.split()
    if not parts:
        return name
    label = {"con": "con", "aux": "aux", "vty": "vty"}.get(parts[0], parts[0])
    number = parts[1] if len(parts) > 1 else "0"
    return "{} {}".format(label, number)


# --------------------------------------------------------------------------- #
# EXEC: show logging                                                          #
# --------------------------------------------------------------------------- #
@command(
    "show logging",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "logging": "Show the contents of logging buffers",
    },
)
def _show_logging(ctx):
    node = ctx.node
    size = node.logging_buffered if node.logging_buffered is not None else 4096
    console = "level debugging" if node.logging_console else "disabled"
    if node.logging_buffered is not None:
        buffered = "level debugging"
    else:
        buffered = "disabled"
    entries = list(getattr(node, "log_buffer", []) or [])
    header = [
        "Syslog logging: enabled (0 messages dropped, 0 messages rate-limited, "
        "0 flushes, 0 overruns, xml disabled, filtering disabled)",
        "",
        "No Active Message Discriminator.",
        "",
        "    Console logging: {}, {} messages logged".format(console, len(entries)),
        "    Monitor logging: level debugging, 0 messages logged",
        "    Buffer logging:  {}, {} messages logged".format(buffered, len(entries)),
        "    Exception Logging: size (4096 bytes)",
        "    Count and timestamp logging messages: disabled",
        "    Persistent logging: disabled",
        "",
        "Log Buffer ({} bytes):".format(size),
    ]
    for entry in entries:
        timestamp = getattr(entry, "timestamp", "")
        message = getattr(entry, "message", "")
        if timestamp:
            header.append("{}: {}".format(timestamp, message))
        else:
            header.append(message)
    return "\n".join(header)


# --------------------------------------------------------------------------- #
# EXEC: show startup-config                                                   #
# --------------------------------------------------------------------------- #
@command(
    "show startup-config",
    modes=(EXEC,),
    privilege=15,
    help={
        "show": "Show running system information",
        "startup-config": "Contents of startup configuration",
    },
)
def _show_startup_config(ctx):
    from .. import render

    return render.render_startup_config(ctx.node)


# --------------------------------------------------------------------------- #
# EXEC: show privilege                                                        #
# --------------------------------------------------------------------------- #
@command(
    "show privilege",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "privilege": "Show current privilege level",
    },
)
def _show_privilege(ctx):
    return "Current privilege level is {}".format(ctx.session.privilege)


# --------------------------------------------------------------------------- #
# EXEC: show terminal                                                         #
# --------------------------------------------------------------------------- #
@command(
    "show terminal",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "terminal": "Display terminal configuration parameters",
    },
)
def _show_terminal(ctx):
    session = ctx.session
    length = session.terminal_length
    width = session.terminal_width
    history = session.history_size
    name = _line_display_name(session.line_name)
    lines = [
        "Line {}, Location: \"\", Type: \"\"".format(name),
        "Length: {} lines, Width: {} columns".format(length, width),
        "Baud rate (TX/RX) is 9600/9600, no parity, 2 stopbits, 8 databits",
        "Status: Ready, Active",
        "Capabilities: none",
        "Modem state: Ready",
        "Editing is enabled.",
        "History is enabled, history size is {}.".format(history),
        "Full user help is disabled",
        "Allowed input transports are {}.".format(
            _transports_text(ctx.node, session)
        ),
    ]
    return "\n".join(lines)


def _transports_text(node, session):
    from ..shell import session_line

    line = session_line(node, session)
    if line is None or not line.transport_input:
        return "none"
    return " ".join(sorted(line.transport_input))


# --------------------------------------------------------------------------- #
# EXEC: show flash: / dir                                                     #
# --------------------------------------------------------------------------- #
def _flash_listing(node):
    switch = _is_switch(node)
    image = (
        "vios_l2-adventerprisek9-m" if switch else "vios-adventerprisek9-m"
    )
    image_size = 92794880 if switch else 147275776
    total = 268435456
    free = total - image_size - 4096
    lines = [
        "Directory of flash:/",
        "",
        "    1  -rw-   {:>10}   Mar 1 1993 00:00:00 +00:00  {}".format(
            image_size, image
        ),
        "",
        "{} bytes total ({} bytes free)".format(total, free),
    ]
    return "\n".join(lines)


@command(
    "show (flash:|flash)",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "flash:": "Display information about flash: file system",
        "flash": "Display information about flash: file system",
    },
)
def _show_flash(ctx):
    return _flash_listing(ctx.node)


@command(
    "dir [{what:WORD}]",
    modes=(EXEC,),
    privilege=1,
    help={
        "dir": "List files on a filesystem",
        "what": "Filesystem or directory to list",
    },
)
def _dir(ctx):
    return _flash_listing(ctx.node)
