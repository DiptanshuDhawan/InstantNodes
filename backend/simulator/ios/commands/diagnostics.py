"""Diagnostic and clear commands (Agent G1, Phase 3 wave 2).

This module fills the remaining EXEC gaps of the coverage list with commands
whose output is computed from the simulated state:

* ``show vtp status``                        (privilege 1)
* ``show port-security [interface X]``       (privilege 1, switches)
* ``show crypto key mypubkey rsa``           (privilege 15)
* ``show ip default-gateway``                (privilege 1)
* ``show line [console 0 | aux 0 | vty N [M]]`` (privilege 1)
* ``debug ...`` / ``undebug ...`` / ``no debug ...`` (privilege 15) and
  ``show debugging`` (privilege 1).  Debug flags only record what is on; no
  debug output is generated.
* ``clear ip dhcp binding (* | A.B.C.D)``    (privilege 15)
* ``clear mac address-table dynamic [address H.H.H | interface X | vlan N]``
  (privilege 15, switches)
* ``write terminal``                         (privilege 15)

Live state comes from ``ctx.engines`` (L2 fabric for port security, services
for the clock) and ``ctx.node``.  The clear commands mutate dynamic state only
(DHCP bindings, the learned MAC table) and deliberately do NOT call
``ctx.mark_dirty()``: that would flag the configuration as modified and re-run
the simulator's automatic DHCP retry.

Debug flags are kept in a module-local table keyed by
``(id(runtime) or None, node.name)``; an entry is discarded when the node object
changes (``reload`` and the simulator reset build new ``NodeState`` objects), so
debugging does not survive a reload, as on IOS.
"""

from __future__ import annotations

import hashlib
import weakref
from typing import Dict, List, Optional, Set, Tuple

from ...models import canonical_interface, format_mac, natural_key, normalise_mac
from ..parser import EXEC, INVALID, command, tokenize
from ..protocol import Prompt

_SHOW = "Show running system information"


# =========================================================================== #
# Shared helpers                                                              #
# =========================================================================== #
def _engines(ctx):
    try:
        return ctx.engines
    except Exception:  # pragma: no cover - defensive (engine build error)
        return None


def _l2(ctx):
    bundle = _engines(ctx)
    return getattr(bundle, "l2", None) if bundle is not None else None


def _services(ctx):
    bundle = _engines(ctx)
    return getattr(bundle, "services", None) if bundle is not None else None


_SHORT_MAP = (
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("TenGigabitEthernet", "Te"),
    ("Ethernet", "Et"),
    ("Port-channel", "Po"),
    ("Loopback", "Lo"),
    ("Serial", "Se"),
    ("Tunnel", "Tu"),
    ("Vlan", "Vl"),
)


def _short(name: str) -> str:
    """IOS short interface name (``Ethernet0/1`` -> ``Et0/1``)."""
    canonical = canonical_interface(name)
    for prefix, short in _SHORT_MAP:
        if canonical.startswith(prefix):
            return short + canonical[len(prefix):]
    return canonical


def _parse_error(text: str) -> str:
    """Mark ``text`` as a parse error so ``| include ...`` never filters it.

    Uses the shell's ``ParseErrorText`` marker when it exists (imported lazily:
    the shell is always loaded before a handler runs); a plain ``str`` otherwise.
    """
    try:
        from ..shell import ParseErrorText  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - older shell without the marker
        return text
    return ParseErrorText(text)


def _caret(ctx, token_index: int) -> str:
    """``^`` under token ``token_index`` of the typed command + invalid input.

    Used when a command exists in the registry but not on this platform or
    for this argument (IOS rejects it in the parser).  Through ``do`` the
    typed line starts with ``do `` (3 characters) before ``ctx.raw``.
    """
    tokens = tokenize(ctx.raw)
    if token_index < len(tokens):
        start = tokens[token_index].start
    else:
        start = len(ctx.raw)
    try:
        base = len(ctx.shell.prompt())
    except Exception:  # pragma: no cover - shell without a prompt
        base = 0
    try:
        if ctx.session.in_config():
            base += len("do ")
    except Exception:  # pragma: no cover - session without modes
        pass
    return _parse_error(" " * (base + start) + "^\n" + INVALID)


def _is_switch(node) -> bool:
    return getattr(node, "kind", "") == "switch"


# =========================================================================== #
# show vtp status                                                             #
# =========================================================================== #
#: VLANs every IOS VLAN database contains (same set as ``show vlan brief``).
_RESERVED_VLANS = {
    1002: "fddi-default",
    1003: "token-ring-default",
    1004: "fddinet-default",
    1005: "trnet-default",
}


def _vtp_vlan_ids(node) -> List[int]:
    """VLAN ids counted by ``show vlan brief``: configured + reserved 1002-1005."""
    return sorted(set(node.vlans) | set(_RESERVED_VLANS))


def _vtp_digest(node, revision: int) -> List[str]:
    """Deterministic 16-byte digest of the VTP domain and VLAN database."""
    parts = [node.vtp_domain or "", str(revision)]
    for vid in _vtp_vlan_ids(node):
        parts.append(f"{vid}:{node.vlans.get(vid) or _RESERVED_VLANS.get(vid, '')}")
    payload = "\n".join(parts).encode("utf-8")
    try:
        digest = hashlib.md5(payload, usedforsecurity=False).digest()
    except (TypeError, ValueError):  # pragma: no cover - FIPS builds
        digest = hashlib.sha256(payload).digest()[:16]
    return [f"0x{byte:02X}" for byte in digest]


def _vtp_updater(node) -> str:
    """The ``Local updater ID`` line of a VTP server."""
    names = sorted(node.interfaces, key=natural_key)
    for name in names:
        iface = node.interfaces[name]
        if name.startswith("Vlan") and iface.ip_address:
            return (
                f"Local updater ID is {iface.ip_address} on interface {_short(name)} "
                "(lowest numbered VLAN interface found)"
            )
    for name in names:
        iface = node.interfaces[name]
        if name.startswith(("Vlan", "Loopback")) or not iface.ip_address:
            continue
        return (
            f"Local updater ID is {iface.ip_address} on interface {_short(name)} "
            "(first layer3 interface found)"
        )
    return "Local updater ID is 0.0.0.0 (no valid interface found)"


@command(
    "show vtp status",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": _SHOW,
        "vtp": "VTP information",
        "status": "VTP domain status",
    },
)
def _show_vtp_status(ctx):
    node = ctx.node
    mode = (node.vtp_mode or "server").lower()
    version = int(node.vtp_version or 1)
    revision = 0
    lines = [
        f"{'VTP Version capable':<32}: 1 to 3",
        f"{'VTP version running':<32}: {version}",
        f"{'VTP Domain Name':<32}: {node.vtp_domain or ''}",
        f"{'VTP Pruning Mode':<32}: Disabled",
        f"{'VTP Traps Generation':<32}: Disabled",
        f"{'Device ID':<32}: {format_mac(node.base_mac(), 'cisco')}",
        "Configuration last modified by 0.0.0.0 at 0-0-00 00:00:00",
    ]
    if mode == "server":
        lines.append(_vtp_updater(node))
    digest = _vtp_digest(node, revision)
    lines.extend(
        [
            "",
            "Feature VLAN:",
            "--------------",
            f"{'VTP Operating Mode':<34}: {mode.capitalize()}",
            f"{'Maximum VLANs supported locally':<34}: 1005",
            f"{'Number of existing VLANs':<34}: {len(_vtp_vlan_ids(node))}",
            f"{'Configuration Revision':<34}: {revision}",
            f"{'MD5 digest':<34}: " + " ".join(digest[:8]),
            " " * 36 + " ".join(digest[8:]),
        ]
    )
    return "\n".join(lines)


# =========================================================================== #
# show port-security [interface X]                                            #
# =========================================================================== #
_VIOLATION_ACTION = {"shutdown": "Shutdown", "restrict": "Restrict", "protect": "Protect"}

#: ``Max Addresses limit in System (excluding one mac per port)`` on IOL L2.
_SYSTEM_SECURE_LIMIT = 4096


def _port_security_counts(node, iface, info) -> dict:
    """IOS port-security counters for one switchport.

    Secure addresses are the configured ones (``mac-address H.H.H``), the
    sticky ones (``iface.port_security_sticky_macs``) and the dynamic secure
    entries the L2 engine installed in ``node.mac_table`` (``entry.secure``).
    Violations and the last source are counted by the engine as frames arrive
    (``iface.port_security_violation_count`` / ``port_security_last_source``).
    """
    if not iface.port_security_enabled:
        return {
            "enabled": False,
            "status": "Secure-down",
            "total": 0,
            "configured": 0,
            "sticky": 0,
            "violations": 0,
            "last_source": "0000.0000.0000:0",
        }
    canonical = iface.name

    def macs(values) -> List[str]:
        result: List[str] = []
        for value in values:
            try:
                mac = normalise_mac(value)
            except ValueError:
                continue
            if mac not in result:
                result.append(mac)
        return result

    configured = macs(iface.port_security_macs)
    sticky = [mac for mac in macs(iface.port_security_sticky_macs) if mac not in configured]
    dynamic: List[str] = []
    for entry in node.mac_table.values():
        if entry.secure != "dynamic" or canonical_interface(entry.port) != canonical:
            continue
        try:
            mac = normalise_mac(entry.mac)
        except ValueError:
            continue
        if mac not in configured and mac not in sticky and mac not in dynamic:
            dynamic.append(mac)
    status = info.status if info is not None else "Secure-down"
    return {
        "enabled": True,
        "status": status,
        "total": len(configured) + len(sticky) + len(dynamic),
        "configured": len(configured),
        "sticky": len(sticky),
        "violations": int(getattr(iface, "port_security_violation_count", 0) or 0),
        "last_source": getattr(iface, "port_security_last_source", None) or "0000.0000.0000:0",
    }


def _port_security_info(ctx, name: str):
    l2 = _l2(ctx)
    if l2 is None:
        return None
    try:
        return l2.port_security(ctx.node.name, name)
    except Exception:  # pragma: no cover - defensive (engine bug)
        return None


@command(
    "show port-security",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": _SHOW,
        "port-security": "Show secure port information",
    },
)
def _show_port_security(ctx):
    node = ctx.node
    if not _is_switch(node):
        return _caret(ctx, 1)
    rows = [
        "Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action",
        "                (Count)       (Count)          (Count)",
        "-" * 75,
    ]
    extra = 0
    for name in sorted(node.interfaces, key=natural_key):
        iface = node.interfaces[name]
        if not iface.port_security_enabled:
            continue
        info = _port_security_info(ctx, name)
        if info is None:
            continue  # not a switchport (routed port, SVI)
        counts = _port_security_counts(node, iface, info)
        extra += max(0, counts["total"] - 1)
        action = _VIOLATION_ACTION.get(iface.port_security_violation, "Shutdown")
        rows.append(
            f"{_short(name):>11}{iface.port_security_maximum:>15}{counts['total']:>13}"
            f"{counts['violations']:>19}{action:>17}"
        )
    rows.append("-" * 75)
    rows.append(f"Total Addresses in System (excluding one mac per port)     : {extra}")
    rows.append(
        "Max Addresses limit in System (excluding one mac per port) : "
        f"{_SYSTEM_SECURE_LIMIT}"
    )
    return "\n".join(rows)


@command(
    "show port-security interface {intf:INTERFACE}",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": _SHOW,
        "port-security": "Show secure port information",
        "interface": "Show secure interface",
        "intf": "Interface name",
    },
)
def _show_port_security_interface(ctx):
    node = ctx.node
    if not _is_switch(node):
        return _caret(ctx, 1)
    name = ctx.args["intf"]
    iface = node.interfaces.get(name)
    if iface is None:
        return None
    info = _port_security_info(ctx, name)
    if info is None:
        return None  # IOS prints nothing for a port that is not a switchport
    counts = _port_security_counts(node, iface, info)
    action = _VIOLATION_ACTION.get(iface.port_security_violation, "Shutdown")
    fields = [
        ("Port Security", "Enabled" if counts["enabled"] else "Disabled"),
        ("Port Status", counts["status"]),
        ("Violation Mode", action),
        ("Aging Time", "0 mins"),
        ("Aging Type", "Absolute"),
        ("SecureStatic Address Aging", "Disabled"),
        ("Maximum MAC Addresses", str(iface.port_security_maximum)),
        ("Total MAC Addresses", str(counts["total"])),
        ("Configured MAC Addresses", str(counts["configured"])),
        ("Sticky MAC Addresses", str(counts["sticky"])),
        ("Last Source Address:Vlan", counts["last_source"]),
        ("Security Violation Count", str(counts["violations"])),
    ]
    return "\n".join(f"{label:<27}: {value}" for label, value in fields)


# =========================================================================== #
# show crypto key mypubkey rsa                                                #
# =========================================================================== #
_MONTH_ABBR = (
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

#: DER AlgorithmIdentifier for rsaEncryption (OID 1.2.840.113549.1.1.1, NULL).
_RSA_ALGORITHM = bytes.fromhex("300D06092A864886F70D0101010500")


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_integer(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body  # keep the INTEGER positive
    return b"\x02" + _der_length(len(body)) + body


def _der_sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_length(len(body)) + body


def _rsa_modulus(seed: str, bits: int) -> int:
    """A deterministic pseudo-random ``bits``-bit odd modulus (sha256 chain)."""
    bits = max(16, int(bits))
    nbytes = (bits + 7) // 8
    seed_bytes = seed.encode("utf-8")
    block = hashlib.sha256(seed_bytes).digest()
    stream = b""
    while len(stream) < nbytes:
        stream += block
        block = hashlib.sha256(block + seed_bytes).digest()
    value = int.from_bytes(stream[:nbytes], "big")
    value &= (1 << bits) - 1
    # RSA moduli have the two top bits set (p and q are full size) and are odd.
    value |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
    return value


def _subject_public_key_info(modulus: int, exponent: int = 65537) -> bytes:
    """DER SubjectPublicKeyInfo of an RSA public key (what IOS prints)."""
    rsa_public_key = _der_sequence(_der_integer(modulus), _der_integer(exponent))
    bit_string = b"\x03" + _der_length(len(rsa_public_key) + 1) + b"\x00" + rsa_public_key
    return _der_sequence(_RSA_ALGORITHM, bit_string)


def _key_data_lines(der: bytes) -> List[str]:
    """IOS ``Key Data:`` layout: 8-hex-digit groups, 8 groups per line."""
    text = der.hex().upper()
    groups = [text[index:index + 8] for index in range(0, len(text), 8)]
    return ["  " + " ".join(groups[index:index + 8]) for index in range(0, len(groups), 8)]


def _key_timestamp(ctx, epoch: float) -> str:
    """``HH:MM:SS ZONE Mon d yyyy`` of the node clock at ``epoch``."""
    services = _services(ctx)
    if services is not None:
        try:
            clock = services.node_clock(ctx.node, now=epoch)
            local = clock.local
            return (
                f"{local.hour:02d}:{local.minute:02d}:{local.second:02d} {clock.zone_name} "
                f"{_MONTH_ABBR[local.month]} {local.day} {local.year}"
            )
        except Exception:  # pragma: no cover - defensive (engine bug)
            pass
    import time as _time

    moment = _time.gmtime(epoch)
    return (
        f"{moment.tm_hour:02d}:{moment.tm_min:02d}:{moment.tm_sec:02d} UTC "
        f"{_MONTH_ABBR[moment.tm_mon]} {moment.tm_mday} {moment.tm_year}"
    )


@command(
    "show crypto key mypubkey rsa",
    modes=(EXEC,),
    privilege=15,
    help={
        "show": _SHOW,
        "crypto": "Encryption module",
        "key": "Show long term public keys",
        "mypubkey": "Show public keys associated with this router",
        "rsa": "Show RSA public keys",
    },
)
def _show_crypto_key_mypubkey_rsa(ctx):
    node = ctx.node
    bits = node.rsa_bits
    if bits is None:
        return None  # IOS prints nothing when no RSA key pair exists
    generated = node.rsa_generated_at
    if generated is None:
        generated = node.boot_time or ctx.now()
    key_name = node.hostname
    if node.domain_name:
        key_name = f"{node.hostname}.{node.domain_name}"
    der = _subject_public_key_info(_rsa_modulus(f"{node.name}:{int(bits)}", int(bits)))
    lines = [
        f"% Key pair was generated at: {_key_timestamp(ctx, float(generated))}",
        f"Key name: {key_name}",
        "Key type: RSA KEYS",
        " Storage Device: private-config",
        " Usage: General Purpose Key",
        " Key is not exportable. Redundancy enabled.",
        " Key Data:",
    ]
    lines.extend(_key_data_lines(der))
    return "\n".join(lines)


# =========================================================================== #
# show ip default-gateway                                                     #
# =========================================================================== #
@command(
    "show ip default-gateway",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": _SHOW,
        "ip": "IP information",
        "default-gateway": "List default-gateway",
    },
)
def _show_ip_default_gateway(ctx):
    gateway = ctx.node.default_gateway
    if gateway:
        return f"Default gateway is {gateway}"
    return "Default gateway is not set"


# =========================================================================== #
# show line                                                                   #
# =========================================================================== #
_LINE_HEADER = (
    "   Tty Typ     Tx/Rx    A Modem  Roty AccO AccI   Uses   Noise  Overruns   Int"
)
_VTY_BASE = 2  # CTY 0, AUX 1, VTY lines from 2


def _vty_span(name: str) -> Optional[Tuple[int, int]]:
    parts = name.split()
    if not parts or parts[0] != "vty" or len(parts) not in (2, 3):
        return None
    if not all(part.isdigit() for part in parts[1:]):
        return None
    first = int(parts[1])
    last = int(parts[2]) if len(parts) == 3 else first
    return (min(first, last), max(first, last))


def _line_table(node) -> List[Tuple[int, str, int, object]]:
    """``(tty, type, relative number, LineConfig)`` for every line, in tty order.

    VTY numbers are the union of the configured ``line vty`` blocks; when blocks
    overlap, the block created last wins (``line vty 0 15`` after the default
    ``vty 0 4`` applies to all sixteen lines).
    """
    rows: List[Tuple[int, str, int, object]] = [
        (0, "CTY", 0, node.lines.get("con 0")),
        (1, "AUX", 0, node.lines.get("aux 0")),
    ]
    vty: Dict[int, object] = {}
    for name, config in node.lines.items():
        span = _vty_span(name)
        if span is None:
            continue
        for number in range(span[0], span[1] + 1):
            vty[number] = config
    for number in sorted(vty):
        rows.append((_VTY_BASE + number, "VTY", number, vty[number]))
    return rows


def _session_tty(session) -> Optional[int]:
    line_type = getattr(session, "line_type", None)
    if line_type == "console":
        return 0
    if line_type == "aux":
        return 1
    if line_type == "vty":
        parts = (getattr(session, "line_name", "") or "").split()
        if len(parts) >= 2 and parts[1].isdigit():
            return _VTY_BASE + int(parts[1])
        return _VTY_BASE
    return None


def _active_lines(ctx) -> Dict[int, Optional[float]]:
    """tty number -> activation epoch (``None`` = unknown) of lines in use.

    The current session's line is always active.  Other sessions are read from
    the runtime's persistent consoles (read-only, best effort): an active root
    console on this node is the CTY, nested ssh/telnet frames into this node
    are VTY lines.
    """
    node = ctx.node
    active: Dict[int, Optional[float]] = {}
    current = _session_tty(ctx.session)
    if current is not None:
        active[current] = None
    consoles = getattr(ctx.runtime, "consoles", None)
    if not isinstance(consoles, dict):
        return active
    try:
        for console in list(consoles.values()):
            if getattr(console, "state", "active") != "active":
                continue
            for index, frame in enumerate(list(getattr(console, "stack", []) or [])):
                shell = getattr(frame, "shell", None)
                if getattr(shell, "node", None) is not node:
                    continue
                tty = _session_tty(getattr(shell, "session", None))
                if tty is None:
                    continue
                opened = getattr(frame, "opened_at", 0.0) or 0.0
                since = float(opened) if index > 0 and opened else float(node.boot_time or 0.0)
                if active.get(tty) is None:
                    active[tty] = since
    except Exception:  # pragma: no cover - console internals changed
        pass
    return active


def _line_row(tty: int, kind: str, active: bool) -> str:
    txrx = "9600/9600" if kind == "AUX" else ""
    return (
        f"{'*' if active else ' '}{tty:>6} {kind}{txrx:>12}  -{'-':>5}{'-':>7}"
        f"{'-':>5}{'-':>5}{0:>7}{0:>8}{'0/0':>8}{'-':>8}"
    )


def _hms(seconds: float) -> str:
    total = int(max(0.0, seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


_TRANSPORT_ORDER = ("telnet", "ssh")


def _transports(values) -> str:
    if not values:
        return "none"
    known = [name for name in _TRANSPORT_ORDER if name in values]
    known += sorted(name for name in values if name not in _TRANSPORT_ORDER)
    return " ".join(known)


def _line_detail(tty: int, kind: str, config, since: Optional[float], active: bool, now: float) -> List[str]:
    length = 24
    if config is not None and getattr(config, "length", None) is not None:
        length = int(config.length)
    timeout = getattr(config, "exec_timeout", None) if config is not None else None
    if timeout is None:
        idle_exec = "00:10:00"
    elif int(timeout[0]) == 0 and int(timeout[1]) == 0:
        idle_exec = "never"
    else:
        idle_exec = _hms(int(timeout[0]) * 60 + int(timeout[1]))
    history = int(getattr(config, "history_size", 10)) if config is not None else 10
    transport_in = getattr(config, "transport_input", set()) if config is not None else set()
    transport_out = getattr(config, "transport_output", None) if config is not None else None
    exec_enabled = getattr(config, "exec_enabled", True) if config is not None else True

    if kind == "VTY":
        baud = "Baud rate (TX/RX) is 9600/9600"
        status = "Ready, Active, No Exit Banner" if active else "No Exit Banner"
        modem = "Ready" if active else "Idle"
    elif kind == "CTY":
        baud = "Baud rate (TX/RX) is 9600/9600, no parity, 2 stopbits, 8 databits"
        status = "PSI Enabled, Ready, Active, No Exit Banner" if active else "PSI Enabled, Ready, No Exit Banner"
        modem = "Ready"
    else:
        baud = "Baud rate (TX/RX) is 9600/9600, no parity, 2 stopbits, 8 databits"
        status = "Ready, Active, No Exit Banner" if active else "No Exit Banner"
        modem = "Ready" if active else "Idle"
    if active:
        activation = _hms(now - since) if since is not None else "00:00:00"
    else:
        activation = "never"
    output = "telnet ssh" if transport_out is None else _transports(transport_out)
    return [
        f'Line {tty}, Location: "", Type: ""',
        f"Length: {length} lines, Width: 80 columns",
        baud,
        f"Status: {status}",
        "Capabilities: " + ("none" if exec_enabled else "EXEC Suppressed"),
        f"Modem state: {modem}",
        "Group codes:    0",
        "Special Chars: Escape  Hold  Stop  Start  Disconnect  Activation",
        "                ^^x    none   -     -       none         ",
        "Timeouts:      Idle EXEC    Idle Session   Modem Answer  Session   Dispatch",
        f"               {idle_exec:<16}never                        none     not set",
        "                            Idle Session Disconnect Warning",
        "                              never ",
        "                            Login-sequence User Response",
        "                             00:00:30",
        "                            Autoselect Initial Wait",
        "                              not set ",
        "Modem type is unknown.",
        "Session limit is not set.",
        f"Time since activation: {activation}",
        "Editing is enabled.",
        f"History is enabled, history size is {history}.",
        "DNS resolution in show commands is enabled",
        "Full user help is disabled",
        f"Allowed input transports are {_transports(transport_in)}.",
        f"Allowed output transports are {output}.",
        "Preferred transport is telnet.",
        "Shell: enabled",
        "Shell trace: off",
        "No output characters are padded",
        "No special data dispatching characters",
    ]


_LINE_HELP = {
    "show": _SHOW,
    "line": "TTY line information",
    "console": "Primary terminal line",
    "aux": "Auxiliary line",
    "vty": "Virtual terminal",
    "n": "First Line range",
    "first": "First Line range",
    "last": "Last Line range",
}


@command("show line", modes=(EXEC,), privilege=1, help=_LINE_HELP)
def _show_line(ctx):
    active = _active_lines(ctx)
    rows = [_LINE_HEADER]
    for tty, kind, _number, _config in _line_table(ctx.node):
        rows.append(_line_row(tty, kind, tty in active))
    return "\n".join(rows)


@command("show line console {n:<0-0>}", modes=(EXEC,), privilege=1, help=_LINE_HELP)
@command("show line aux {n:<0-0>}", modes=(EXEC,), privilege=1, help=_LINE_HELP)
@command(
    "show line vty {first:<0-15>} [{last:<1-15>}]", modes=(EXEC,), privilege=1, help=_LINE_HELP
)
def _show_line_detail(ctx):
    node = ctx.node
    table = _line_table(node)
    if "console" in ctx.path:
        selected = [row for row in table if row[1] == "CTY"]
    elif "aux" in ctx.path:
        selected = [row for row in table if row[1] == "AUX"]
    else:
        first = int(ctx.args["first"])
        last = int(ctx.args.get("last", first))
        numbers = {row[2] for row in table if row[1] == "VTY"}
        if first not in numbers:
            return _caret(ctx, 3)
        if last < first or last not in numbers:
            return _caret(ctx, 4)
        selected = [row for row in table if row[1] == "VTY" and first <= row[2] <= last]
    active = _active_lines(ctx)
    now = ctx.now()
    blocks: List[str] = []
    for tty, kind, _number, config in selected:
        is_active = tty in active
        block = [_LINE_HEADER, _line_row(tty, kind, is_active), ""]
        block.extend(_line_detail(tty, kind, config, active.get(tty), is_active, now))
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


# =========================================================================== #
# debug / undebug / no debug / show debugging                                 #
# =========================================================================== #
#: flag key -> (show debugging group, message stem, trailing punctuation).
_DEBUG_FLAGS: Dict[str, Tuple[str, str, str]] = {
    "ip ospf adj": ("OSPF", "OSPF adjacency events debugging is", ""),
    "ip ospf events": ("OSPF", "OSPF events debugging is", ""),
    "ip ospf hello": ("OSPF", "OSPF hello events debugging is", ""),
    "ip icmp": ("Generic IP", "ICMP packet debugging is", ""),
    "ip packet": ("Generic IP", "IP packet debugging is", ""),
    "ip dhcp server events": ("DHCP server", "DHCP server event debugging is", "."),
    "ip dhcp server packet": ("DHCP server", "DHCP server packet debugging is", "."),
    "ntp events": ("NTP", "NTP events debugging is", ""),
    "ntp packets": ("NTP", "NTP packets debugging is", ""),
    "spanning-tree events": ("Spanning Tree", "Spanning Tree event debugging is", ""),
    "etherchannel": ("EtherChannel", "EtherChannel/PAgP Shim debugging is", ""),
}

_ALL_ON = "All possible debugging has been turned on"
_ALL_OFF = "All possible debugging has been turned off"
_DEBUG_ALL_WARNING = "This may severely impact network performance. Continue? (yes/[no]): "


class _DebugEntry:
    """Debug flags of one node, tied to the NodeState object they were set on."""

    __slots__ = ("node_ref", "flags")

    def __init__(self, node) -> None:
        try:
            self.node_ref = weakref.ref(node)
        except TypeError:  # pragma: no cover - node type without weakref support
            self.node_ref = lambda node=node: node
        self.flags: Set[str] = set()


#: (id(runtime) or None, node name) -> flags.  Module-local by design.
_DEBUG_STATE: Dict[Tuple[Optional[int], str], _DebugEntry] = {}


def _debug_key(ctx) -> Tuple[Optional[int], str]:
    runtime = ctx.runtime
    return (id(runtime) if runtime is not None else None, ctx.node.name)


def _debug_flags(ctx, create: bool = True) -> Optional[Set[str]]:
    """The live flag set of ``ctx.node`` (reset when the node was rebuilt)."""
    key = _debug_key(ctx)
    entry = _DEBUG_STATE.get(key)
    if entry is not None and entry.node_ref() is not ctx.node:
        del _DEBUG_STATE[key]  # reload / reset: debugging starts off
        entry = None
    if entry is None:
        if not create:
            return None
        for stale in [k for k, v in _DEBUG_STATE.items() if v.node_ref() is None]:
            del _DEBUG_STATE[stale]
        entry = _DebugEntry(ctx.node)
        _DEBUG_STATE[key] = entry
    return entry.flags


def _debug_message(flag: str, on: bool) -> str:
    _group, stem, tail = _DEBUG_FLAGS[flag]
    return f"{stem} {'on' if on else 'off'}{tail}"


def _flag_from_path(path: List[str]) -> str:
    words = list(path)
    if words and words[0] == "no":
        words = words[1:]
    words = words[1:]  # drop "debug" / "undebug"
    if words and words[0] == "etherchannel":
        return "etherchannel"
    return " ".join(words)


def _set_debug(ctx, on: bool):
    flag = _flag_from_path(ctx.path)
    flags = _debug_flags(ctx)
    if on:
        flags.add(flag)
    else:
        flags.discard(flag)
        flags.discard("all")
    return _debug_message(flag, on)


_DEBUG_HELP = {
    "no": "Disable debugging functions",
    "debug": "Debugging functions (see also 'undebug')",
    "undebug": "Disable debugging functions (see also 'debug')",
    "ip": "IP information",
}

_DEBUG_FAMILIES = (
    (
        "ip ospf (adj | events | hello)",
        {
            "ospf": "OSPF information",
            "adj": "OSPF adjacency events",
            "events": "OSPF events",
            "hello": "OSPF hello events",
        },
    ),
    (
        "ip (icmp | packet)",
        {
            "icmp": "ICMP transactions",
            "packet": "General IP debugging and IPSO security transactions",
        },
    ),
    (
        "ip dhcp server (events | packet)",
        {
            "dhcp": "Dynamic Host Configuration Protocol",
            "server": "DHCP server activity",
            "events": "Report address assignments, lease expirations, etc.",
            "packet": "Decode message receptions and transmissions",
        },
    ),
    (
        "ntp (events | packets)",
        {
            "ntp": "NTP information",
            "events": "NTP events",
            "packets": "NTP packets",
        },
    ),
    (
        "spanning-tree events",
        {
            "spanning-tree": "Spanning tree debugging",
            "events": "Spanning tree topology events",
        },
    ),
    (
        "etherchannel [all]",
        {
            "etherchannel": "EtherChannel/PAgP Shim debugging",
            "all": "All debugging messages",
        },
    ),
)


def _debug_on(ctx):
    return _set_debug(ctx, not ctx.negate)


def _debug_off(ctx):
    return _set_debug(ctx, False)


for _family, _family_help in _DEBUG_FAMILIES:
    command(
        f"[no] debug {_family}",
        modes=(EXEC,),
        privilege=15,
        help={**_DEBUG_HELP, **_family_help},
    )(_debug_on)
    command(
        f"undebug {_family}",
        modes=(EXEC,),
        privilege=15,
        help={**_DEBUG_HELP, **_family_help},
    )(_debug_off)


@command(
    "debug all",
    modes=(EXEC,),
    privilege=15,
    help={**_DEBUG_HELP, "all": "Enable all debugging"},
)
def _debug_all(ctx):
    answer = yield Prompt("\n" + _DEBUG_ALL_WARNING)
    if (answer or "").strip().lower() not in ("y", "ye", "yes"):
        return
    flags = _debug_flags(ctx)
    flags.update(_DEBUG_FLAGS)
    flags.add("all")
    yield _ALL_ON


@command(
    "undebug all",
    modes=(EXEC,),
    privilege=15,
    help={**_DEBUG_HELP, "all": "Disable all debugging"},
)
@command(
    "no debug all",
    modes=(EXEC,),
    privilege=15,
    help={**_DEBUG_HELP, "all": "Disable all debugging"},
)
def _undebug_all(ctx):
    flags = _debug_flags(ctx, create=False)
    if flags is not None:
        flags.clear()
    return _ALL_OFF


@command(
    "show debugging",
    modes=(EXEC,),
    privilege=1,
    help={"show": _SHOW, "debugging": "State of each debugging option"},
)
def _show_debugging(ctx):
    flags = _debug_flags(ctx, create=False)
    if not flags:
        return None
    groups: Dict[str, List[str]] = {}
    for flag, (group, _stem, _tail) in _DEBUG_FLAGS.items():
        if flag in flags:
            groups.setdefault(group, []).append("  " + _debug_message(flag, True))
    lines: List[str] = []
    for group, entries in groups.items():
        lines.append(f"{group}:")
        lines.extend(entries)
    return "\n".join(lines) if lines else None


# =========================================================================== #
# clear ip dhcp binding (* | A.B.C.D)                                         #
# =========================================================================== #
def _automatic(binding) -> bool:
    return str(getattr(binding, "binding_type", "Automatic") or "Automatic").lower().startswith("auto")


def _drop_binding(pool, address: str) -> None:
    binding = pool.bindings.pop(address, None)
    client = getattr(binding, "client_node", None) if binding is not None else None
    for name, leased in list(pool.leases.items()):
        if leased == address or (client is not None and name == client):
            pool.leases.pop(name, None)


@command(
    "clear ip dhcp binding (* | {address:A.B.C.D})",
    modes=(EXEC,),
    privilege=15,
    help={
        "clear": "Reset functions",
        "ip": "IP information",
        "dhcp": "Delete items from the DHCP database",
        "binding": "DHCP address bindings",
        "*": "Clear all automatic bindings",
        "address": "Clear a specific binding",
    },
)
def _clear_ip_dhcp_binding(ctx):
    # No ctx.mark_dirty(): bindings are dynamic state, and marking the node
    # dirty would re-run the automatic DHCP retry (re-leasing every host).
    node = ctx.node
    address = ctx.args.get("address")
    if address is None:
        for pool in node.dhcp_pools.values():
            for leased in [a for a, b in pool.bindings.items() if _automatic(b)]:
                _drop_binding(pool, leased)
        return None
    for pool in node.dhcp_pools.values():
        binding = pool.bindings.get(address)
        if binding is not None and _automatic(binding):
            _drop_binding(pool, address)
            return None
    return f"% Address {address} not in binding table"


# =========================================================================== #
# clear mac address-table dynamic [address H.H.H | interface X | vlan N]      #
# =========================================================================== #
@command(
    "clear mac address-table dynamic "
    "[(address {hw:H.H.H} | interface {intf:INTERFACE} | vlan {vid:<1-4094>})]",
    modes=(EXEC,),
    privilege=15,
    help={
        "clear": "Reset functions",
        "mac": "MAC configuration",
        "address-table": "MAC forwarding table",
        "dynamic": "dynamic entry type",
        "address": "address keyword",
        "hw": "48 bit mac address",
        "interface": "interface keyword",
        "intf": "interface",
        "vlan": "vlan keyword",
        "vid": "Vlan interface number",
    },
)
def _clear_mac_address_table_dynamic(ctx):
    node = ctx.node
    if not _is_switch(node):
        return _caret(ctx, 1)
    target_mac = ctx.args.get("hw")
    if target_mac is not None:
        target_mac = normalise_mac(target_mac)
    interface = ctx.args.get("intf")
    vlan = ctx.args.get("vid")
    for key, entry in list(node.mac_table.items()):
        if entry.static or getattr(entry, "secure", None):
            continue  # secure addresses are cleared with clear port-security
        if target_mac is not None and normalise_mac(entry.mac) != target_mac:
            continue
        if interface is not None and canonical_interface(entry.port) != interface:
            continue
        if vlan is not None and int(entry.vlan) != int(vlan):
            continue
        del node.mac_table[key]
    return None


# =========================================================================== #
# write terminal                                                              #
# =========================================================================== #
@command(
    "write terminal",
    modes=(EXEC,),
    privilege=15,
    help={
        "write": "Write running configuration to memory, network, or terminal",
        "terminal": "Write to terminal",
    },
)
def _write_terminal(ctx):
    node = ctx.node
    try:
        from .. import render

        return render.render_show_running(node)
    except Exception:  # pragma: no cover - renderer unavailable
        body = node.render_running_config()
        size = len(body.encode("utf-8"))
        header = f"Building configuration...\n\nCurrent configuration : {size} bytes\n"
        return header + body.rstrip("\n")
