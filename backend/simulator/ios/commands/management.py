"""Management & services IOS commands (Agent CMD-MGMT, Phase 2).

This module registers the configuration and ``show`` commands for the device
*services*: NTP, the clock timezone / summer-time, CDP and LLDP, the IP domain /
name-server / host table, RSA key generation and the SSH server, and the DHCP
server (pool sub-commands, excluded addresses).  Live operational output is read
from :class:`simulator.services.ServicesEngine` via ``ctx.engines.services`` and
formatted into IOS-faithful text; configuration handlers mutate ``ctx.node`` /
``ctx.target`` and call :meth:`ctx.mark_dirty`.

Ownership (PLAN Phase 2): this module owns ONLY this file.  It never edits the
shell/parser/engines/other command modules.  Auto-discovery registers it.

Command surface
---------------
CONFIG (global):
  * ``[no] ntp server A.B.C.D [key <1-4294967295>]``
  * ``[no] ntp master [<1-15>]``
  * ``[no] ntp authenticate``
  * ``[no] ntp authentication-key <1-4294967295> md5 LINE``
  * ``[no] ntp trusted-key <1-4294967295>``
  * ``clock timezone WORD <-23-23> [<0-59>]`` / ``no clock timezone``
  * ``clock summer-time WORD recurring`` / ``no clock summer-time``
  * ``[no] cdp run`` / ``cdp timer <5-254>`` / ``cdp holdtime <10-255>``
  * ``[no] lldp run``
  * ``[no] ip domain-name WORD`` / ``[no] ip domain name WORD``
  * ``[no] ip domain-lookup``
  * ``[no] ip name-server A.B.C.D``
  * ``[no] ip host WORD A.B.C.D``
  * ``crypto key generate rsa [modulus <360-4096>]`` / ``crypto key zeroize rsa``
  * ``ip ssh version <1-2>`` / ``ip ssh time-out <1-120>``
    / ``ip ssh authentication-retries <0-5>``
  * ``[no] ip dhcp excluded-address A.B.C.D [A.B.C.D]``
DHCP pool sub-mode (``ctx.target`` is the :class:`~simulator.models.DHCPPool`):
  * ``network A.B.C.D A.B.C.D`` / ``default-router A.B.C.D`` / ``dns-server A.B.C.D``
  * ``domain-name WORD`` / ``lease (infinite | <0-365> [<0-23>] [<0-59>])``
SHOW (EXEC):
  * ``show ntp status`` / ``show ntp associations [detail]``
  * ``show cdp`` / ``show cdp neighbors [detail]`` / ``show lldp neighbors``
  * ``show ip ssh`` / ``show hosts``
  * ``show ip dhcp binding`` / ``show ip dhcp pool [WORD]`` / ``show ip dhcp conflict``
"""

from __future__ import annotations

from typing import List, Optional

from ...models import NTPServer
from ..parser import CONFIG, DHCP_CONFIG, EXEC, command
from ..protocol import Prompt


# ===========================================================================
# Shared helpers
# ===========================================================================
def _services(ctx):
    """Return the live :class:`ServicesEngine`, or ``None`` when unwired."""
    engines = ctx.engines
    return engines.services if engines is not None else None


def _node_name(ctx) -> str:
    return ctx.node.name


# Capability code -> full name (``show cdp ... detail`` / legend expansion).
_CDP_CAP_FULL = {
    "R": "Router",
    "T": "Trans Bridge",
    "B": "Source Route Bridge",
    "S": "Switch",
    "H": "Host",
    "I": "IGMP",
    "r": "Repeater",
    "P": "Phone",
}

_CDP_CAP_LEGEND = (
    "Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge\n"
    "                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone, \n"
    "                  D - Remote, C - CVTA, M - Two-port Mac Relay \n"
)

_LLDP_CAP_LEGEND = (
    "Capability codes:\n"
    "    (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device\n"
    "    (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other\n"
)


def _lldp_short(canonical: str) -> str:
    """``Ethernet0/0`` -> ``Et0/0`` (LLDP local-interface abbreviation)."""
    prefixes = (
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("TenGigabitEthernet", "Te"),
        ("Ethernet", "Et"),
        ("Serial", "Se"),
        ("Loopback", "Lo"),
        ("Port-channel", "Po"),
        ("Tunnel", "Tu"),
        ("Vlan", "Vl"),
    )
    for prefix, short in prefixes:
        if canonical.startswith(prefix):
            return short + canonical[len(prefix):]
    return canonical


def _expand_caps(codes: str) -> str:
    names = [_CDP_CAP_FULL.get(code, code) for code in codes.split()]
    return " ".join(names)


# ===========================================================================
# NTP configuration
# ===========================================================================
@command(
    "[no] ntp server {ip:A.B.C.D} [key {k:<1-4294967295>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ntp": "Configure NTP",
        "server": "Configure NTP server",
        "ip": "IP address of peer",
        "key": "Configure peer authentication key",
        "k": "Peer key number",
    },
)
def _ntp_server(ctx):
    address = ctx.args["ip"]
    if ctx.negate:
        ctx.node.ntp_servers.pop(address, None)
    else:
        key_id = ctx.args.get("k")
        ctx.node.ntp_servers[address] = NTPServer(address, key_id=key_id)
    ctx.mark_dirty()
    return None


@command(
    "[no] ntp master [{stratum:<1-15>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ntp": "Configure NTP",
        "master": "Act as NTP master clock",
        "stratum": "Stratum number",
    },
)
def _ntp_master(ctx):
    if ctx.negate:
        ctx.node.ntp_master = None
    else:
        ctx.node.ntp_master = int(ctx.args.get("stratum", 8))
    ctx.mark_dirty()
    return None


@command(
    "[no] ntp authenticate",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ntp": "Configure NTP",
        "authenticate": "Authenticate time sources",
    },
)
def _ntp_authenticate(ctx):
    ctx.node.ntp_authenticate = not ctx.negate
    ctx.mark_dirty()
    return None


def _ntp_key_text(text: str) -> str:
    """Plaintext of ``ntp authentication-key N md5 VALUE [0|7]``.

    The running-config shows keys type-7 encrypted with a trailing ``7``; a
    replayed configuration (reload, ``copy startup-config running-config``,
    a pasted ``show run``) must decode them instead of encrypting them again.
    """
    parts = text.split()
    if len(parts) >= 2 and parts[-1] in ("0", "7"):
        value = " ".join(parts[:-1])
        if parts[-1] == "7":
            from ...crypto import type7_decode

            decoded = type7_decode(value)
            if decoded is not None:
                return decoded
        return value
    return text.strip()


@command(
    "[no] ntp authentication-key {k:<1-4294967295>} md5 {key:LINE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ntp": "Configure NTP",
        "authentication-key": "Authentication key for trusted time sources",
        "k": "Key number",
        "md5": "MD5 authentication",
        "key": "Authentication key",
    },
)
@command(
    "no ntp authentication-key {k:<1-4294967295>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ntp": "Configure NTP",
        "authentication-key": "Authentication key for trusted time sources",
        "k": "Key number",
    },
)
def _ntp_authentication_key(ctx):
    key_id = int(ctx.args["k"])
    if ctx.negate:
        ctx.node.ntp_keys.pop(key_id, None)
    else:
        key = ctx.args.get("key")
        if key is not None:
            ctx.node.ntp_keys[key_id] = _ntp_key_text(key)
    ctx.mark_dirty()
    return None


@command(
    "[no] ntp trusted-key {k:<1-4294967295>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ntp": "Configure NTP",
        "trusted-key": "Key numbers for trusted time sources",
        "k": "Key number",
    },
)
def _ntp_trusted_key(ctx):
    key_id = int(ctx.args["k"])
    if ctx.negate:
        ctx.node.ntp_trusted_keys.discard(key_id)
    else:
        ctx.node.ntp_trusted_keys.add(key_id)
    ctx.mark_dirty()
    return None


# ===========================================================================
# Clock timezone / summer-time
# ===========================================================================
@command(
    "clock timezone {name:WORD} {hours:<-23-23>} [{minutes:<0-59>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "clock": "Configure time-of-day clock",
        "timezone": "Configure time zone",
        "name": "Name of time zone",
        "hours": "Hours offset from UTC",
        "minutes": "Minutes offset from UTC",
    },
)
def _clock_timezone(ctx):
    ctx.node.timezone_name = ctx.args["name"]
    ctx.node.timezone_offset = int(ctx.args["hours"])
    ctx.node.timezone_offset_minutes = int(ctx.args.get("minutes", 0) or 0)
    ctx.mark_dirty()
    return None


@command(
    "no clock timezone",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "clock": "Configure time-of-day clock",
        "timezone": "Configure time zone",
    },
)
def _no_clock_timezone(ctx):
    ctx.node.timezone_name = "UTC"
    ctx.node.timezone_offset = 0
    ctx.node.timezone_offset_minutes = 0
    ctx.mark_dirty()
    return None


@command(
    "clock summer-time {name:WORD} recurring",
    modes=(CONFIG,),
    privilege=15,
    help={
        "clock": "Configure time-of-day clock",
        "summer-time": "Configure summer (daylight savings) time",
        "name": "Name of time zone in summer",
        "recurring": "Configure recurring summer time",
    },
)
def _clock_summer_time(ctx):
    ctx.node.summer_time_name = ctx.args["name"]
    ctx.node.summer_time_recurring = True
    ctx.mark_dirty()
    return None


@command(
    "no clock summer-time",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "clock": "Configure time-of-day clock",
        "summer-time": "Configure summer (daylight savings) time",
    },
)
def _no_clock_summer_time(ctx):
    ctx.node.summer_time_name = None
    ctx.node.summer_time_recurring = False
    ctx.mark_dirty()
    return None


# ===========================================================================
# CDP / LLDP
# ===========================================================================
@command(
    "[no] cdp run",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "cdp": "Global CDP configuration subcommands",
        "run": "Enable CDP",
    },
)
def _cdp_run(ctx):
    ctx.node.cdp_enabled = not ctx.negate
    ctx.mark_dirty()
    return None


@command(
    "cdp timer {n:<5-254>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "cdp": "Global CDP configuration subcommands",
        "timer": "Specify the rate at which CDP packets are sent",
        "n": "Rate at which CDP packets are sent (seconds)",
    },
)
def _cdp_timer(ctx):
    ctx.node.cdp_timer = int(ctx.args["n"])
    ctx.mark_dirty()
    return None


@command(
    "cdp holdtime {n:<10-255>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "cdp": "Global CDP configuration subcommands",
        "holdtime": "Specify the holdtime (in sec) to be sent in packets",
        "n": "Length of time (in sec) that receiver must keep this packet",
    },
)
def _cdp_holdtime(ctx):
    ctx.node.cdp_holdtime = int(ctx.args["n"])
    ctx.mark_dirty()
    return None


@command(
    "[no] lldp run",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "lldp": "Global LLDP configuration subcommands",
        "run": "Enable LLDP",
    },
)
def _lldp_run(ctx):
    ctx.node.lldp_enabled = not ctx.negate
    ctx.mark_dirty()
    return None


# ===========================================================================
# IP domain / name-server / host
# ===========================================================================
@command(
    "[no] ip domain-name {d:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "domain-name": "Define the default domain name",
        "d": "Default domain name",
    },
)
@command(
    "[no] ip domain name {d:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "domain": "IP DNS Resolver",
        "name": "Define the default domain name",
        "d": "Default domain name",
    },
)
def _ip_domain_name(ctx):
    if ctx.negate:
        ctx.node.domain_name = None
    else:
        ctx.node.domain_name = ctx.args["d"]
    ctx.mark_dirty()
    return None


@command(
    "[no] ip domain-lookup",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "domain-lookup": "Enable IP Domain Name System hostname translation",
    },
)
@command(
    "[no] ip domain lookup",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "domain": "IP DNS Resolver",
        "lookup": "Enable IP Domain Name System hostname translation",
    },
)
def _ip_domain_lookup(ctx):
    ctx.node.ip_domain_lookup = not ctx.negate
    ctx.mark_dirty()
    return None


@command(
    "[no] ip name-server {addr:A.B.C.D}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "name-server": "Specify address of name server to use",
        "addr": "Domain server IP address",
    },
)
def _ip_name_server(ctx):
    address = ctx.args["addr"]
    if ctx.negate:
        ctx.node.name_servers = [a for a in ctx.node.name_servers if a != address]
    elif address not in ctx.node.name_servers:
        ctx.node.name_servers.append(address)
    ctx.mark_dirty()
    return None


@command(
    "[no] ip host {name:WORD} {addr:A.B.C.D}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "host": "Add an entry to the host table",
        "name": "Name of host",
        "addr": "Host IP address",
    },
)
def _ip_host(ctx):
    name = ctx.args["name"]
    if ctx.negate:
        ctx.node.ip_hosts.pop(name, None)
    else:
        ctx.node.ip_hosts[name] = ctx.args["addr"]
    ctx.mark_dirty()
    return None


# ===========================================================================
# Crypto RSA keys / SSH server
# ===========================================================================
def _ssh_version_text(node) -> str:
    """SSH version shown by ``show ip ssh`` and the SSH syslog messages."""
    version = getattr(node, "ssh_version", None)
    if version == 2:
        return "2.0"
    if version == 1:
        return "1.5"
    return "1.99"


@command(
    "crypto key generate rsa [modulus {bits:<360-4096>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "crypto": "Encryption module",
        "key": "Long term key operations",
        "generate": "Generate new keys",
        "rsa": "Generate RSA keys",
        "modulus": "Provide number of modulus bits on the command line",
        "bits": "Number of modulus bits",
    },
)
def _crypto_key_generate_rsa(ctx):
    node = ctx.node
    if not node.domain_name:
        yield "% Please define a domain-name first."
        return
    had_keys = node.rsa_bits is not None
    name_line = f"The name for the keys will be: {node.hostname}.{node.domain_name}\n"
    bits = ctx.args.get("bits")
    if bits is None:
        yield (
            name_line
            + "Choose the size of the key modulus in the range of 360 to 4096 for your\n"
            "  General Purpose Keys. Choosing a key modulus greater than 512 may take\n"
            "  a few minutes.\n\n"
        )
        answer = yield Prompt("How many bits in the modulus [512]: ")
        answer = (answer or "").strip()
        if not answer:
            bits = 512
        else:
            try:
                bits = int(answer)
            except ValueError:
                bits = 512
        header = ""
    else:
        header = name_line + f"% The key modulus size is {int(bits)} bits\n"
    bits = int(bits)
    node.rsa_bits = bits
    node.rsa_generated_at = ctx.now()
    ctx.mark_dirty()
    yield (
        header
        + f"% Generating {bits} bit RSA keys, keys will be non-exportable...\n"
        "[OK] (elapsed time was 0 seconds)"
    )
    if not had_keys:
        ctx.emit_log(f"%SSH-5-ENABLED: SSH {_ssh_version_text(node)} has been enabled")


@command(
    "crypto key zeroize rsa",
    modes=(CONFIG,),
    privilege=15,
    help={
        "crypto": "Encryption module",
        "key": "Long term key operations",
        "zeroize": "Remove keys",
        "rsa": "Remove RSA keys",
    },
)
def _crypto_key_zeroize_rsa(ctx):
    had_keys = ctx.node.rsa_bits is not None
    ctx.node.rsa_bits = None
    ctx.node.rsa_generated_at = None
    ctx.mark_dirty()
    if had_keys:
        ctx.emit_log(f"%SSH-5-DISABLED: SSH {_ssh_version_text(ctx.node)} has been disabled")
    return None


@command(
    "ip ssh version {v:<1-2>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "ip": "Global IP configuration subcommands",
        "ssh": "Configure ssh options",
        "version": "Specify protocol version",
        "v": "Protocol version",
    },
)
def _ip_ssh_version(ctx):
    ctx.node.ssh_version = int(ctx.args["v"])
    ctx.mark_dirty()
    return None


@command(
    "ip ssh time-out {n:<1-120>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "ip": "Global IP configuration subcommands",
        "ssh": "Configure ssh options",
        "time-out": "Set timeout value",
        "n": "SSH time-out interval (secs)",
    },
)
def _ip_ssh_timeout(ctx):
    ctx.node.ip_ssh_timeout = int(ctx.args["n"])
    ctx.mark_dirty()
    return None


@command(
    "ip ssh authentication-retries {n:<0-5>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "ip": "Global IP configuration subcommands",
        "ssh": "Configure ssh options",
        "authentication-retries": "Specify number of authentication retries",
        "n": "Number of authentication retries",
    },
)
def _ip_ssh_retries(ctx):
    ctx.node.ip_ssh_retries = int(ctx.args["n"])
    ctx.mark_dirty()
    return None


# ===========================================================================
# DHCP excluded-address (global)
# ===========================================================================
@command(
    "[no] ip dhcp excluded-address {a:A.B.C.D} [{b:A.B.C.D}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "dhcp": "Configure DHCP server and relay parameters",
        "excluded-address": "Prevent DHCP from assigning certain addresses",
        "a": "Low IP address",
        "b": "High IP address",
    },
)
def _ip_dhcp_excluded_address(ctx):
    low = ctx.args["a"]
    high = ctx.args.get("b", low)
    pair = (low, high)
    if ctx.negate:
        ctx.node.dhcp_excluded = [
            item for item in ctx.node.dhcp_excluded if item != pair
        ]
    elif pair not in ctx.node.dhcp_excluded:
        ctx.node.dhcp_excluded.append(pair)
    ctx.mark_dirty()
    return None


# ===========================================================================
# DHCP pool sub-mode (ctx.target is a DHCPPool)
# ===========================================================================
@command(
    "network {net:A.B.C.D} {mask:A.B.C.D}",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={
        "network": "Configure the subnet number and mask",
        "net": "Specify network number",
        "mask": "Specify the subnet mask",
    },
)
def _dhcp_network(ctx):
    pool = ctx.target
    pool.network_address = ctx.args["net"]
    pool.netmask = ctx.args["mask"]
    ctx.mark_dirty()
    return None


@command(
    "default-router {ip:A.B.C.D}",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={
        "default-router": "Default routers",
        "ip": "Router IP address",
    },
)
def _dhcp_default_router(ctx):
    ctx.target.default_router = ctx.args["ip"]
    ctx.mark_dirty()
    return None


@command(
    "dns-server {ip:A.B.C.D}",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={
        "dns-server": "DNS Servers",
        "ip": "Server IP address",
    },
)
def _dhcp_dns_server(ctx):
    ctx.target.dns_servers = [ctx.args["ip"]]
    ctx.mark_dirty()
    return None


@command(
    "domain-name {d:WORD}",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={
        "domain-name": "Domain name",
        "d": "Domain name",
    },
)
def _dhcp_domain_name(ctx):
    ctx.target.domain_name = ctx.args["d"]
    ctx.mark_dirty()
    return None


@command(
    "lease (infinite | {days:<0-365>} [{hours:<0-23>} [{minutes:<0-59>}]])",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={
        "lease": "Address lease time",
        "infinite": "Infinite lease",
        "days": "Days",
        "hours": "Hours",
        "minutes": "Minutes",
    },
)
def _dhcp_lease(ctx):
    pool = ctx.target
    if "infinite" in ctx.path:
        pool.lease_infinite = True
        pool.lease_days = 0
        pool.lease_hours = 0
        pool.lease_minutes = 0
    else:
        pool.lease_infinite = False
        pool.lease_days = int(ctx.args.get("days", 0))
        pool.lease_hours = int(ctx.args.get("hours", 0))
        pool.lease_minutes = int(ctx.args.get("minutes", 0))
    ctx.mark_dirty()
    return None


# ===========================================================================
# SHOW: NTP
# ===========================================================================
def _fmt_ntp_status(status) -> str:
    if status.synchronized:
        first = (
            f"Clock is synchronized, stratum {status.stratum}, "
            f"reference is {status.reference}"
        )
    else:
        first = "Clock is unsynchronized, stratum 16, no reference clock"
    drift = status.drift_ppm / 1_000_000.0
    if status.last_update == "never":
        last = f"system poll interval is {status.system_poll_interval}, never updated."
    else:
        last = (
            f"system poll interval is {status.system_poll_interval}, "
            f"last update was {status.last_update}."
        )
    return "\n".join(
        [
            first,
            f"nominal freq is {status.nominal_freq:.4f} Hz, "
            f"actual freq is {status.actual_freq:.4f} Hz, precision is {status.precision}",
            f"ntp uptime is {status.ntp_uptime_cs} (1/100 of seconds), "
            f"resolution is {status.resolution}",
            f"reference time is {status.reference_time_hex} ({status.reference_time_text})",
            f"clock offset is {status.clock_offset_ms:.4f} msec, "
            f"root delay is {status.root_delay_ms:.2f} msec",
            f"root dispersion is {status.root_dispersion_ms:.2f} msec, "
            f"peer dispersion is {status.peer_dispersion_ms:.2f} msec",
            f"loopfilter state is {status.loopfilter_state}, drift is {drift:.9f} s/s",
            last,
        ]
    )


@command(
    "show ntp status",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ntp": "Network time protocol",
        "status": "VINES time server information",
    },
)
def _show_ntp_status(ctx):
    services = _services(ctx)
    if services is None:
        return None
    return _fmt_ntp_status(services.ntp_status(_node_name(ctx)))


_NTP_ASSOC_HEADER = (
    "  address         ref clock       st   when   poll reach  delay  offset   disp"
)
_NTP_ASSOC_LEGEND = (
    " * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured"
)


def _assoc_prefix(marker: str) -> str:
    # Engine marker collapses selection; every association here is configured.
    if marker == "*":
        return "*~"
    if marker == "+":
        return "+~"
    if marker == "~":
        return " ~"
    return "  "


def _fmt_ntp_associations(rows) -> str:
    lines = [_NTP_ASSOC_HEADER]
    for row in rows:
        prefix = _assoc_prefix(row.marker)
        lines.append(
            f"{prefix}{row.address:<15} {row.ref_clock:<14} {row.stratum:>2}"
            f"  {row.when:>5}  {row.poll:>5}  {row.reach:>4}"
            f"  {row.delay_ms:>6.3f}  {row.offset_ms:>6.3f}  {row.dispersion_ms:>6.3f}"
        )
    lines.append(_NTP_ASSOC_LEGEND)
    return "\n".join(lines)


def _fmt_ntp_associations_detail(rows, services, node_name) -> str:
    if not rows:
        return ""
    blocks: List[str] = []
    for row in rows:
        flags = []
        flags.append("configured")
        if row.authenticated:
            flags.append("authenticated")
        flags.append("sane" if row.sane else "insane")
        flags.append("valid" if row.valid else "invalid")
        head = f"{row.address} {', '.join(flags)}, stratum {row.stratum}"
        blocks.append(
            "\n".join(
                [
                    head,
                    f"ref ID {row.ref_id or row.ref_clock}, time "
                    f"00000000.00000000 (00:00:00.000 UTC)",
                    "our mode client, peer mode server, "
                    "our poll intvl 64, peer poll intvl 64",
                    f"root delay 0.00 msec, root disp 0.03, reach {row.reach}, "
                    "sync dist 0.000",
                    f"delay {row.delay_ms:.2f} msec, offset {row.offset_ms:.4f} msec, "
                    f"dispersion {row.dispersion_ms:.2f}",
                ]
            )
        )
    return "\n".join(blocks)


@command(
    "show ntp associations [detail]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ntp": "Network time protocol",
        "associations": "NTP associations",
        "detail": "Display detailed association information",
    },
)
def _show_ntp_associations(ctx):
    services = _services(ctx)
    if services is None:
        return None
    detail = "detail" in ctx.path
    rows = services.ntp_associations(_node_name(ctx), detail=detail)
    if detail:
        return _fmt_ntp_associations_detail(rows, services, _node_name(ctx))
    return _fmt_ntp_associations(rows)


# ===========================================================================
# SHOW: CDP / LLDP
# ===========================================================================
@command(
    "show cdp",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "cdp": "CDP information",
    },
)
def _show_cdp(ctx):
    services = _services(ctx)
    if services is None:
        return None
    globals_ = services.cdp_globals(_node_name(ctx))
    if not globals_.enabled:
        return "% CDP is not enabled"
    advertise = "enabled" if globals_.advertise_v2 else "disabled"
    return (
        "Global CDP information:\n"
        f"        Sending CDP packets every {globals_.timer} seconds\n"
        f"        Sending a holdtime value of {globals_.holdtime} seconds\n"
        f"        Sending CDPv2 advertisements is  {advertise}"
    )


def _fmt_cdp_neighbors(neighbors) -> str:
    header = (
        "Device ID        Local Intrfce    Holdtme    Capability  Platform  Port ID"
    )
    lines = [_CDP_CAP_LEGEND, header]
    for n in neighbors:
        platform = (n.platform or "")[:9]
        lines.append(
            f"{n.device_id:<17}{n.local_interface_short:<17}"
            f"{n.holdtime:<11}{n.capabilities:<12}{platform:<10}{n.port_id_short}"
        )
    lines.append("")
    lines.append(f"Total cdp entries displayed : {len(neighbors)}")
    return "\n".join(lines)


def _fmt_cdp_neighbors_detail(neighbors) -> str:
    blocks: List[str] = []
    for n in neighbors:
        parts = ["-------------------------", f"Device ID: {n.device_id}"]
        addresses = n.interface_addresses or n.mgmt_addresses
        parts.append("Entry address(es): ")
        for addr in addresses:
            parts.append(f"  IP address: {addr}")
        parts.append(
            f"Platform: {n.platform},  Capabilities: {_expand_caps(n.capabilities)}"
        )
        parts.append(
            f"Interface: {n.local_interface},  "
            f"Port ID (outgoing port): {n.port_id}"
        )
        parts.append(f"Holdtime : {n.holdtime} sec")
        parts.append("")
        parts.append("Version :")
        parts.append(n.version)
        parts.append("")
        parts.append(f"advertisement version: {n.advertisement_version}")
        if n.native_vlan is not None:
            parts.append(f"Native VLAN: {n.native_vlan}")
        parts.append(f"Duplex: {n.duplex}")
        blocks.append("\n".join(parts))
    tail = f"\n\nTotal cdp entries displayed : {len(neighbors)}"
    return "\n".join(blocks) + tail if blocks else "Total cdp entries displayed : 0"


@command(
    "show cdp neighbors [detail]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "cdp": "CDP information",
        "neighbors": "CDP neighbor entries information",
        "detail": "Show detailed information",
    },
)
def _show_cdp_neighbors(ctx):
    services = _services(ctx)
    if services is None:
        return None
    if not services.cdp_globals(_node_name(ctx)).enabled:
        return "% CDP is not enabled"
    neighbors = services.cdp_neighbors(_node_name(ctx))
    if "detail" in ctx.path:
        return _fmt_cdp_neighbors_detail(neighbors)
    return _fmt_cdp_neighbors(neighbors)


@command(
    "show lldp neighbors",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "lldp": "LLDP information",
        "neighbors": "LLDP neighbor entries information",
    },
)
def _show_lldp_neighbors(ctx):
    services = _services(ctx)
    if services is None:
        return None
    neighbors = services.lldp_neighbors(_node_name(ctx))
    header = (
        "Device ID           Local Intf     Hold-time  Capability      Port ID"
    )
    lines = [_LLDP_CAP_LEGEND, header]
    for n in neighbors:
        local = _lldp_short(n.local_interface)
        port = _lldp_short(n.port_id)
        lines.append(
            f"{n.system_name:<20}{local:<15}{n.hold_time:<11}"
            f"{n.capabilities:<16}{port}"
        )
    lines.append("")
    lines.append(f"Total entries displayed: {len(neighbors)}")
    return "\n".join(lines)


# ===========================================================================
# SHOW: SSH
# ===========================================================================
@command(
    "show ip ssh",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "ssh": "Status of SSH server connections",
    },
)
def _show_ip_ssh(ctx):
    services = _services(ctx)
    if services is None:
        return None
    info = services.ssh_server_info(_node_name(ctx))
    lines = [info.version_text]
    if not info.enabled:
        lines.append(
            "%Please create RSA keys to enable SSH (and of atleast 768 bits "
            "for SSH v2)."
        )
    lines.append(
        f"Authentication timeout: {info.auth_timeout} secs; "
        f"Authentication retries: {info.retries}"
    )
    return "\n".join(lines)


# ===========================================================================
# SHOW: hosts
# ===========================================================================
@command(
    "show hosts",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "hosts": "IP domain-name, lookup style, nameservers, and host table",
    },
)
def _show_hosts(ctx):
    node = ctx.node
    lines: List[str] = []
    if node.domain_name:
        lines.append(f"Default domain is {node.domain_name}")
    else:
        lines.append("Default domain is not set")
    if node.ip_domain_lookup:
        lines.append("Name/address lookup uses domain service")
    else:
        lines.append("Name/address lookup is disabled")
    servers = ", ".join(node.name_servers) if node.name_servers else "255.255.255.255"
    lines.append(f"Name servers are {servers}")
    lines.append("")
    lines.append("Codes: UN - unknown, EX - expired, OK - OK, ?? - revalidate")
    lines.append("       temp - temporary, perm - permanent")
    lines.append("       NA - Not Applicable None - Not defined")
    lines.append("")
    lines.append(
        "Host                      Port  Flags      Age Type   Address(es)"
    )
    for name in sorted(node.ip_hosts):
        address = node.ip_hosts[name]
        lines.append(
            f"{name:<25} {'None':<5} {'(perm, OK)':<10} {0:>3} {'IP':<6} {address}"
        )
    return "\n".join(lines)


# ===========================================================================
# SHOW: DHCP
# ===========================================================================
_DHCP_BINDING_HEADER = (
    "IP address          Client-ID/              Lease expiration        "
    "Type       State      Interface\n"
    "                    Hardware address/\n"
    "                    User name"
)


@command(
    "show ip dhcp binding",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "dhcp": "Show items in the DHCP database",
        "binding": "DHCP address bindings",
    },
)
def _show_ip_dhcp_binding(ctx):
    services = _services(ctx)
    if services is None:
        return None
    rows = services.dhcp_bindings(_node_name(ctx))
    lines = ["Bindings from all pools not associated with VRF:", _DHCP_BINDING_HEADER]
    for row in rows:
        lines.append(
            f"{row.ip:<20}{row.client_id:<24}{row.lease_expiration:<24}"
            f"{row.type:<11}{row.state:<11}{row.interface}"
        )
    return "\n".join(lines)


def _fmt_dhcp_pool(stats) -> str:
    lines = [f"Pool {stats.pool_name} :"]
    lines.append(" Utilization mark (high/low)    : 100 / 0")
    lines.append(" Subnet size (first/next)       : 0 / 0")
    lines.append(f" Total addresses                : {stats.total}")
    lines.append(f" Leased addresses               : {stats.leased}")
    lines.append(f" Excluded addresses             : {stats.excluded}")
    lines.append(" Pending event                  : none")
    if stats.network:
        lines.append(" 1 subnet is currently in the pool :")
        lines.append(
            " Current index        IP address range"
            "                    Leased/Excluded/Total"
        )
        current = stats.current_index or stats.first_address or "0.0.0.0"
        lines.append(
            f" {current:<20} {stats.first_address:<16} - {stats.last_address:<16} "
            f"{stats.leased:>4} / {stats.excluded:>4} / {stats.total}"
        )
    return "\n".join(lines)


@command(
    "show ip dhcp pool [{name:WORD}]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "dhcp": "Show items in the DHCP database",
        "pool": "DHCP pools information",
        "name": "Pool name",
    },
)
def _show_ip_dhcp_pool(ctx):
    services = _services(ctx)
    if services is None:
        return None
    node = ctx.node
    requested = ctx.args.get("name")
    if requested is not None:
        names = [requested]
    else:
        names = sorted(node.dhcp_pools)
    blocks: List[str] = []
    for name in names:
        stats = services.dhcp_pool_stats(_node_name(ctx), name)
        if stats is None:
            continue
        blocks.append(_fmt_dhcp_pool(stats))
    return "\n".join(blocks)


@command(
    "show ip dhcp conflict",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "dhcp": "Show items in the DHCP database",
        "conflict": "DHCP address conflicts",
    },
)
def _show_ip_dhcp_conflict(ctx):
    services = _services(ctx)
    if services is None:
        return None
    rows = services.dhcp_conflicts(_node_name(ctx))
    lines = ["IP address        Detection method   Detection time"]
    for row in rows:
        lines.append(
            f"{row.address:<18}{row.detection_method:<19}{row.detection_time}"
        )
    return "\n".join(lines)
