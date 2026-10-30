"""Interface configuration sub-commands (Agent CMD-IFSW).

These handlers run in the interface configuration submodes that core's
``interface`` / ``interface range`` entry commands push (``CONFIG_IF`` /
``CONFIG_IF_RANGE`` / ``CONFIG_SUBIF``).  They read ``ctx.target`` -- a single
:class:`~simulator.models.InterfaceState` (``config-if`` / ``config-subif``) or
a list of them (``config-if-range``) -- and mutate the matching model fields,
marking the node dirty so the engine bundle and ``running-config`` reflect the
change.

Switchport / spanning-tree / channel-group interface commands live in the
sibling :mod:`switching` module; this module owns the generic L3 / physical
interface settings (description, addressing, shutdown, duplex/speed, tuning,
helper-address, cdp, per-interface OSPF and sub-interface encapsulation).
"""

from __future__ import annotations

from typing import List

from ...models import InterfaceState
from ..parser import (
    CONFIG_IF,
    CONFIG_IF_RANGE,
    CONFIG_SUBIF,
    command,
)

#: Interface submodes these commands are valid in.
IF_MODES = (CONFIG_IF, CONFIG_IF_RANGE, CONFIG_SUBIF)


def _targets(ctx) -> List[InterfaceState]:
    """Return every :class:`InterfaceState` the current submode applies to."""
    target = ctx.target
    if isinstance(target, list):
        return [item for item in target if isinstance(item, InterfaceState)]
    if isinstance(target, InterfaceState):
        return [target]
    return []


# --------------------------------------------------------------------------- #
# Description                                                                 #
# --------------------------------------------------------------------------- #
@command(
    "description {text:LINE}",
    modes=IF_MODES,
    privilege=15,
    help={"description": "Interface specific description", "text": "Up to 240 characters describing this interface"},
)
def _description(ctx):
    text = ctx.args["text"]
    for iface in _targets(ctx):
        iface.description = text
    ctx.mark_dirty()
    return None


@command(
    "no description",
    modes=IF_MODES,
    privilege=15,
    help={"no": "Negate a command or set its defaults", "description": "Interface specific description"},
)
def _no_description(ctx):
    for iface in _targets(ctx):
        iface.description = None
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# IP addressing                                                               #
# --------------------------------------------------------------------------- #
#: IOS refuses an address on a LAN subinterface that has no VLAN encapsulation.
_SUBIF_NEEDS_VLAN = (
    "\n% Configuring IP routing on a LAN subinterface is only allowed if that\n"
    "subinterface is already configured as part of an IEEE 802.10, IEEE 802.1Q,\n"
    "or ISL vLAN.\n\n"
)
#: ... and on a switchport (an L2 port needs `no switchport` first).
_L2_PORT_NO_IP = "% IP addresses may not be configured on L2 links."


def _is_l2_port(node, iface) -> bool:
    name = iface.name
    return (
        getattr(node, "kind", None) == "switch"
        and not name.startswith(("Vlan", "Loopback"))
        and "." not in name
        and not iface.routed_port
    )


@command(
    "ip address {ip:A.B.C.D} {mask:A.B.C.D} [secondary]",
    modes=IF_MODES,
    privilege=15,
    help={
        "ip": "Interface Internet Protocol config commands",
        "address": "Set the IP address of an interface",
        "mask": "IP subnet mask",
        "secondary": "Make this IP address a secondary address",
    },
)
def _ip_address(ctx):
    address = ctx.args["ip"]
    mask = ctx.args["mask"]
    secondary = "secondary" in ctx.path
    rejected = applied = False
    l2_rejected = False
    for iface in _targets(ctx):
        if _is_l2_port(ctx.node, iface):
            l2_rejected = True
            continue
        if "." in iface.name and iface.encapsulation_vlan is None:
            rejected = True
            continue
        applied = True
        if secondary:
            pair = (address, mask)
            if pair not in iface.secondary_addresses:
                iface.secondary_addresses.append(pair)
        else:
            iface.ip_address = address
            iface.netmask = mask
            iface.address_source = "manual"
    if applied:
        ctx.mark_dirty()
    if l2_rejected:
        return _L2_PORT_NO_IP
    return _SUBIF_NEEDS_VLAN if rejected else None


@command(
    "no ip address",
    modes=IF_MODES,
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Interface Internet Protocol config commands",
        "address": "Set the IP address of an interface",
    },
)
def _no_ip_address(ctx):
    for iface in _targets(ctx):
        iface.ip_address = None
        iface.netmask = None
        iface.address_source = None
        iface.secondary_addresses = []
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# Administrative state                                                        #
# --------------------------------------------------------------------------- #
@command(
    "[no] shutdown",
    modes=IF_MODES,
    privilege=15,
    help={"no": "Negate a command or set its defaults", "shutdown": "Shutdown the selected interface"},
)
def _shutdown(ctx):
    for iface in _targets(ctx):
        iface.shutdown = not ctx.negate
        if not ctx.negate and iface.err_disabled_reason:
            # IOS recovery: `shutdown` then `no shutdown` clears err-disable and
            # flushes the addresses learned on the port.  Sticky secure
            # addresses survive: they are configuration
            # (iface.port_security_sticky_macs) and are re-installed on use.
            iface.err_disabled_reason = None
            iface.port_security_violation_count = 0
            table = getattr(ctx.node, "mac_table", None)
            if isinstance(table, dict):
                for key in [k for k, entry in table.items()
                            if not entry.static and entry.port == iface.name]:
                    del table[key]
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# Duplex / speed                                                              #
# --------------------------------------------------------------------------- #
@command(
    "duplex (auto|full|half)",
    modes=IF_MODES,
    privilege=15,
    help={
        "duplex": "Configure duplex operation",
        "auto": "Enable AUTO duplex configuration",
        "full": "Force full duplex operation",
        "half": "Force half-duplex operation",
    },
)
def _duplex(ctx):
    value = ctx.path[-1]
    for iface in _targets(ctx):
        iface.duplex = value
    ctx.mark_dirty()
    return None


@command(
    "speed (auto|10|100|1000)",
    modes=IF_MODES,
    privilege=15,
    help={
        "speed": "Configure speed operation",
        "auto": "Enable AUTO speed configuration",
        "10": "Force 10 Mbps operation",
        "100": "Force 100 Mbps operation",
        "1000": "Force 1000 Mbps operation",
    },
)
def _speed(ctx):
    value = ctx.path[-1]
    for iface in _targets(ctx):
        iface.speed = value
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# Interface tuning (mtu / bandwidth / delay)                                  #
# --------------------------------------------------------------------------- #
@command(
    "mtu {n:<64-9216>}",
    modes=IF_MODES,
    privilege=15,
    help={"mtu": "Set the interface Maximum Transmission Unit (MTU)", "n": "MTU size in bytes"},
)
def _mtu(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.mtu = value
    ctx.mark_dirty()
    return None


@command(
    "bandwidth {n:<1-10000000>}",
    modes=IF_MODES,
    privilege=15,
    help={"bandwidth": "Set bandwidth informational parameter", "n": "Bandwidth in kilobits"},
)
def _bandwidth(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.bandwidth_kbps = value
    ctx.mark_dirty()
    return None


@command(
    "delay {n:<1-16777215>}",
    modes=IF_MODES,
    privilege=15,
    help={"delay": "Specify interface throughput delay", "n": "Throughput delay (tens of microseconds)"},
)
def _delay(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.delay_tens_usec = value
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# IP helper-address                                                           #
# --------------------------------------------------------------------------- #
@command(
    "[no] ip helper-address {ip:A.B.C.D}",
    modes=IF_MODES,
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Interface Internet Protocol config commands",
        "helper-address": "Specify a destination address for UDP broadcasts",
    },
)
def _ip_helper_address(ctx):
    address = ctx.args["ip"]
    for iface in _targets(ctx):
        if ctx.negate:
            if address in iface.helper_addresses:
                iface.helper_addresses.remove(address)
        elif address not in iface.helper_addresses:
            iface.helper_addresses.append(address)
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# CDP                                                                         #
# --------------------------------------------------------------------------- #
@command(
    "[no] cdp enable",
    modes=IF_MODES,
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "cdp": "CDP interface subcommands",
        "enable": "Enable CDP on interface",
    },
)
def _cdp_enable(ctx):
    for iface in _targets(ctx):
        iface.cdp_enabled = not ctx.negate
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# Per-interface OSPF                                                          #
# --------------------------------------------------------------------------- #
@command(
    "ip ospf {pid:<1-65535>} area {area:<0-4294967295>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "ip": "Interface Internet Protocol config commands",
        "ospf": "OSPF interface commands",
        "pid": "Process ID",
        "area": "Set the OSPF area ID",
    },
)
def _ip_ospf_area(ctx):
    pid = ctx.args["pid"]
    area = ctx.args["area"]
    for iface in _targets(ctx):
        iface.ospf_process = pid
        iface.ospf_area = area
    ctx.mark_dirty()
    return None


@command(
    "ip ospf cost {c:<1-65535>}",
    modes=IF_MODES,
    privilege=15,
    help={"ip": "Interface Internet Protocol config commands", "ospf": "OSPF interface commands", "cost": "Interface cost", "c": "Cost"},
)
def _ip_ospf_cost(ctx):
    value = ctx.args["c"]
    for iface in _targets(ctx):
        iface.ospf_cost = value
    ctx.mark_dirty()
    return None


@command(
    "ip ospf priority {p:<0-255>}",
    modes=IF_MODES,
    privilege=15,
    help={"ip": "Interface Internet Protocol config commands", "ospf": "OSPF interface commands", "priority": "Router priority", "p": "Priority"},
)
def _ip_ospf_priority(ctx):
    value = ctx.args["p"]
    for iface in _targets(ctx):
        iface.ospf_priority = value
    ctx.mark_dirty()
    return None


@command(
    "ip ospf hello-interval {n:<1-65535>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "ip": "Interface Internet Protocol config commands",
        "ospf": "OSPF interface commands",
        "hello-interval": "Time between HELLO packets",
        "n": "Seconds",
    },
)
def _ip_ospf_hello(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.ospf_hello_interval = value
    ctx.mark_dirty()
    return None


@command(
    "ip ospf dead-interval {n:<1-65535>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "ip": "Interface Internet Protocol config commands",
        "ospf": "OSPF interface commands",
        "dead-interval": "Interval after which a neighbor is declared dead",
        "n": "Seconds",
    },
)
def _ip_ospf_dead(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.ospf_dead_interval = value
    ctx.mark_dirty()
    return None


@command(
    "ip ospf network (broadcast|point-to-point)",
    modes=IF_MODES,
    privilege=15,
    help={
        "ip": "Interface Internet Protocol config commands",
        "ospf": "OSPF interface commands",
        "network": "Network type",
        "broadcast": "Specify OSPF broadcast multi-access network",
        "point-to-point": "Specify OSPF point-to-point network",
    },
)
def _ip_ospf_network(ctx):
    value = ctx.path[-1]
    for iface in _targets(ctx):
        iface.ospf_network_type = value
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# Sub-interface encapsulation                                                 #
# --------------------------------------------------------------------------- #
@command(
    "encapsulation dot1Q {vlan:<1-4094>} [native]",
    modes=(CONFIG_SUBIF,),
    privilege=15,
    help={
        "encapsulation": "Set encapsulation type for an interface",
        "dot1Q": "IEEE 802.1Q Virtual LAN",
        "vlan": "IEEE 802.1Q VLAN ID",
        "native": "Make this as native vlan",
    },
)
def _encapsulation_dot1q(ctx):
    vlan = ctx.args["vlan"]
    native = "native" in ctx.path
    for iface in _targets(ctx):
        iface.encapsulation_vlan = vlan
        iface.encapsulation_native = native
    ctx.mark_dirty()
    return None
