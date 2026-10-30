"""Switching commands (Agent CMD-IFSW): switchport / STP / EtherChannel config
and the Layer-2 ``show`` family.

Configuration handlers run in the interface submodes (``switchport ...``,
``channel-group``, ``spanning-tree`` port settings), the VLAN submode (``name``)
and global config (``spanning-tree`` globals, ``vtp``); they mutate
:class:`~simulator.models.InterfaceState` / :class:`NodeState` fields and mark
the node dirty.

``show`` handlers register in EXEC (reachable from config via ``do``) and format
the live Layer-2 state computed by :class:`simulator.l2.L2Fabric` (reached via
``ctx.engines.l2``) into IOL 15.x-faithful text: ``show interfaces`` and its
``status`` / ``switchport`` / ``trunk`` / ``description`` variants, ``show vlan``,
``show mac address-table``, ``show spanning-tree``, ``show etherchannel`` and
``show lacp neighbor``.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

from ...models import (
    InterfaceState,
    canonical_interface,
    format_mac,
    interface_parent,
    natural_key,
)
from ..parser import (
    CONFIG,
    CONFIG_IF,
    CONFIG_IF_RANGE,
    CONFIG_VLAN,
    EXEC,
    command,
)

#: Interface submodes the switchport / STP-port / channel commands are valid in.
IF_MODES = (CONFIG_IF, CONFIG_IF_RANGE)


# =========================================================================== #
# Helpers                                                                     #
# =========================================================================== #
def _targets(ctx) -> List[InterfaceState]:
    target = ctx.target
    if isinstance(target, list):
        return [item for item in target if isinstance(item, InterfaceState)]
    if isinstance(target, InterfaceState):
        return [target]
    return []


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
    """Return the IOS short interface name (``Ethernet0/0`` -> ``Et0/0``)."""
    canonical = canonical_interface(name)
    for prefix, short in _SHORT_MAP:
        if canonical.startswith(prefix):
            return short + canonical[len(prefix):]
    return canonical


def _l2(ctx):
    bundle = ctx.engines
    return getattr(bundle, "l2", None) if bundle is not None else None


def _l3(ctx):
    bundle = ctx.engines
    return getattr(bundle, "l3", None) if bundle is not None else None


def _prefix_len(netmask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return 0


# =========================================================================== #
# Switchport configuration                                                    #
# =========================================================================== #
@command(
    "switchport mode (access|trunk|dynamic (auto|desirable))",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "mode": "Set trunking mode of the interface",
        "access": "Set trunking mode to ACCESS unconditionally",
        "trunk": "Set trunking mode to TRUNK unconditionally",
        "dynamic": "Set trunking mode to dynamically negotiate",
        "auto": "Set trunking mode dynamic negotiation parameter to AUTO",
        "desirable": "Set trunking mode dynamic negotiation parameter to DESIRABLE",
    },
)
def _switchport_mode(ctx):
    rest = ctx.path[2:]
    mode = "dynamic " + rest[1] if rest and rest[0] == "dynamic" else rest[0]
    for iface in _targets(ctx):
        iface.switchport_mode = mode
        iface.routed_port = False
        iface.configured = True
    ctx.mark_dirty()
    return None


@command(
    "[no] switchport",
    modes=IF_MODES,
    privilege=15,
    help={"no": "Negate a command or set its defaults", "switchport": "Set switching mode characteristics"},
)
def _switchport(ctx):
    for iface in _targets(ctx):
        if ctx.negate:
            iface.routed_port = True
            iface.switchport_mode = None
        else:
            iface.routed_port = False
            if iface.switchport_mode is None:
                iface.switchport_mode = "dynamic auto"
    ctx.mark_dirty()
    return None


@command(
    "switchport access vlan {id:<1-4094>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "access": "Set access mode characteristics of the interface",
        "vlan": "Set VLAN when interface is in access mode",
        "id": "VLAN ID of the VLAN when this port is in access mode",
    },
)
def _switchport_access_vlan(ctx):
    vlan = ctx.args["id"]
    for iface in _targets(ctx):
        iface.access_vlan = vlan
        iface.configured = True
    ctx.mark_dirty()
    node = ctx.node
    if vlan in node.vlans or vlan in _RESERVED_VLANS or node.vtp_mode == "client":
        # A VTP client cannot create VLANs: IOS keeps the port setting, and the
        # port stays inactive until the VLAN arrives.
        return None
    # IOS (VTP server or transparent) creates a missing access VLAN.
    node.vlans[vlan] = f"VLAN{vlan:04d}"
    return f"% Access VLAN does not exist. Creating vlan {vlan}"


@command(
    "switchport trunk encapsulation (dot1q|isl|negotiate)",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "trunk": "Set trunking characteristics of the interface",
        "encapsulation": "Set trunking encapsulation when interface is in trunking mode",
        "dot1q": "Interface uses only 802.1q trunking encapsulation when trunking",
        "isl": "Interface uses only ISL trunking encapsulation when trunking",
        "negotiate": "Device will negotiate trunking encapsulation with peer on interface",
    },
)
def _switchport_trunk_encapsulation(ctx):
    choice = ctx.path[-1]
    value = None if choice == "negotiate" else choice
    for iface in _targets(ctx):
        iface.trunk_encapsulation = value
        iface.configured = True
    ctx.mark_dirty()
    return None


@command(
    "switchport trunk native vlan {id:<1-4094>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "trunk": "Set trunking characteristics of the interface",
        "native": "Set trunking native characteristics when interface is in trunking mode",
        "vlan": "Set VLAN when interface is in access mode",
        "id": "VLAN ID of the native VLAN when this port is in trunking mode",
    },
)
def _switchport_trunk_native(ctx):
    vlan = ctx.args["id"]
    for iface in _targets(ctx):
        iface.trunk_native_vlan = vlan
        iface.configured = True
    ctx.mark_dirty()
    return None


@command(
    "switchport trunk allowed vlan (all|none|{ids:VLAN_LIST}|add {ids:VLAN_LIST}|remove {ids:VLAN_LIST})",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "trunk": "Set trunking characteristics of the interface",
        "allowed": "Set allowed VLAN characteristics when interface is in trunking mode",
        "vlan": "Set allowed VLANs when interface is in trunking mode",
        "all": "All VLANs",
        "none": "No VLANs",
        "add": "Add VLANs to the current list",
        "remove": "Remove VLANs from the current list",
        "ids": "VLAN IDs of the allowed VLANs",
    },
)
def _switchport_trunk_allowed(ctx):
    ids = ctx.args.get("ids")
    for iface in _targets(ctx):
        if "all" in ctx.path:
            iface.trunk_allowed_vlans = None
        elif "none" in ctx.path:
            iface.trunk_allowed_vlans = set()
        elif "add" in ctx.path:
            current = set(range(1, 4095)) if iface.trunk_allowed_vlans is None else set(iface.trunk_allowed_vlans)
            current.update(ids or [])
            iface.trunk_allowed_vlans = current
        elif "remove" in ctx.path:
            current = set(range(1, 4095)) if iface.trunk_allowed_vlans is None else set(iface.trunk_allowed_vlans)
            current.difference_update(ids or [])
            iface.trunk_allowed_vlans = current
        else:
            iface.trunk_allowed_vlans = set(ids or [])
        iface.configured = True
    ctx.mark_dirty()
    return None


@command(
    "[no] switchport nonegotiate",
    modes=IF_MODES,
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "switchport": "Set switching mode characteristics",
        "nonegotiate": "Device will not engage in negotiation protocol on this interface",
    },
)
def _switchport_nonegotiate(ctx):
    for iface in _targets(ctx):
        iface.nonegotiate = not ctx.negate
        iface.configured = True
    ctx.mark_dirty()
    return None


@command(
    "[no] switchport voice vlan {id:<1-4094>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "switchport": "Set switching mode characteristics",
        "voice": "Voice appliance attributes",
        "vlan": "Vlan for voice traffic",
        "id": "Vlan for voice traffic",
    },
)
def _switchport_voice_vlan(ctx):
    vlan = ctx.args["id"]
    for iface in _targets(ctx):
        iface.voice_vlan = None if ctx.negate else vlan
        iface.configured = True
    ctx.mark_dirty()
    return None


# ---- port-security -------------------------------------------------------- #
@command(
    "[no] switchport port-security",
    modes=IF_MODES,
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "switchport": "Set switching mode characteristics",
        "port-security": "Security related command",
    },
)
def _switchport_port_security(ctx):
    for iface in _targets(ctx):
        iface.port_security_enabled = not ctx.negate
    ctx.mark_dirty()
    return None


@command(
    "switchport port-security maximum {n:<1-4097>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "port-security": "Security related command",
        "maximum": "Max secure addresses",
        "n": "Maximum number of addresses",
    },
)
def _port_security_maximum(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.port_security_maximum = value
        iface.port_security_enabled = True
    ctx.mark_dirty()
    return None


@command(
    "switchport port-security violation (protect|restrict|shutdown)",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "port-security": "Security related command",
        "violation": "Security violation mode",
        "protect": "Security violation protect mode",
        "restrict": "Security violation restrict mode",
        "shutdown": "Security violation shutdown mode",
    },
)
def _port_security_violation(ctx):
    for iface in _targets(ctx):
        iface.port_security_violation = ctx.path[-1]
        iface.port_security_enabled = True
    ctx.mark_dirty()
    return None


@command(
    "switchport port-security mac-address sticky",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "port-security": "Security related command",
        "mac-address": "Secure mac address",
        "sticky": "Configure dynamic secure addresses as sticky",
    },
)
def _port_security_mac_sticky(ctx):
    for iface in _targets(ctx):
        iface.port_security_sticky = True
        iface.port_security_enabled = True
        # IOS converts the port's dynamic secure addresses to sticky ones.
        for entry in getattr(ctx.node, "mac_table", {}).values():
            if entry.port == iface.name and entry.secure == "dynamic":
                entry.secure = "sticky"
                mac = format_mac(entry.mac, "cisco")
                if mac not in iface.port_security_sticky_macs:
                    iface.port_security_sticky_macs.append(mac)
    ctx.mark_dirty()
    return None


@command(
    "switchport port-security mac-address {mac:H.H.H}",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "port-security": "Security related command",
        "mac-address": "Secure mac address",
        "mac": "48 bit mac address",
    },
)
def _port_security_mac_static(ctx):
    mac = ctx.args["mac"]
    for iface in _targets(ctx):
        if mac not in iface.port_security_macs:
            iface.port_security_macs.append(mac)
        iface.port_security_enabled = True
    ctx.mark_dirty()
    return None


@command(
    "switchport port-security sticky",
    modes=IF_MODES,
    privilege=15,
    help={
        "switchport": "Set switching mode characteristics",
        "port-security": "Security related command",
        "sticky": "Configure dynamic secure addresses as sticky",
    },
)
def _port_security_sticky(ctx):
    for iface in _targets(ctx):
        iface.port_security_sticky = True
        iface.port_security_enabled = True
    ctx.mark_dirty()
    return None


# ---- EtherChannel membership ---------------------------------------------- #
@command(
    "channel-group {n:<1-48>} mode (active|passive|on|desirable|auto)",
    modes=IF_MODES,
    privilege=15,
    help={
        "channel-group": "Etherchannel/port bundling configuration",
        "n": "Channel group number",
        "mode": "Etherchannel mode of the interface",
        "active": "Enable LACP unconditionally",
        "passive": "Enable LACP only if a LACP device is detected",
        "on": "Enable Etherchannel only",
        "desirable": "Enable PAgP unconditionally",
        "auto": "Enable PAgP only if a PAgP device is detected",
    },
)
def _channel_group(ctx):
    group = ctx.args["n"]
    mode = ctx.path[-1]
    node = ctx.node
    created = not node.has_interface(f"Port-channel{group}")
    for iface in _targets(ctx):
        iface.channel_group = group
        iface.channel_mode = mode
    node.ensure_interface(f"Port-channel{group}")
    ctx.mark_dirty()
    if created:
        return f"Creating a port-channel interface Port-channel {group}"
    return None


@command(
    "channel-protocol (lacp|pagp)",
    modes=IF_MODES,
    privilege=15,
    help={
        "channel-protocol": "Select the channel protocol (LACP, PAgP)",
        "lacp": "Prepare interface for LACP protocol",
        "pagp": "Prepare interface for PAgP protocol",
    },
)
def _channel_protocol(ctx):
    proto = ctx.path[-1]
    for iface in _targets(ctx):
        iface.channel_protocol = proto
    ctx.mark_dirty()
    return None


# ---- spanning-tree (interface) -------------------------------------------- #
@command(
    "spanning-tree portfast [disable]",
    modes=IF_MODES,
    privilege=15,
    help={
        "spanning-tree": "Spanning Tree Subsystem",
        "portfast": "Enable an interface to move directly to forwarding on link up",
        "disable": "Disable portfast for this interface",
    },
)
def _stp_portfast(ctx):
    disable = "disable" in ctx.path
    for iface in _targets(ctx):
        iface.stp_portfast = not disable
    ctx.mark_dirty()
    return None


@command(
    "spanning-tree bpduguard (enable|disable)",
    modes=IF_MODES,
    privilege=15,
    help={
        "spanning-tree": "Spanning Tree Subsystem",
        "bpduguard": "Don't accept BPDUs on this interface",
        "enable": "Enable BPDU guard for this interface",
        "disable": "Disable BPDU guard for this interface",
    },
)
def _stp_bpduguard(ctx):
    for iface in _targets(ctx):
        iface.stp_bpduguard = ctx.path[-1] == "enable"
    ctx.mark_dirty()
    return None


@command(
    "spanning-tree cost {n:<1-200000000>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "spanning-tree": "Spanning Tree Subsystem",
        "cost": "Change an interface's spanning tree port path cost",
        "n": "Port path cost",
    },
)
def _stp_cost(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.stp_cost = value
    ctx.mark_dirty()
    return None


@command(
    "spanning-tree port-priority {n:<0-240>}",
    modes=IF_MODES,
    privilege=15,
    help={
        "spanning-tree": "Spanning Tree Subsystem",
        "port-priority": "Change an interface's spanning tree port priority",
        "n": "Port priority in increments of 16",
    },
)
def _stp_port_priority(ctx):
    value = ctx.args["n"]
    for iface in _targets(ctx):
        iface.stp_port_priority = value
    ctx.mark_dirty()
    return None


# =========================================================================== #
# VLAN submode                                                                #
# =========================================================================== #
@command(
    "name {name:WORD}",
    modes=(CONFIG_VLAN,),
    privilege=15,
    help={"name": "Ascii name of the VLAN"},
)
def _vlan_name(ctx):
    name = ctx.args["name"]
    target = ctx.target
    ids = target if isinstance(target, list) else [target]
    for vlan_id in ids:
        if isinstance(vlan_id, int):
            ctx.node.vlans[vlan_id] = name
    ctx.mark_dirty()
    return None


# =========================================================================== #
# Global spanning-tree / VTP                                                  #
# =========================================================================== #
@command(
    "spanning-tree mode (pvst|rapid-pvst)",
    modes=(CONFIG,),
    privilege=15,
    help={
        "spanning-tree": "Spanning Tree Subsystem",
        "mode": "Spanning tree operating mode",
        "pvst": "Per-Vlan spanning tree mode",
        "rapid-pvst": "Per-Vlan rapid spanning tree mode",
    },
)
def _stp_mode(ctx):
    ctx.node.stp_mode = ctx.path[-1]
    ctx.mark_dirty()
    return None


@command(
    "spanning-tree vlan {ids:VLAN_LIST} priority {p:<0-61440>}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "spanning-tree": "Spanning Tree Subsystem",
        "vlan": "VLAN Switch Spanning Tree",
        "ids": "vlan range, example: 1,3-5,7,9-11",
        "priority": "Set the bridge priority for the spanning tree",
        "p": "bridge priority in increments of 4096",
    },
)
def _stp_vlan_priority(ctx):
    priority = ctx.args["p"]
    for vlan_id in ctx.args["ids"]:
        ctx.node.stp_priorities[vlan_id] = priority
    ctx.mark_dirty()
    return None


@command(
    "[no] spanning-tree portfast [bpduguard] default",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "spanning-tree": "Spanning Tree Subsystem",
        "portfast": "Spanning tree portfast options",
        "bpduguard": "Enable portfast bpdu guard by default on all portfast ports",
        "default": "Enable portfast by default on all access ports",
    },
)
def _stp_portfast_default(ctx):
    enabled = not ctx.negate
    if "bpduguard" in ctx.path:
        ctx.node.stp_bpduguard_default = enabled
    else:
        ctx.node.stp_portfast_default = enabled
    ctx.mark_dirty()
    return None


@command(
    "vtp mode (server|client|transparent)",
    modes=(CONFIG,),
    privilege=15,
    help={
        "vtp": "Configure global VTP state",
        "mode": "Configure VTP device mode",
        "server": "Set the device to VTP server mode",
        "client": "Set the device to VTP client mode",
        "transparent": "Set the device to VTP transparent mode",
    },
)
def _vtp_mode(ctx):
    ctx.node.vtp_mode = ctx.path[-1]
    ctx.mark_dirty()
    return None


@command(
    "vtp domain {name:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={"vtp": "Configure global VTP state", "domain": "Set the name of the VTP administrative domain"},
)
def _vtp_domain(ctx):
    ctx.node.vtp_domain = ctx.args["name"]
    ctx.mark_dirty()
    return None


# =========================================================================== #
# show interfaces  (full per-interface block)                                 #
# =========================================================================== #
def _hardware(name: str) -> str:
    if name.startswith("Vlan"):
        return "EtherSVI"
    if name.startswith("Loopback"):
        return "Loopback"
    if name.startswith("Port-channel"):
        return "EtherChannel"
    if name.startswith("Tunnel"):
        return "Tunnel"
    return "AmdP2"


def _default_bw(name: str) -> int:
    if name.startswith("Loopback"):
        return 8000000
    if name.startswith("Vlan"):
        return 1000000
    return 10000  # IOL Ethernet / Port-channel 10 Mbit


def _default_mtu(name: str) -> int:
    return 1514 if name.startswith("Loopback") else 1500


def _line_state(l2, node, name):
    if l2 is not None:
        try:
            return l2.line_state(node.name, name)
        except Exception:
            pass
    iface = node.interfaces.get(name)
    if iface is not None and iface.shutdown:
        return ("administratively down", "down")
    return ("up", "up")


def _render_interface(node, iface, l2) -> List[str]:
    name = iface.name
    status, protocol = _line_state(l2, node, name)
    is_sub = interface_parent(name) is not None
    is_loop = name.startswith("Loopback")
    is_vlan = name.startswith("Vlan")

    lines: List[str] = [f"{name} is {status}, line protocol is {protocol}"]

    mac = node.interface_mac(name)
    hw = _hardware(name)
    if mac and not is_loop:
        cisco = format_mac(mac, "cisco")
        lines.append(f"  Hardware is {hw}, address is {cisco} (bia {cisco})")
    else:
        lines.append(f"  Hardware is {hw}")

    if iface.description:
        lines.append(f"  Description: {iface.description}")

    if iface.ip_address and iface.netmask:
        lines.append(f"  Internet address is {iface.ip_address}/{_prefix_len(iface.netmask)}")

    mtu = iface.mtu or _default_mtu(name)
    bw = iface.bandwidth_kbps or _default_bw(name)
    dly = iface.delay_tens_usec * 10 if iface.delay_tens_usec else (5000 if is_loop else 1000)
    lines.append(f"  MTU {mtu} bytes, BW {bw} Kbit/sec, DLY {dly} usec,")
    lines.append("     reliability 255/255, txload 1/255, rxload 1/255")

    if is_sub and iface.encapsulation_vlan is not None:
        tag = iface.encapsulation_vlan
        if iface.encapsulation_native:
            lines.append(f"  Encapsulation 802.1Q Virtual LAN, Vlan ID {tag}, native")
        else:
            lines.append(f"  Encapsulation 802.1Q Virtual LAN, Vlan ID {tag}.")
    elif is_loop:
        lines.append("  Encapsulation LOOPBACK, loopback not set")
    elif is_vlan:
        lines.append("  Encapsulation ARPA, loopback not set")
    else:
        lines.append("  Encapsulation ARPA, loopback not set")
        lines.append(f"  Keepalive set ({iface.keepalive or 10} sec)")

    # Duplex / speed line for real physical Ethernet / Port-channel ports.
    if not is_sub and not is_loop and not is_vlan:
        duplex_map = {"auto": "Auto-duplex", "full": "Full-duplex", "half": "Half-duplex"}
        speed_map = {"auto": "Auto Speed", "10": "10Mb/s", "100": "100Mb/s", "1000": "1000Mb/s"}
        duplex = duplex_map.get(iface.duplex, "Auto-duplex")
        speed = speed_map.get(iface.speed, "Auto Speed")
        lines.append(f"  {duplex}, {speed}, media type is unknown")

    if not is_loop:
        lines.append("  ARP type: ARPA, ARP Timeout 04:00:00")

    lines.append("  Last input never, output never, output hang never")
    cleared = "never" if not iface.counters.cleared_at else "0:00:00"
    lines.append(f'  Last clearing of "show interface" counters {cleared}')
    lines.append("  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0")
    lines.append("  Queueing strategy: fifo")
    lines.append("  Output queue: 0/40 (size/max)")
    lines.append("  5 minute input rate 0 bits/sec, 0 packets/sec")
    lines.append("  5 minute output rate 0 bits/sec, 0 packets/sec")

    c = iface.counters
    lines.append(f"     {c.packets_in} packets input, {c.bytes_in} bytes, 0 no buffer")
    lines.append(f"     Received {c.broadcasts_in} broadcasts ({c.multicasts_in} IP multicasts)")
    lines.append("     0 runts, 0 giants, 0 throttles")
    lines.append(f"     {c.input_errors} input errors, {c.crc} CRC, 0 frame, 0 overrun, 0 ignored")
    lines.append("     0 input packets with dribble condition detected")
    lines.append(f"     {c.packets_out} packets output, {c.bytes_out} bytes, 0 underruns")
    lines.append(f"     {c.output_errors} output errors, {c.collisions} collisions, {c.interface_resets} interface resets")
    lines.append("     0 unknown protocol drops")
    lines.append("     0 babbles, 0 late collision, 0 deferred")
    lines.append("     0 lost carrier, 0 no carrier")
    lines.append("     0 output buffer failures, 0 output buffers swapped out")
    return lines


def _interface_names(node) -> List[str]:
    return sorted(node.interfaces, key=natural_key)


@command(
    "show interfaces [{intf:INTERFACE}]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "interfaces": "Interface status and configuration",
        "intf": "Interface name",
    },
)
def _show_interfaces(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    intf = ctx.args.get("intf")
    if intf is not None:
        if intf not in node.interfaces:
            return f"                              ^\n% Invalid input detected at '^' marker."
        names = [intf]
    else:
        names = _interface_names(node)
    blocks: List[str] = []
    for name in names:
        blocks.extend(_render_interface(node, node.interfaces[name], l2))
    return "\n".join(blocks)


# =========================================================================== #
# show interfaces status                                                      #
# =========================================================================== #
def _status_names(node) -> List[str]:
    names = []
    for name in sorted(node.interfaces, key=natural_key):
        if name.startswith(("Vlan", "Loopback")) or interface_parent(name):
            continue
        names.append(name)
    return names


@command(
    "show interfaces [{intf:INTERFACE}] status",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "interfaces": "Interface status and configuration",
        "intf": "Interface name",
        "status": "Show interface line status",
    },
)
def _show_interfaces_status(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    intf = ctx.args.get("intf")
    names = [intf] if intf is not None else _status_names(node)
    header = f"{'Port':<10}{'Name':<19}{'Status':<13}{'Vlan':<11}{'Duplex':>6}  {'Speed':>5} {'Type'}"
    rows = [header]
    duplex_map = {"auto": "auto", "full": "full", "half": "half"}
    for name in names:
        iface = node.interfaces.get(name)
        if iface is None:
            continue
        ps = l2.port_status(node.name, name) if l2 is not None else None
        if ps is not None:
            status_text = ps.status_text
            vlan_text = ps.vlan_text
        else:
            status_text = "connected" if not iface.shutdown else "disabled"
            vlan_text = "routed"
        desc = (iface.description or "")[:18]
        duplex = duplex_map.get(iface.duplex, "auto")
        speed = iface.speed if iface.speed != "auto" else "auto"
        rows.append(
            f"{_short(name):<10}{desc:<19}{status_text:<13}{vlan_text:<11}{duplex:>6}  {speed:>5} unknown"
        )
    return "\n".join(rows)


# =========================================================================== #
# show interfaces description                                                 #
# =========================================================================== #
@command(
    "show interfaces [{intf:INTERFACE}] description",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "interfaces": "Interface status and configuration",
        "intf": "Interface name",
        "description": "Show interface description",
    },
)
def _show_interfaces_description(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    intf = ctx.args.get("intf")
    names = [intf] if intf is not None else _interface_names(node)
    header = f"{'Interface':<30}{'Status':<21}{'Protocol':<11}Description"
    rows = [header]
    for name in names:
        iface = node.interfaces.get(name)
        if iface is None:
            continue
        status, protocol = _line_state(l2, node, name)
        status_short = {
            "administratively down": "admin down",
            "up": "up",
            "down": "down",
        }.get(status, status)
        proto_short = protocol.split(" ")[0]
        rows.append(f"{_short(name):<30}{status_short:<21}{proto_short:<11}{iface.description or ''}")
    return "\n".join(rows)


# =========================================================================== #
# show interfaces switchport                                                  #
# =========================================================================== #
def _switchport_block(info) -> List[str]:
    admin_mode = info.admin_mode
    oper_mode = info.oper_mode
    oper_map = {"static access": "static access", "trunk": "trunk", "down": "down", "routed": "routed"}
    admin_encap = info.admin_encapsulation
    if oper_mode == "trunk":
        oper_encap = {"802.1q": "dot1q", "isl": "isl", "n-isl": "isl"}.get(info.oper_encapsulation, "native")
    else:
        oper_encap = "native"

    def vlan_field(vlan: int) -> str:
        return f"{vlan} (default)" if vlan == 1 else str(vlan)

    lines = [
        f"Name: {_short(info.interface)}",
        f"Switchport: {'Enabled' if info.is_switchport else 'Disabled'}",
        f"Administrative Mode: {admin_mode}",
        f"Operational Mode: {oper_map.get(oper_mode, oper_mode)}",
        f"Administrative Trunking Encapsulation: {admin_encap}",
        f"Operational Trunking Encapsulation: {oper_encap}",
        f"Negotiation of Trunking: {'On' if info.negotiation else 'Off'}",
        f"Access Mode VLAN: {vlan_field(info.access_vlan)}",
        f"Trunking Native Mode VLAN: {vlan_field(info.native_vlan)}",
        "Administrative Native VLAN tagging: enabled",
        f"Voice VLAN: {info.voice_vlan if info.voice_vlan is not None else 'none'}",
    ]
    lines.extend(
        [
            "Administrative private-vlan host-association: none",
            "Administrative private-vlan mapping: none",
            "Administrative private-vlan trunk native VLAN: none",
            "Administrative private-vlan trunk Native VLAN tagging: enabled",
            "Administrative private-vlan trunk encapsulation: dot1q",
            "Administrative private-vlan trunk normal VLANs: none",
            "Administrative private-vlan trunk associations: none",
            "Administrative private-vlan trunk mappings: none",
            "Operational private-vlan: none",
        ]
    )
    if info.allowed_vlans is None or len(info.allowed_vlans) >= 4094:
        allowed = "ALL"
    else:
        allowed = _compress(info.allowed_vlans)
    lines.append(f"Trunking VLANs Enabled: {allowed}")
    lines.append("Pruning VLANs Enabled: 2-1001")
    lines.append("Capture Mode Disabled")
    lines.append("Capture VLANs Allowed: ALL")
    lines.append("")
    lines.append("Protected: false")
    lines.append("Unknown unicast blocked: disabled")
    lines.append("Unknown multicast blocked: disabled")
    lines.append("Appliance trust: none")
    return lines


@command(
    "show interfaces [{intf:INTERFACE}] switchport",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "interfaces": "Interface status and configuration",
        "intf": "Interface name",
        "switchport": "Show interface switchport information",
    },
)
def _show_interfaces_switchport(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    if l2 is None:
        return None
    intf = ctx.args.get("intf")
    names = [intf] if intf is not None else _status_names(node)
    blocks: List[str] = []
    for name in names:
        info = l2.switchport(node.name, name)
        if info is None:
            continue
        if blocks:
            blocks.append("")
        blocks.extend(_switchport_block(info))
    if not blocks:
        return None
    return "\n".join(blocks)


# =========================================================================== #
# show interfaces trunk                                                       #
# =========================================================================== #
@command(
    "show interfaces [{intf:INTERFACE}] trunk",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "interfaces": "Interface status and configuration",
        "intf": "Interface name",
        "trunk": "Show interface trunk information",
    },
)
def _show_interfaces_trunk(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    rows = l2.trunks(node.name) if l2 is not None else []
    intf = ctx.args.get("intf")
    if intf is not None:
        rows = [r for r in rows if r.interface == canonical_interface(intf)]
    if not rows:
        return None
    out: List[str] = []
    out.append(f"{'Port':<12}{'Mode':<17}{'Encapsulation':<15}{'Status':<14}{'Native vlan'}")
    for r in rows:
        out.append(f"{r.port:<12}{r.mode:<17}{r.encapsulation:<15}{r.status:<14}{r.native_vlan}")
    out.append("")
    out.append(f"{'Port':<12}{'Vlans allowed on trunk'}")
    for r in rows:
        out.append(f"{r.port:<12}{_compress(r.allowed_vlans)}")
    out.append("")
    out.append(f"{'Port':<12}{'Vlans allowed and active in management domain'}")
    for r in rows:
        out.append(f"{r.port:<12}{_compress(r.allowed_active_vlans) or 'none'}")
    out.append("")
    out.append(f"{'Port':<12}{'Vlans in spanning tree forwarding state and not pruned'}")
    for r in rows:
        fwd = _compress(r.forwarding_vlans)
        out.append(f"{r.port:<12}{fwd if fwd else 'none'}")
    return "\n".join(out)


# =========================================================================== #
# show vlan [brief | id N]                                                    #
# =========================================================================== #
_RESERVED_VLANS = {
    1002: ("fddi-default", "fddi", "act/unsup"),
    1003: ("token-ring-default", "tr", "act/unsup"),
    1004: ("fddinet-default", "fdnet", "act/unsup"),
    1005: ("trnet-default", "trnet", "act/unsup"),
}


def _compress(vlans) -> str:
    numbers = sorted({int(v) for v in vlans})
    if not numbers:
        return ""
    ranges: List[str] = []
    start = prev = numbers[0]
    for number in numbers[1:]:
        if number == prev + 1:
            prev = number
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = number
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


def _access_ports_by_vlan(node, l2) -> Dict[int, List[str]]:
    result: Dict[int, List[str]] = {}
    for name in sorted(node.interfaces, key=natural_key):
        iface = node.interfaces[name]
        if name.startswith(("Vlan", "Loopback")) or interface_parent(name):
            continue
        if iface.channel_group is not None:
            continue  # represented by its Port-channel
        info = l2.switchport(node.name, name) if l2 is not None else None
        if info is None or not info.is_switchport:
            continue
        if info.admin_mode == "trunk" or info.oper_mode in ("trunk", "routed"):
            continue
        result.setdefault(info.access_vlan, []).append(_short(name))
    return result


def _wrap_ports(ports: List[str], indent: int, width: int = 80) -> List[str]:
    if not ports:
        return [""]
    avail = width - indent
    lines: List[str] = []
    current = ""
    for port in ports:
        piece = port if not current else current + ", " + port
        if len(piece) > avail and current:
            lines.append(current)
            current = port
        else:
            current = piece
    if current:
        lines.append(current)
    return lines


def _vlan_brief_rows(node, l2, vlan_ids: List[int]) -> List[str]:
    port_map = _access_ports_by_vlan(node, l2)
    rows: List[str] = []
    for vid in vlan_ids:
        if vid in node.vlans:
            name = node.vlans[vid]
            status = "active"
        elif vid in _RESERVED_VLANS:
            name, _, status = _RESERVED_VLANS[vid]
        else:
            continue
        ports = port_map.get(vid, [])
        port_lines = _wrap_ports(ports, 48)
        first = f"{vid:<4} {name:<32} {status:<9} {port_lines[0]}".rstrip()
        rows.append(first)
        for extra in port_lines[1:]:
            rows.append(" " * 48 + extra)
    return rows


def _vlan_type_rows(node, vlan_ids: List[int]) -> List[str]:
    rows: List[str] = []
    for vid in vlan_ids:
        if vid in _RESERVED_VLANS:
            _, vtype, _ = _RESERVED_VLANS[vid]
        elif vid in node.vlans:
            vtype = "enet"
        else:
            continue
        said = 100000 + vid
        stp = "ieee" if vid == 1004 else ("ibm" if vid == 1005 else "-")
        rows.append(
            f"{vid:<4} {vtype:<5} {said:<10} {1500:<5} {'-':<6} {'-':<6} {'-':<8} {stp:<4} {'-':<8} {0:<6} {0}"
        )
    return rows


def _vlan_ids_for_show(node) -> List[int]:
    ids = sorted(v for v in node.vlans)
    ids += [v for v in sorted(_RESERVED_VLANS) if v not in node.vlans]
    return ids


@command(
    "show vlan brief",
    modes=(EXEC,),
    privilege=1,
    help={"show": "Show running system information", "vlan": "VTP VLAN status", "brief": "VTP all VLAN status in brief"},
)
def _show_vlan_brief(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    out = [
        f"{'VLAN':<4} {'Name':<32} {'Status':<9} {'Ports'}",
        f"{'----':<4} {'-' * 32} {'-' * 9} {'-' * 31}",
    ]
    out.extend(_vlan_brief_rows(node, l2, _vlan_ids_for_show(node)))
    return "\n".join(out)


@command(
    "show vlan",
    modes=(EXEC,),
    privilege=1,
    help={"show": "Show running system information", "vlan": "VTP VLAN status"},
)
def _show_vlan(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    vlan_ids = _vlan_ids_for_show(node)
    out = [
        f"{'VLAN':<4} {'Name':<32} {'Status':<9} {'Ports'}",
        f"{'----':<4} {'-' * 32} {'-' * 9} {'-' * 31}",
    ]
    out.extend(_vlan_brief_rows(node, l2, vlan_ids))
    out.append("")
    out.append(
        f"{'VLAN':<4} {'Type':<5} {'SAID':<10} {'MTU':<5} {'Parent':<6} {'RingNo':<6} "
        f"{'BridgeNo':<8} {'Stp':<4} {'BrdgMode':<8} {'Trans1':<6} {'Trans2'}"
    )
    out.append(
        f"{'----':<4} {'-' * 5} {'-' * 10} {'-' * 5} {'-' * 6} {'-' * 6} {'-' * 8} "
        f"{'-' * 4} {'-' * 8} {'-' * 6} {'-' * 6}"
    )
    out.extend(_vlan_type_rows(node, vlan_ids))
    out.append("")
    out.append("Remote SPAN VLANs")
    out.append("-" * 78)
    out.append("")
    out.append("")
    out.append(f"{'Primary':<7} {'Secondary':<9} {'Type':<17} {'Ports'}")
    out.append(f"{'-' * 7} {'-' * 9} {'-' * 17} {'-' * 42}")
    return "\n".join(out)


@command(
    "show vlan id {id:<1-4094>}",
    modes=(EXEC,),
    privilege=1,
    help={"show": "Show running system information", "vlan": "VTP VLAN status", "id": "VTP VLAN ID 1-4094", },
)
def _show_vlan_id(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    vid = ctx.args["id"]
    if vid not in node.vlans and vid not in _RESERVED_VLANS:
        return f"VLAN id {vid} not found in current VLAN database"
    out = [
        f"{'VLAN':<4} {'Name':<32} {'Status':<9} {'Ports'}",
        f"{'----':<4} {'-' * 32} {'-' * 9} {'-' * 31}",
    ]
    out.extend(_vlan_brief_rows(node, l2, [vid]))
    out.append("")
    out.append(
        f"{'VLAN':<4} {'Type':<5} {'SAID':<10} {'MTU':<5} {'Parent':<6} {'RingNo':<6} "
        f"{'BridgeNo':<8} {'Stp':<4} {'BrdgMode':<8} {'Trans1':<6} {'Trans2'}"
    )
    out.append(
        f"{'----':<4} {'-' * 5} {'-' * 10} {'-' * 5} {'-' * 6} {'-' * 6} {'-' * 8} "
        f"{'-' * 4} {'-' * 8} {'-' * 6} {'-' * 6}"
    )
    out.extend(_vlan_type_rows(node, [vid]))
    return "\n".join(out)


# =========================================================================== #
# show mac address-table                                                      #
# =========================================================================== #
@command(
    "show mac address-table",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "mac": "MAC configuration",
        "address-table": "MAC forwarding table",
    },
)
def _show_mac_address_table(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    entries = l2.mac_table(node.name) if l2 is not None else []
    out = [
        "          Mac Address Table",
        "-" * 43,
        "",
        f"{'Vlan':<4}    {'Mac Address':<18}{'Type':<12}{'Ports'}",
        f"{'----':<4}    {'-' * 11:<18}{'-' * 8:<12}{'-' * 5}",
    ]
    for e in entries:
        out.append(f"{e.vlan:>4}    {e.mac:<18}{e.type:<12}{e.port}")
    out.append(f"Total Mac Addresses for this criterion: {len(entries)}")
    return "\n".join(out)


# =========================================================================== #
# show spanning-tree [vlan N | summary]                                       #
# =========================================================================== #
def _stp_protocol(node) -> str:
    return "rstp" if node.stp_mode == "rapid-pvst" else "ieee"


def _stp_vlan_block(node, info) -> List[str]:
    lines = [f"VLAN{info.vlan:04d}"]
    lines.append(f"  Spanning tree enabled protocol {_stp_protocol(node)}")
    # Root ID block.
    lines.append(f"  Root ID    Priority    {info.root_priority}")
    lines.append(f"             Address     {info.root_address}")
    if info.is_root:
        lines.append("             This bridge is the root")
        lines.append(
            f"             Hello Time   {info.hello_time} sec  Max Age {info.max_age} sec  "
            f"Forward Delay {info.forward_delay} sec"
        )
    else:
        lines.append(f"             Cost        {info.root_cost}")
        root_port = next((p for p in info.ports if p.role == "Root"), None)
        if root_port is not None:
            long_name = canonical_interface(root_port.interface)
            lines.append(f"             Port        {root_port.port_number} ({long_name})")
        lines.append(
            f"             Hello Time   {info.hello_time} sec  Max Age {info.max_age} sec  "
            f"Forward Delay {info.forward_delay} sec"
        )
    lines.append("")
    # Bridge ID block.
    base_priority = info.bridge_priority - info.vlan
    lines.append(
        f"  Bridge ID  Priority    {info.bridge_priority}  "
        f"(priority {base_priority} sys-id-ext {info.vlan})"
    )
    lines.append(f"             Address     {info.bridge_address}")
    lines.append(
        f"             Hello Time   {info.hello_time} sec  Max Age {info.max_age} sec  "
        f"Forward Delay {info.forward_delay} sec"
    )
    lines.append(f"             Aging Time  {info.aging_time} sec")
    lines.append("")
    lines.append(f"{'Interface':<19} {'Role':<4} {'Sts':<3} {'Cost':<9} {'Prio.Nbr':<8} {'Type'}")
    lines.append(f"{'-' * 19} {'-' * 4} {'-' * 3} {'-' * 9} {'-' * 8} {'-' * 32}")
    for p in info.ports:
        lines.append(
            f"{p.port:<19} {p.role:<4} {p.state:<3} {p.cost:<9} {p.prio_nbr:<8} {p.type}"
        )
    return lines


@command(
    "show spanning-tree",
    modes=(EXEC,),
    privilege=1,
    help={"show": "Show running system information", "spanning-tree": "Spanning tree topology"},
)
def _show_spanning_tree(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    if l2 is None or node.kind != "switch":
        return "No spanning tree instance exists."
    vlans = l2.stp_vlans(node.name)
    if not vlans:
        return "No spanning tree instance exists."
    blocks: List[str] = []
    for vlan in vlans:
        info = l2.stp(node.name, vlan)
        if info is None:
            continue
        if blocks:
            blocks.append("")
            blocks.append("")
        blocks.extend(_stp_vlan_block(node, info))
    return "\n".join(blocks)


@command(
    "show spanning-tree vlan {id:<1-4094>}",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "spanning-tree": "Spanning tree topology",
        "vlan": "VLAN Switch Spanning Trees",
        "id": "vlan range, example: 1,3-5,7,9-11",
    },
)
def _show_spanning_tree_vlan(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    vid = ctx.args["id"]
    if l2 is None or node.kind != "switch":
        return "No spanning tree instance exists."
    info = l2.stp(node.name, vid)
    if info is None:
        return f"No spanning tree instance for VLAN {vid:04d} exists."
    return "\n".join(_stp_vlan_block(node, info))


@command(
    "show spanning-tree summary",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "spanning-tree": "Spanning tree topology",
        "summary": "Summary of port states",
    },
)
def _show_spanning_tree_summary(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    if l2 is None or node.kind != "switch":
        return "Spanning tree enabled protocol ieee"
    vlans = l2.stp_vlans(node.name)
    root_of = []
    stats = []
    tot_blk = tot_fwd = tot_active = 0
    for vlan in vlans:
        info = l2.stp(node.name, vlan)
        if info is None:
            continue
        if info.is_root:
            root_of.append(f"VLAN{vlan:04d}")
        blk = sum(1 for p in info.ports if p.state == "BLK")
        fwd = sum(1 for p in info.ports if p.state == "FWD")
        active = len(info.ports)
        tot_blk += blk
        tot_fwd += fwd
        tot_active += active
        stats.append((f"VLAN{vlan:04d}", blk, 0, 0, fwd, active))

    mode = "rapid-pvst" if node.stp_mode == "rapid-pvst" else "pvst"
    out = [f"Switch is in {mode} mode"]
    out.append(f"Root bridge for: {', '.join(root_of) if root_of else 'none'}")
    out.append(f"{'Extended system ID':<38} is enabled")
    out.append(f"{'Portfast Default':<38} is {'enabled' if node.stp_portfast_default else 'disabled'}")
    out.append(f"{'PortFast BPDU Guard Default':<38} is {'enabled' if node.stp_bpduguard_default else 'disabled'}")
    out.append(f"{'Portfast BPDU Filter Default':<38} is disabled")
    out.append(f"{'Loopguard Default':<38} is disabled")
    out.append(f"{'EtherChannel misconfig guard':<38} is enabled")
    out.append(f"{'UplinkFast':<38} is disabled")
    out.append(f"{'BackboneFast':<38} is disabled")
    out.append("Configured Pathcost method used is short")
    out.append("")
    out.append(f"{'Name':<22} {'Blocking':>8} {'Listening':>9} {'Learning':>8} {'Forwarding':>10} {'STP Active':>10}")
    out.append(f"{'-' * 22} {'-' * 8} {'-' * 9} {'-' * 8} {'-' * 10} {'-' * 10}")
    for name, blk, lis, lrn, fwd, active in stats:
        out.append(f"{name:<22} {blk:>8} {lis:>9} {lrn:>8} {fwd:>10} {active:>10}")
    out.append(f"{'-' * 22} {'-' * 8} {'-' * 9} {'-' * 8} {'-' * 10} {'-' * 10}")
    label = f"{len(stats)} vlan" + ("s" if len(stats) != 1 else "")
    out.append(f"{label:<22} {tot_blk:>8} {0:>9} {0:>8} {tot_fwd:>10} {tot_active:>10}")
    return "\n".join(out)


# =========================================================================== #
# show etherchannel summary / port-channel                                    #
# =========================================================================== #
_ETHERCHANNEL_FLAGS = (
    "Flags:  D - down        P - bundled in port-channel\n"
    "        I - stand-alone s - suspended\n"
    "        H - Hot-standby (LACP only)\n"
    "        R - Layer3      S - Layer2\n"
    "        U - in use      f - failed to allocate aggregator\n"
    "\n"
    "        M - not in use, minimum links not met\n"
    "        u - unsuitable for bundling\n"
    "        w - waiting to be aggregated\n"
    "        d - default port\n"
    "\n"
    "        A - formed by Auto LAG\n"
)


@command(
    "show etherchannel summary",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "etherchannel": "EtherChannel information",
        "summary": "One-line summary per channel-group",
    },
)
def _show_etherchannel_summary(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    channels = l2.etherchannels(node.name) if l2 is not None else []
    in_use = sum(1 for c in channels if c.in_use)
    out = [_ETHERCHANNEL_FLAGS]
    out.append(f"Number of channel-groups in use: {in_use}")
    out.append(f"Number of aggregators:           {len(channels)}")
    out.append("")
    out.append(f"{'Group':<6} {'Port-channel':<13} {'Protocol':<11} {'Ports'}")
    out.append(f"{'-' * 6}+{'-' * 13}+{'-' * 11}+{'-' * 47}")
    for c in channels:
        po_display = f"{c.port}({c.flags})"
        proto = c.protocol if c.protocol != "-" else "-"
        members = [f"{m.port}({m.flags})" for m in c.members]
        member_lines = _wrap_member_ports(members)
        first = member_lines[0] if member_lines else ""
        out.append(f"{str(c.group):<7}{po_display:<16}{proto:<10}{first}")
        for extra in member_lines[1:]:
            out.append(" " * 33 + extra)
    return "\n".join(out)


def _wrap_member_ports(members: List[str], per_line: int = 4) -> List[str]:
    if not members:
        return [""]
    lines: List[str] = []
    for i in range(0, len(members), per_line):
        chunk = members[i:i + per_line]
        lines.append("".join(f"{m:<12}" for m in chunk).rstrip())
    return lines


@command(
    "show etherchannel port-channel",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "etherchannel": "EtherChannel information",
        "port-channel": "Port-channel information",
    },
)
def _show_etherchannel_portchannel(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    channels = l2.etherchannels(node.name) if l2 is not None else []
    out = ["                Channel-group listing:", "                ----------------------", ""]
    for c in channels:
        out.append(f"Group: {c.group}")
        out.append("----------")
        out.append("Port-channels in the group:")
        out.append("---------------------------")
        out.append("")
        out.append(f"Port-channel: {c.port}    ({'Primary Aggregator' if c.in_use else 'Not Aggregated'})")
        out.append("")
        out.append("------------")
        proto = c.protocol if c.protocol != "-" else "-"
        out.append(f"Age of the Port-channel   = 0d:00h:00m:00s")
        out.append(f"Logical slot/port   = 16/{c.group}          Number of ports = {len(c.members)}")
        out.append(f"Port state          = Port-channel {'Ag-Inuse' if c.in_use else 'Ag-Not-Inuse'}")
        out.append(f"Protocol            =   {proto}")
        out.append(f"Port security       = Disabled")
        out.append("")
        out.append("Ports in the Port-channel:")
        out.append("")
        out.append(f"{'Index':<7} {'Load':<6} {'Port':<8} {'EC state':<17} {'No of bits'}")
        out.append(f"{'-' * 6}+{'-' * 6}+{'-' * 6}+{'-' * 18}+{'-' * 11}")
        ec_state = {"LACP": "Active", "PAgP": "Desirable-Sl", "-": "On"}.get(c.protocol, "On")
        for m in c.members:
            state = ec_state if m.bundled else "Not-in-Bndl"
            out.append(f"{'00':<7} {'00':<6} {m.port:<8} {state:<17} {'0'}")
        out.append("")
    if not channels:
        out.append("")
    return "\n".join(out)


# =========================================================================== #
# show lacp neighbor                                                          #
# =========================================================================== #
_LACP_FLAGS = (
    "Flags:  S - Device is requesting Slow LACPDUs\n"
    "        F - Device is requesting Fast LACPDUs\n"
    "        A - Device is in Active mode       P - Device is in Passive mode\n"
)


@command(
    "show lacp neighbor",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "lacp": "LACP information",
        "neighbor": "Display LACP neighbor information",
    },
)
def _show_lacp_neighbor(ctx):
    node = ctx.node
    l2 = _l2(ctx)
    if l2 is None:
        return None
    channels = l2.etherchannels(node.name)
    out = [_LACP_FLAGS]
    any_group = False
    for c in channels:
        if c.protocol != "LACP":
            continue
        neighbors = l2.lacp_neighbors(node.name, c.group)
        if not neighbors:
            continue
        any_group = True
        out.append(f"Channel group {c.group} neighbors")
        out.append("")
        out.append("Partner's information:")
        out.append("")
        out.append(
            f"                  {'LACP port':<16}               {'Oper':<8}{'Port':<12}{'Port'}"
        )
        out.append(
            f"{'Port':<10}{'Flags':<8}{'Priority':<10}{'Dev ID':<16}{'Age':<7}{'Key':<8}{'Number':<12}{'State'}"
        )
        for nb in neighbors:
            state = "0x3D" if nb.flags.endswith("A") else "0x35"
            out.append(
                f"{nb.interface:<10}{nb.flags:<8}{nb.partner_port_priority:<10}"
                f"{nb.partner_mac:<16}{'0s':<7}0x{nb.partner_oper_key:<6x}"
                f"0x{nb.partner_port_number:<10x}{state}"
            )
        out.append("")
    if not any_group:
        return _LACP_FLAGS.rstrip("\n")
    return "\n".join(out)
