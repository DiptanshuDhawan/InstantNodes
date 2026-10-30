"""Configuration commands needed for config replay and legacy parity (Phase 2, A3).

Three groups, all auto-discovered by :func:`simulator.ios.commands.ensure_registered`:

* **Renderer boilerplate** -- global lines that :mod:`simulator.ios.render` emits in
  every running-config (``version 15.7``, ``boot-start-marker``, ``ip cef`` ...).
  They are accepted as no-ops so a rendered config replays cleanly (``reload``,
  ``copy startup-config running-config``, authored configs pasted from a show).
* **Negations used by the authored lab startup configs** -- ``default interface``,
  ``no interface``, ``no vlan``, ``no router ospf``, ``no ip dhcp pool``.
* **Legacy parity** -- forms the retired ``cli.py`` accepted that no Phase 2
  module registered (``no channel-group``, ``no encapsulation dot1Q``,
  ``no switchport access vlan``, ``no name``, ``crypto key generate rsa
  general-keys``) plus the matching ``no`` forms of interface, DHCP-pool and
  switchport settings so a user can undo what they typed.

Handlers mutate ``ctx.node`` / ``ctx.target`` and call ``ctx.mark_dirty()``; no-op
handlers change nothing.
"""

from __future__ import annotations

from typing import List

from ...models import InterfaceState, interface_parent, is_physical_interface
from ..parser import (
    CONFIG,
    CONFIG_IF,
    CONFIG_IF_RANGE,
    CONFIG_SUBIF,
    CONFIG_VLAN,
    DHCP_CONFIG,
    command,
)

#: Modes in which per-interface ``no`` forms are valid (matches interfaces.py).
_IF_ALL = (CONFIG_IF, CONFIG_IF_RANGE, CONFIG_SUBIF)
#: Switchport modes (matches switching.py's IF_MODES).
_IF_L2 = (CONFIG_IF, CONFIG_IF_RANGE)

_NO = "Negate a command or set its defaults"
#: VLANs IOS refuses to delete.
_DEFAULT_VLANS = (1, 1002, 1003, 1004, 1005)


def _targets(ctx) -> List[InterfaceState]:
    target = ctx.target
    if isinstance(target, list):
        return [item for item in target if isinstance(item, InterfaceState)]
    if isinstance(target, InterfaceState):
        return [target]
    return []


def _noop(ctx):
    return None


# =========================================================================== #
# Renderer boilerplate (accepted, no state change)                            #
# =========================================================================== #
_BOILERPLATE = (
    ("version {v:WORD}", {"version": "Version", "v": "Version number"}),
    ("boot-start-marker", {"boot-start-marker": "Boot Start Marker"}),
    ("boot-end-marker", {"boot-end-marker": "Boot End Marker"}),
    ("no aaa new-model", {"no": _NO, "aaa": "Authentication, Authorization and Accounting.",
                          "new-model": "Enable NEW access control commands and functions."}),
    ("[no] ip cef", {"no": _NO, "ip": "Global IP configuration subcommands",
                     "cef": "Cisco Express Forwarding"}),
    ("[no] ipv6 cef", {"no": _NO, "ipv6": "Global IPv6 configuration commands",
                       "cef": "Cisco Express Forwarding"}),
    ("multilink bundle-name authenticated",
     {"multilink": "PPP multilink global configuration",
      "bundle-name": "Select method for naming multilink bundles",
      "authenticated": "Use peer's authenticated name"}),
    ("redundancy", {"redundancy": "Enter redundancy mode"}),
    ("control-plane", {"control-plane": "Configure control plane services"}),
    ("[no] ip forward-protocol nd", {"no": _NO, "ip": "Global IP configuration subcommands",
                                     "forward-protocol": "Controls forwarding of physical and directed IP broadcasts",
                                     "nd": "Sun's Network Disk protocol"}),
    ("[no] service compress-config", {"no": _NO, "service": "Modify use of network based services",
                                      "compress-config": "Compress the configuration file"}),
    ("spanning-tree extend system-id", {"spanning-tree": "Spanning Tree Subsystem",
                                        "extend": "Spanning Tree 802.1t extensions",
                                        "system-id": "Extend system-id into priority portion of the bridge id (PVST & Rapid PVST)"}),
    ("vlan internal allocation policy (ascending|descending)",
     {"vlan": "VLAN commands", "internal": "internal VLAN",
      "allocation": "internal VLAN allocation", "policy": "internal VLAN allocation policy",
      "ascending": "ascending allocation of internal VLANs",
      "descending": "descending allocation of internal VLANs"}),
    ("logging discriminator {name:WORD} {rest:LINE}",
     {"logging": "Modify message logging facilities",
      "discriminator": "Create or modify a message discriminator",
      "name": "discriminator name", "rest": "Discriminator match criteria"}),
    ("logging console discriminator {name:WORD}",
     {"logging": "Modify message logging facilities",
      "console": "Set console logging parameters",
      "discriminator": "Establish MD-Console association", "name": "discriminator name"}),
    ("mmi polling-interval {n:<1-65535>}", {"mmi": "Configure MMI", "polling-interval": "Polling interval",
                                            "n": "Polling interval in seconds"}),
    ("no mmi auto-configure", {"no": _NO, "mmi": "Configure MMI", "auto-configure": "Auto-configure"}),
    ("no mmi pvc", {"no": _NO, "mmi": "Configure MMI", "pvc": "PVC"}),
    ("mmi snmp-timeout {n:<1-65535>}", {"mmi": "Configure MMI", "snmp-timeout": "SNMP timeout",
                                        "n": "Timeout in seconds"}),
)

for _pattern, _help in _BOILERPLATE:
    command(_pattern, modes=(CONFIG,), privilege=15, help=_help)(_noop)


@command(
    "[no] ip http (server|secure-server)",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "ip": "Global IP configuration subcommands", "http": "HTTP server configuration",
          "server": "Enable HTTP server", "secure-server": "Enable HTTP secure server"},
)
def _ip_http(ctx):
    """Stored and shown in the running-config; no HTTP service is simulated."""
    attribute = "ip_http_server" if ctx.path[-1] == "server" else "ip_http_secure_server"
    setattr(ctx.node, attribute, not ctx.negate)
    ctx.mark_dirty()
    return None


# =========================================================================== #
# Negations used by authored startup configs                                  #
# =========================================================================== #
@command(
    "default interface {intf:INTERFACE}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "default": "Set a command to its defaults",
        "interface": "Select an interface to configure",
        "intf": "Interface to default",
    },
)
def _default_interface(ctx):
    name = ctx.args["intf"]
    ctx.node.default_interface(name)
    ctx.mark_dirty()
    return f"Interface {name} set to default configuration"


@command(
    "no interface {intf:INTERFACE}",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "interface": "Select an interface to configure", "intf": "Interface to delete"},
)
def _no_interface(ctx):
    name = ctx.args["intf"]
    node = ctx.node
    if interface_parent(name) is None and is_physical_interface(name):
        return "% Physical interfaces cannot be removed"
    if name.startswith("Port-channel"):
        try:
            group = int(name[len("Port-channel"):])
        except ValueError:
            group = None
        for iface in node.interfaces.values():
            if group is not None and iface.channel_group == group:
                iface.channel_group = None
                iface.channel_mode = None
    node.remove_interface(name)
    ctx.mark_dirty()
    return None


@command(
    "no vlan {ids:VLAN_LIST}",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "vlan": "VLAN commands", "ids": "ISL VLAN IDs 1-4094"},
)
def _no_vlan(ctx):
    messages = []
    for vlan_id in ctx.args["ids"]:
        if vlan_id in _DEFAULT_VLANS:
            messages.append(f"%Default VLAN {vlan_id} may not be deleted.")
            continue
        ctx.node.vlans.pop(vlan_id, None)
    ctx.mark_dirty()
    return "\n".join(messages) if messages else None


@command(
    "no router ospf {pid:<1-65535>}",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "router": "Enable a routing process",
          "ospf": "Open Shortest Path First (OSPF)", "pid": "Process ID"},
)
def _no_router_ospf(ctx):
    pid = ctx.args["pid"]
    node = ctx.node
    node.ospf_processes.pop(pid, None)
    # IOS removes the interface-level "ip ospf <pid> area <a>" with the process.
    for iface in node.interfaces.values():
        if iface.ospf_process == pid:
            iface.ospf_process = None
            iface.ospf_area = None
    ctx.mark_dirty()
    return None


@command(
    "no ip dhcp pool {name:WORD}",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "ip": "Global IP configuration subcommands",
          "dhcp": "Configure DHCP server and relay parameters",
          "pool": "Configure DHCP address pools", "name": "Pool name"},
)
def _no_ip_dhcp_pool(ctx):
    wanted = ctx.args["name"].lower()
    pools = ctx.node.dhcp_pools
    for name in [name for name in pools if name.lower() == wanted]:
        pools.pop(name)
    ctx.mark_dirty()
    return None


@command(
    "no ip default-gateway",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "ip": "Global IP configuration subcommands",
          "default-gateway": "Specify default gateway (if not routing IP)"},
)
def _no_ip_default_gateway(ctx):
    ctx.node.default_gateway = None
    ctx.mark_dirty()
    return None


# =========================================================================== #
# Legacy parity: interface / switchport negations                             #
# =========================================================================== #
@command(
    "no channel-group [{n:<1-48>} [mode (active|passive|on|desirable|auto)]]",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "channel-group": "Etherchannel/port bundling configuration",
          "n": "Channel group number", "mode": "Etherchannel Mode of the interface"},
)
def _no_channel_group(ctx):
    for iface in _targets(ctx):
        iface.channel_group = None
        iface.channel_mode = None
    ctx.mark_dirty()
    return None


@command(
    "no channel-protocol [(lacp|pagp)]",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "channel-protocol": "Select the channel protocol (LACP, PAgP)",
          "lacp": "Prepare interface for LACP protocol", "pagp": "Prepare interface for PAgP protocol"},
)
def _no_channel_protocol(ctx):
    for iface in _targets(ctx):
        iface.channel_protocol = None
    ctx.mark_dirty()
    return None


@command(
    "no line vty {first:<0-15>} [{last:<0-15>}]",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "line": "Configure a terminal line", "vty": "Virtual terminal",
          "first": "First line number", "last": "Last line number"},
)
def _no_line_vty(ctx):
    """Delete added VTY lines (5 and up); the five default lines stay."""
    first = int(ctx.args["first"])
    last = int(ctx.args.get("last", first))
    first, last = min(first, last), max(first, last)
    if first <= 4:
        return "% Not all lines may be deleted"
    # Split blocks at the range edges, then drop the lines inside the range.
    for line in ctx.node.vty_range(first, last):
        ctx.node.lines.pop(line.name, None)
    ctx.mark_dirty()
    return None


@command(
    "no encapsulation dot1Q [{vlan:<1-4094>}] [native]",
    modes=(CONFIG_SUBIF,),
    privilege=15,
    help={"no": _NO, "encapsulation": "Set encapsulation type for an interface",
          "dot1Q": "IEEE 802.1Q Virtual LAN", "vlan": "IEEE 802.1Q VLAN ID",
          "native": "Make this as native vlan"},
)
def _no_encapsulation(ctx):
    for iface in _targets(ctx):
        iface.encapsulation_vlan = None
        iface.encapsulation_native = False
    ctx.mark_dirty()
    return None


@command(
    "no switchport access vlan [{id:<1-4094>}]",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "switchport": "Set switching mode characteristics",
          "access": "Set access mode characteristics of the interface",
          "vlan": "Set VLAN when interface is in access mode", "id": "VLAN ID of the VLAN when this port is in access mode"},
)
def _no_switchport_access_vlan(ctx):
    for iface in _targets(ctx):
        iface.access_vlan = 1
    ctx.mark_dirty()
    return None


@command(
    "no switchport trunk native vlan [{id:<1-4094>}]",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "switchport": "Set switching mode characteristics",
          "trunk": "Set trunking characteristics of the interface",
          "native": "Set trunking native characteristics when interface is in trunking mode",
          "vlan": "Set native VLAN when interface is in trunking mode", "id": "VLAN ID of the native VLAN"},
)
def _no_switchport_trunk_native(ctx):
    for iface in _targets(ctx):
        iface.trunk_native_vlan = 1
    ctx.mark_dirty()
    return None


@command(
    "no switchport trunk allowed vlan",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "switchport": "Set switching mode characteristics",
          "trunk": "Set trunking characteristics of the interface",
          "allowed": "Set allowed VLAN characteristics when interface is in trunking mode",
          "vlan": "Set allowed VLANs when interface is in trunking mode"},
)
def _no_switchport_trunk_allowed(ctx):
    for iface in _targets(ctx):
        iface.trunk_allowed_vlans = None
    ctx.mark_dirty()
    return None


@command(
    "no switchport trunk encapsulation",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "switchport": "Set switching mode characteristics",
          "trunk": "Set trunking characteristics of the interface",
          "encapsulation": "Set trunking encapsulation when interface is in trunking mode"},
)
def _no_switchport_trunk_encapsulation(ctx):
    for iface in _targets(ctx):
        iface.trunk_encapsulation = None
    ctx.mark_dirty()
    return None


def _reset_attr(attribute: str, value):
    def handler(ctx):
        for iface in _targets(ctx):
            setattr(iface, attribute, value)
        ctx.mark_dirty()
        return None

    return handler


#: (pattern, modes, attribute, default value, help)
_INTERFACE_RESETS = (
    ("no speed", _IF_ALL, "speed", "auto", {"speed": "Configure speed operation."}),
    ("no duplex", _IF_ALL, "duplex", "auto", {"duplex": "Configure duplex operation."}),
    ("no mtu", _IF_ALL, "mtu", None, {"mtu": "Set the interface Maximum Transmission Unit (MTU)"}),
    ("no bandwidth", _IF_ALL, "bandwidth_kbps", None, {"bandwidth": "Set bandwidth informational parameter"}),
    ("no delay", _IF_ALL, "delay_tens_usec", None, {"delay": "Specify interface throughput delay"}),
    ("no ip ospf cost", _IF_ALL, "ospf_cost", None, {"ip": "Interface Internet Protocol config commands",
                                                      "ospf": "OSPF interface commands", "cost": "Interface cost"}),
    ("no ip ospf priority", _IF_ALL, "ospf_priority", None, {"ip": "Interface Internet Protocol config commands",
                                                              "ospf": "OSPF interface commands", "priority": "Router priority"}),
    ("no ip ospf hello-interval", _IF_ALL, "ospf_hello_interval", None,
     {"ip": "Interface Internet Protocol config commands", "ospf": "OSPF interface commands",
      "hello-interval": "Time between HELLO packets"}),
    ("no ip ospf dead-interval", _IF_ALL, "ospf_dead_interval", None,
     {"ip": "Interface Internet Protocol config commands", "ospf": "OSPF interface commands",
      "dead-interval": "Interval after which a neighbor is declared dead"}),
    ("no ip ospf network", _IF_ALL, "ospf_network_type", None,
     {"ip": "Interface Internet Protocol config commands", "ospf": "OSPF interface commands",
      "network": "Network type"}),
    ("no spanning-tree portfast", _IF_L2, "stp_portfast", None,
     {"spanning-tree": "Spanning Tree Subsystem", "portfast": "Spanning tree portfast options"}),
    ("no spanning-tree bpduguard", _IF_L2, "stp_bpduguard", None,
     {"spanning-tree": "Spanning Tree Subsystem", "bpduguard": "Don't accept BPDUs on this interface"}),
    ("no spanning-tree cost", _IF_L2, "stp_cost", None,
     {"spanning-tree": "Spanning Tree Subsystem", "cost": "Change an interface's spanning tree port path cost"}),
    ("no spanning-tree port-priority", _IF_L2, "stp_port_priority", None,
     {"spanning-tree": "Spanning Tree Subsystem", "port-priority": "Change an interface's spanning tree port priority"}),
)

for _pattern, _modes, _attribute, _value, _help in _INTERFACE_RESETS:
    command(_pattern, modes=_modes, privilege=15, help=dict(_help, no=_NO))(
        _reset_attr(_attribute, _value)
    )


@command(
    "no ip ospf {pid:<1-65535>} area [{area:<0-4294967295>}]",
    modes=_IF_ALL,
    privilege=15,
    help={"no": _NO, "ip": "Interface Internet Protocol config commands",
          "ospf": "OSPF interface commands", "pid": "Process ID", "area": "Set the OSPF area ID"},
)
def _no_ip_ospf_area(ctx):
    for iface in _targets(ctx):
        if iface.ospf_process == ctx.args["pid"]:
            iface.ospf_process = None
            iface.ospf_area = None
    ctx.mark_dirty()
    return None


# =========================================================================== #
# Legacy parity: VLAN name, DHCP pool, crypto general-keys                    #
# =========================================================================== #
@command(
    "no name [{value:WORD}]",
    modes=(CONFIG_VLAN,),
    privilege=15,
    help={"no": _NO, "name": "Ascii name of the VLAN", "value": "The ascii name for the VLAN"},
)
def _no_vlan_name(ctx):
    target = ctx.target
    ids = target if isinstance(target, list) else [target]
    for vlan_id in ids:
        if isinstance(vlan_id, int):
            ctx.node.vlans[vlan_id] = f"VLAN{vlan_id:04d}"
    ctx.mark_dirty()
    return None


def _pool(ctx):
    return ctx.target if ctx.target is not None and hasattr(ctx.target, "bindings") else None


@command(
    "no default-router [{ip:A.B.C.D}]",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={"no": _NO, "default-router": "Default routers", "ip": "Router's IP address"},
)
def _no_default_router(ctx):
    pool = _pool(ctx)
    if pool is not None:
        pool.default_router = None
        ctx.mark_dirty()
    return None


@command(
    "no dns-server [{ip:A.B.C.D}]",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={"no": _NO, "dns-server": "DNS servers", "ip": "Server's IP address"},
)
def _no_dns_server(ctx):
    pool = _pool(ctx)
    if pool is not None:
        pool.dns_servers = []
        ctx.mark_dirty()
    return None


@command(
    "no domain-name [{d:WORD}]",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={"no": _NO, "domain-name": "Domain name", "d": "Domain name"},
)
def _no_dhcp_domain_name(ctx):
    pool = _pool(ctx)
    if pool is not None:
        pool.domain_name = None
        ctx.mark_dirty()
    return None


@command(
    "no network [{net:A.B.C.D} [{mask:A.B.C.D}]]",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={"no": _NO, "network": "Network number and mask", "net": "Network number in dotted-decimal notation",
          "mask": "Network mask or prefix length"},
)
def _no_dhcp_network(ctx):
    pool = _pool(ctx)
    if pool is not None:
        pool.network_address = None
        pool.netmask = None
        ctx.mark_dirty()
    return None


@command(
    "no lease",
    modes=(DHCP_CONFIG,),
    privilege=15,
    help={"no": _NO, "lease": "Address lease time"},
)
def _no_lease(ctx):
    pool = _pool(ctx)
    if pool is not None:
        pool.lease_days, pool.lease_hours, pool.lease_minutes = 1, 0, 0
        pool.lease_infinite = False
        ctx.mark_dirty()
    return None


@command(
    "crypto key generate rsa general-keys [modulus {bits:<360-4096>}]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "crypto": "Encryption module",
        "key": "Long term key operations",
        "generate": "Generate new keys",
        "rsa": "Generate RSA keys",
        "general-keys": "Generate a general purpose RSA key pair for signing and encryption",
        "modulus": "Provide number of modulus bits on the command line",
        "bits": "Number of modulus bits",
    },
)
def _crypto_key_generate_general_keys(ctx):
    from .management import _crypto_key_generate_rsa

    yield from _crypto_key_generate_rsa(ctx)


# =========================================================================== #
# Phase 3: `no` forms that restore a default (found missing in a sweep)      #
# =========================================================================== #
def _reset_node(attribute: str, value):
    def handler(ctx):
        setattr(ctx.node, attribute, value() if callable(value) else value)
        ctx.mark_dirty()
        return None

    return handler


_SSH_HELP = {"no": _NO, "ip": "Global IP configuration subcommands",
             "ssh": "Configure ssh options"}
_CDP_HELP = {"no": _NO, "cdp": "Global CDP configuration subcommands"}
_VTP_HELP = {"no": _NO, "vtp": "Configure global VTP state"}

#: (pattern, attribute, default value, extra help)
_NODE_RESETS = (
    ("no ip ssh version [{v:<1-2>}]", "ssh_version", None,
     dict(_SSH_HELP, version="Specify protocol version supported", v="Protocol version")),
    ("no ip ssh time-out [{n:<1-120>}]", "ip_ssh_timeout", 120,
     dict(_SSH_HELP, **{"time-out": "Specify SSH time-out interval", "n": "SSH time-out interval (secs)"})),
    ("no ip ssh authentication-retries [{n:<0-5>}]", "ip_ssh_retries", 3,
     dict(_SSH_HELP, **{"authentication-retries": "Specify number of authentication retries",
                        "n": "Number of authentication retries"})),
    ("no cdp timer [{n:<5-254>}]", "cdp_timer", 60,
     dict(_CDP_HELP, timer="Specify the rate at which CDP packets are sent (in sec)", n="Rate at which CDP packets are sent (in sec)")),
    ("no cdp holdtime [{n:<10-255>}]", "cdp_holdtime", 180,
     dict(_CDP_HELP, holdtime="Specify the holdtime (in sec) to be sent in packets", n="Length of time (in sec) that receiver must keep this packet")),
    ("no spanning-tree mode [(pvst|rapid-pvst)]", "stp_mode", "pvst",
     {"no": _NO, "spanning-tree": "Spanning Tree Subsystem", "mode": "Spanning tree operating mode",
      "pvst": "Per-Vlan spanning tree mode", "rapid-pvst": "Per-Vlan rapid spanning tree mode"}),
    ("no vtp mode [(server|client|transparent)]", "vtp_mode", "server",
     dict(_VTP_HELP, mode="Configure VTP device mode", server="Set the device to server mode",
          client="Set the device to client mode", transparent="Set the device to transparent mode")),
    ("no vtp domain [{name:WORD}]", "vtp_domain", "",
     dict(_VTP_HELP, domain="Set the name of the VTP administrative domain.", name="The ascii name for the VTP administrative domain.")),
    ("no ip domain-name", "domain_name", None,
     {"no": _NO, "ip": "Global IP configuration subcommands", "domain-name": "Define the default domain name"}),
    ("no ip domain name", "domain_name", None,
     {"no": _NO, "ip": "Global IP configuration subcommands", "domain": "IP DNS Resolver",
      "name": "Define the default domain name"}),
)

for _pattern, _attribute, _value, _help in _NODE_RESETS:
    command(_pattern, modes=(CONFIG,), privilege=15, help=_help)(_reset_node(_attribute, _value))


@command(
    "no spanning-tree vlan {ids:VLAN_LIST} priority [{p:<0-61440>}]",
    modes=(CONFIG,),
    privilege=15,
    help={"no": _NO, "spanning-tree": "Spanning Tree Subsystem", "vlan": "VLAN Switch Spanning Tree",
          "ids": "Spanning tree VLAN id(s)", "priority": "Set the bridge priority for the spanning tree",
          "p": "bridge priority in increments of 4096"},
)
def _no_stp_vlan_priority(ctx):
    for vlan_id in ctx.args["ids"]:
        ctx.node.stp_priorities.pop(vlan_id, None)
    ctx.mark_dirty()
    return None


_PSEC_HELP = {"no": _NO, "switchport": "Set switching mode characteristics",
              "port-security": "Security related command"}

#: (pattern, attribute, default value, extra help) on the target switchports.
_PSEC_RESETS = (
    ("no switchport port-security maximum [{n:<1-4097>}]", "port_security_maximum", 1,
     dict(_PSEC_HELP, maximum="Max secure addresses", n="Maximum addresses")),
    ("no switchport port-security violation [(protect|restrict|shutdown)]", "port_security_violation", "shutdown",
     dict(_PSEC_HELP, violation="Security violation mode", protect="Security violation protect mode",
          restrict="Security violation restrict mode", shutdown="Security violation shutdown mode")),
)

for _pattern, _attribute, _value, _help in _PSEC_RESETS:
    command(_pattern, modes=_IF_L2, privilege=15, help=_help)(_reset_attr(_attribute, _value))


@command(
    "no switchport port-security mac-address sticky",
    modes=_IF_L2,
    privilege=15,
    help=dict(_PSEC_HELP, **{"mac-address": "Secure mac address",
                             "sticky": "Configure dynamic secure addresses as sticky"}),
)
def _no_port_security_sticky(ctx):
    """IOS turns the sticky addresses back into dynamic secure addresses."""
    for iface in _targets(ctx):
        iface.port_security_sticky = False
        iface.port_security_sticky_macs = []
        for entry in ctx.node.mac_table.values():
            if entry.port == iface.name and entry.secure == "sticky":
                entry.secure = "dynamic"
    ctx.mark_dirty()
    return None


@command(
    "no switchport port-security mac-address {mac:H.H.H}",
    modes=_IF_L2,
    privilege=15,
    help=dict(_PSEC_HELP, **{"mac-address": "Secure mac address", "mac": "48 bit mac address"}),
)
def _no_port_security_mac(ctx):
    from ...models import normalise_mac

    wanted = normalise_mac(ctx.args["mac"])
    for iface in _targets(ctx):
        kept = []
        for value in iface.port_security_macs:
            try:
                if normalise_mac(value) == wanted:
                    continue
            except ValueError:
                pass
            kept.append(value)
        iface.port_security_macs = kept
    ctx.mark_dirty()
    return None


@command(
    "no switchport mode [(access|trunk|dynamic (auto|desirable))]",
    modes=_IF_L2,
    privilege=15,
    help={"no": _NO, "switchport": "Set switching mode characteristics",
          "mode": "Set trunking mode of the interface"},
)
def _no_switchport_mode(ctx):
    for iface in _targets(ctx):
        # Back to the platform default (see models.NodeState.ensure_interface).
        iface.switchport_mode = "access"
        iface.configured = False
    ctx.mark_dirty()
    return None


@command(
    "switchport port-security mac-address sticky {mac:H.H.H}",
    modes=_IF_L2,
    privilege=15,
    help=dict(_PSEC_HELP, **{"mac-address": "Secure mac address",
                             "sticky": "Configure dynamic secure addresses as sticky",
                             "mac": "48 bit mac address"}),
)
def _port_security_sticky_mac(ctx):
    """A sticky secure address (what `show running-config` prints for one)."""
    from ...models import format_mac

    mac = format_mac(ctx.args["mac"], "cisco")
    for iface in _targets(ctx):
        if mac not in iface.port_security_sticky_macs:
            iface.port_security_sticky_macs.append(mac)
        iface.port_security_enabled = True
    ctx.mark_dirty()
    return None


@command(
    "no switchport port-security mac-address sticky {mac:H.H.H}",
    modes=_IF_L2,
    privilege=15,
    help=dict(_PSEC_HELP, **{"mac-address": "Secure mac address",
                             "sticky": "Configure dynamic secure addresses as sticky",
                             "mac": "48 bit mac address"}),
)
def _no_port_security_sticky_mac(ctx):
    from ...models import normalise_mac

    wanted = normalise_mac(ctx.args["mac"])
    for iface in _targets(ctx):
        iface.port_security_sticky_macs = [
            value for value in iface.port_security_sticky_macs if normalise_mac(value) != wanted
        ]
        for key in [k for k, entry in ctx.node.mac_table.items()
                    if entry.port == iface.name and entry.mac == wanted]:
            del ctx.node.mac_table[key]
    ctx.mark_dirty()
    return None
