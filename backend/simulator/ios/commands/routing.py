"""Routing / L3 / OSPF IOS commands (Agent CMD-RT, phase 2).

This command module is auto-discovered by :func:`simulator.ios.commands.ensure_registered`.
It registers, against the shared parser :data:`REGISTRY`:

* global configuration: ``ip route`` (static routes), ``ip routing`` and
  ``ip default-gateway``;
* OSPF router configuration (``config-router`` submode, whose ``ctx.target`` is
  the :class:`~simulator.models.OSPFProcess` entered by core's ``router ospf``):
  ``network``, ``router-id``, ``passive-interface``, ``default-information
  originate``, ``auto-cost reference-bandwidth``, ``maximum-paths``,
  ``log-adjacency-changes`` and ``shutdown``;
* privileged/user EXEC show commands that render live engine state as
  IOS-faithful text: ``show ip route``, ``show ip interface [brief]``,
  ``show ip protocols``, ``show ip ospf`` (+ ``neighbor``/``interface``/
  ``database``) and ``show arp`` / ``show ip arp``;
* EXEC tools ``ping``, ``traceroute`` and the ``clear`` commands for the ARP
  cache and the OSPF process.

Everything the show/exec commands print is computed from
``ctx.engines.{l3,ospf,l2}`` (the Phase-1 engines wired together by
:mod:`simulator.engines`); configuration handlers mutate ``ctx.node`` /
``ctx.target`` and call :meth:`ctx.mark_dirty` so the runtime rebuilds the
engine bundle before the next read.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional

from ...models import StaticRoute, canonical_interface, natural_key
from ...ospf import normalise_network_statement
from ..parser import CONFIG, CONFIG_ROUTER, EXEC, command
from ..protocol import Prompt, Sleep


# --------------------------------------------------------------------------- #
# Constants / small helpers                                                   #
# --------------------------------------------------------------------------- #
#: The ``show ip route`` legend, exactly as an IOL 15.x image prints it.
ROUTE_CODES = (
    "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n"
    "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\n"
    "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2\n"
    "       E1 - OSPF external type 1, E2 - OSPF external type 2\n"
    "       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2\n"
    "       ia - IS-IS inter area, * - candidate default, U - per-user static route\n"
    "       o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP\n"
    "       a - application route\n"
    "       + - replicated route, % - next hop override, p - overrides from PfR"
)

_PROBE_DELAY = 0.12  # per-probe pacing (ignored by the terminal in tests)


def _hms(seconds: float) -> str:
    """Format *seconds* as ``HH:MM:SS`` (used for route ages / uptimes)."""
    total = int(max(0, seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _classful(network: "ipaddress.IPv4Network") -> "ipaddress.IPv4Network":
    """Return the classful (A/B/C) supernet that contains *network*."""
    first = int(network.network_address)
    octet = (first >> 24) & 0xFF
    if octet < 128:
        prefix = 8
    elif octet < 192:
        prefix = 16
    elif octet < 224:
        prefix = 24
    else:
        return network
    if network.prefixlen < prefix:
        return network
    return ipaddress.ip_network(f"{network.network_address}/{prefix}", strict=False)


def _bundle(ctx):
    """Return the engine bundle, or ``None`` when no provider is wired."""
    return ctx.engines


def _node_name(ctx) -> str:
    return ctx.node.name


# --------------------------------------------------------------------------- #
# Global configuration: ip route / ip routing / ip default-gateway            #
# --------------------------------------------------------------------------- #
@command(
    "[no] ip route {prefix:A.B.C.D} {mask:A.B.C.D} ( {nh:A.B.C.D} | {intf:INTERFACE} )"
    " [{dist:<1-255>}] [name {name:WORD}] [permanent]",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "route": "Establish static routes",
        "prefix": "Destination prefix",
        "mask": "Destination prefix mask",
        "nh": "Forwarding router's address",
        "intf": "Output interface",
        "dist": "Distance metric for this route",
        "name": "Specify name of the next hop",
        "permanent": "permanent route",
    },
)
def _ip_route(ctx):
    node = ctx.node
    prefix = ctx.args["prefix"]
    mask = ctx.args["mask"]
    next_hop = ctx.args.get("nh")
    interface = canonical_interface(ctx.args["intf"]) if ctx.args.get("intf") else None
    distance = int(ctx.args["dist"]) if "dist" in ctx.args else 1
    name = ctx.args.get("name")
    permanent = "permanent" in ctx.path

    if ctx.negate:
        node.static_routes = [
            route
            for route in node.static_routes
            if not (
                route.prefix == prefix
                and route.mask == mask
                and (route.next_hop or None) == (next_hop or None)
                and (route.interface or None) == (interface or None)
            )
        ]
        ctx.mark_dirty()
        return None

    for route in node.static_routes:
        if (
            route.prefix == prefix
            and route.mask == mask
            and (route.next_hop or None) == (next_hop or None)
            and (route.interface or None) == (interface or None)
        ):
            route.distance = distance
            route.name = name
            route.permanent = permanent
            ctx.mark_dirty()
            return None

    node.static_routes.append(
        StaticRoute(
            prefix=prefix,
            mask=mask,
            next_hop=next_hop,
            interface=interface,
            distance=distance,
            name=name,
            permanent=permanent,
        )
    )
    ctx.mark_dirty()
    return None


@command(
    "[no] ip routing",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "routing": "Enable IP routing",
    },
)
def _ip_routing(ctx):
    ctx.node.ip_routing = not ctx.negate
    ctx.node.ip_routing_configured = True
    ctx.mark_dirty()
    return None


@command(
    "[no] ip default-gateway {gw:A.B.C.D}",
    modes=(CONFIG,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "ip": "Global IP configuration subcommands",
        "default-gateway": "Specify default gateway (if not routing IP)",
        "gw": "Default gateway's IP address",
    },
)
def _ip_default_gateway(ctx):
    ctx.node.default_gateway = None if ctx.negate else ctx.args["gw"]
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# OSPF router configuration (ctx.target is an OSPFProcess)                     #
# --------------------------------------------------------------------------- #
def _process(ctx):
    """Return the OSPFProcess core's ``router ospf`` pushed as the submode target."""
    return ctx.target


@command(
    "[no] network {net:A.B.C.D} {wild:A.B.C.D} area {area:<0-4294967295>}",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "network": "Enable routing on an IP network",
        "net": "Network number",
        "wild": "OSPF wild card bits",
        "area": "Set the OSPF area ID",
    },
)
def _ospf_network(ctx):
    process = _process(ctx)
    if process is None:
        return None
    # IOS stores the address with its host bits cleared and turns a subnet
    # mask into wildcard bits (``network 10.1.1.1 255.255.255.0`` ->
    # ``network 10.1.1.0 0.0.0.255``); ``no network`` matches the same way.
    address, wildcard = normalise_network_statement(ctx.args["net"], ctx.args["wild"])
    value = (address, wildcard, int(ctx.args["area"]))
    if ctx.negate:
        if value in process.networks:
            process.networks.remove(value)
    elif value not in process.networks:
        process.networks.append(value)
    ctx.mark_dirty()
    return None


@command(
    "[no] router-id {id:A.B.C.D}",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "router-id": "router-id for this OSPF process",
        "id": "OSPF router-id in IP address format",
    },
)
def _ospf_router_id(ctx):
    process = _process(ctx)
    if process is None:
        return None
    process.router_id = None if ctx.negate else ctx.args["id"]
    ctx.mark_dirty()
    return None


@command(
    "[no] passive-interface ( default | {intf:INTERFACE} )",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "passive-interface": "Suppress routing updates on an interface",
        "default": "Suppress routing updates on all interfaces",
        "intf": "Interface name",
    },
)
def _ospf_passive_interface(ctx):
    process = _process(ctx)
    if process is None:
        return None
    if "default" in ctx.path:
        process.passive_default = not ctx.negate
        if not ctx.negate:
            process.passive_interfaces.clear()
        else:
            process.non_passive_interfaces.clear()
        ctx.mark_dirty()
        return None
    name = canonical_interface(ctx.args["intf"])
    if process.passive_default:
        # Under ``passive-interface default`` individual interfaces are
        # exempted with ``no passive-interface`` and re-added by the positive.
        if ctx.negate:
            process.non_passive_interfaces.add(name)
        else:
            process.non_passive_interfaces.discard(name)
    else:
        if ctx.negate:
            process.passive_interfaces.discard(name)
        else:
            process.passive_interfaces.add(name)
    ctx.mark_dirty()
    return None


@command(
    "[no] default-information originate [always]",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "default-information": "Control distribution of default information",
        "originate": "Distribute a default route",
        "always": "Always advertise default route",
    },
)
def _ospf_default_information(ctx):
    process = _process(ctx)
    if process is None:
        return None
    if ctx.negate:
        process.default_information_originate = False
        process.default_information_always = False
    else:
        process.default_information_originate = True
        process.default_information_always = "always" in ctx.path
    ctx.mark_dirty()
    return None


@command(
    "[no] auto-cost reference-bandwidth {mbps:<1-4294967>}",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "auto-cost": "Calculate OSPF interface cost according to bandwidth",
        "reference-bandwidth": "Use reference bandwidth method to assign OSPF cost",
        "mbps": "The reference bandwidth in terms of Mbits per second",
    },
)
def _ospf_auto_cost(ctx):
    process = _process(ctx)
    if process is None:
        return None
    process.reference_bandwidth_mbps = 100 if ctx.negate else int(ctx.args["mbps"])
    ctx.mark_dirty()
    return None


@command(
    "[no] maximum-paths {n:<1-32>}",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "maximum-paths": "Forward packets over multiple paths",
        "n": "Number of paths",
    },
)
def _ospf_maximum_paths(ctx):
    process = _process(ctx)
    if process is None:
        return None
    process.maximum_paths = 4 if ctx.negate else int(ctx.args["n"])
    ctx.mark_dirty()
    return None


@command(
    "[no] log-adjacency-changes [detail]",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "log-adjacency-changes": "Log changes in adjacency state",
        "detail": "Log all state transitions",
    },
)
def _ospf_log_adjacency(ctx):
    process = _process(ctx)
    if process is None:
        return None
    if ctx.negate:
        process.log_adjacency_changes = False
        process.log_adjacency_detail = False
    else:
        process.log_adjacency_changes = True
        process.log_adjacency_detail = "detail" in ctx.path
    ctx.mark_dirty()
    return None


@command(
    "[no] shutdown",
    modes=(CONFIG_ROUTER,),
    privilege=15,
    help={
        "no": "Negate a command or set its defaults",
        "shutdown": "Shutdown the router process",
    },
)
def _ospf_shutdown(ctx):
    process = _process(ctx)
    if process is None:
        return None
    process.shutdown = not ctx.negate
    ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# show ip route                                                               #
# --------------------------------------------------------------------------- #
def _route_tail(node, entry) -> str:
    """Render the per-route suffix after the network for *entry* (one hop)."""
    code = entry.code
    if code in ("C", "L"):
        return f"is directly connected, {entry.next_hops[0][1]}"
    via, egress = entry.next_hops[0]
    if via is None:
        return f"is directly connected, {egress}"
    if code.startswith("O"):
        return f"[{entry.distance}/{entry.metric}] via {via}, {_hms(entry.age)}, {egress}"
    base = f"[{entry.distance}/{entry.metric}] via {via}"
    if _static_has_interface(node, entry):
        base += f", {egress}"
    return base


def _static_has_interface(node, entry) -> bool:
    """True when a static route to *entry*'s prefix was configured with an interface."""
    for route in getattr(node, "static_routes", []):
        if route.interface:
            try:
                net = ipaddress.ip_network(f"{route.prefix}/{route.mask}", strict=False)
            except ValueError:
                continue
            if net == entry.network:
                return True
    return False


def _emit_route_entry(lines: List[str], node, entry, indent: str, show_mask: bool) -> None:
    """Append the (possibly multi-line, for ECMP) output for one route entry."""
    if entry.network.prefixlen == 0:
        net_str = "0.0.0.0/0"
    elif show_mask:
        net_str = entry.network.with_prefixlen
    else:
        net_str = str(entry.network.network_address)

    code = entry.code
    hops = entry.next_hops or [(None, "")]
    routed = code not in ("C", "L") and hops[0][0] is not None

    if not routed:
        lines.append(f"{code:<6}{indent}{net_str} {_route_tail(node, entry)}")
        return

    first_line = None
    pad = 0
    for index, (via, egress) in enumerate(hops):
        if code.startswith("O"):
            seg = f"[{entry.distance}/{entry.metric}] via {via}, {_hms(entry.age)}, {egress}"
        else:
            seg = f"[{entry.distance}/{entry.metric}] via {via}"
            if _static_has_interface(node, entry):
                seg += f", {egress}"
        if index == 0:
            first_line = f"{code:<6}{indent}{net_str} {seg}"
            pad = len(first_line) - len(seg)
            lines.append(first_line)
        else:
            lines.append(" " * pad + seg)


def _render_routing_table(ctx, proto: Optional[str] = None, address: Optional[str] = None) -> str:
    bundle = _bundle(ctx)
    if bundle is None:
        return ""
    table = bundle.l3.routing_table(_node_name(ctx))
    entries = list(table.entries)

    if address is not None:
        return _render_route_detail(ctx, table, address)

    if proto is not None:
        entries = [e for e in entries if _entry_matches_proto(e, proto)]

    lines: List[str] = []
    # IOS 15 prints the legend and gateway line for ``show ip route <protocol>``
    # too, even when no route matches.
    lines.append(ROUTE_CODES)
    lines.append("")
    if table.gateway_of_last_resort:
        lines.append(
            f"Gateway of last resort is {table.gateway_of_last_resort} to network 0.0.0.0"
        )
    else:
        lines.append("Gateway of last resort is not set")
    lines.append("")

    # Group by classful major network, preserving deterministic ordering.
    order: dict = {}
    groups: List[list] = []
    for entry in entries:
        major = entry.network if entry.network.prefixlen == 0 else _classful(entry.network)
        key = major.with_prefixlen
        if key not in order:
            order[key] = len(groups)
            groups.append([major, []])
        groups[order[key]][1].append(entry)
    groups.sort(key=lambda item: (int(item[0].network_address), item[0].prefixlen))

    for major, group_entries in groups:
        if major.prefixlen == 0:
            for entry in group_entries:
                _emit_route_entry(lines, ctx.node, entry, "", True)
            continue
        masks = sorted({e.network.prefixlen for e in group_entries})
        n = len(group_entries)
        m = len(masks)
        classful_prefix = major.prefixlen
        if m == 1 and masks[0] == classful_prefix and n == 1:
            _emit_route_entry(lines, ctx.node, group_entries[0], "", True)
            continue
        if m == 1:
            lines.append(
                f"      {major.network_address}/{masks[0]} is subnetted, {n} subnets"
            )
            show_mask = False
        else:
            lines.append(
                f"      {major.network_address}/{classful_prefix} is variably subnetted, "
                f"{n} subnets, {m} masks"
            )
            show_mask = True
        for entry in group_entries:
            _emit_route_entry(lines, ctx.node, entry, "   ", show_mask)

    return "\n".join(lines)


def _entry_matches_proto(entry, proto: str) -> bool:
    proto = proto.lower()
    code = entry.code
    if "connected".startswith(proto):
        return code == "C"
    if "static".startswith(proto):
        return code in ("S", "S*")
    if "ospf".startswith(proto):
        return code.startswith("O")
    if "local".startswith(proto):
        return code == "L"
    return False


def _render_route_detail(ctx, table, address: str) -> str:
    entry = table.lookup(address)
    # ``lookup`` ignores local /32 entries; fall back to an exact L match.
    if entry is None:
        for candidate in table.entries:
            try:
                if ipaddress.ip_address(address) in candidate.network:
                    entry = candidate
                    break
            except ValueError:
                return "% Network not in table"
    if entry is None:
        return "% Network not in table"

    lines = [f"Routing entry for {entry.network.with_prefixlen}"]
    code = entry.code
    if code in ("C", "L"):
        lines.append("  Known via \"connected\", distance 0, metric 0 (connected, via interface)")
        lines.append("  Routing Descriptor Blocks:")
        lines.append(f"  * directly connected, via {entry.next_hops[0][1]}")
        lines.append("      Route metric is 0, traffic share count is 1")
        return "\n".join(lines)
    if code.startswith("O"):
        pid = next(iter(ctx.node.ospf_processes), 1)
        lines.append(
            f"  Known via \"ospf {pid}\", distance {entry.distance}, metric {entry.metric}"
            ", type intra area"
        )
        via, egress = entry.next_hops[0]
        lines.append(f"  Last update from {via} on {egress}, {_hms(entry.age)} ago")
        lines.append("  Routing Descriptor Blocks:")
        source = _ospf_source_for(ctx, via)
        for index, (hop_via, hop_egress) in enumerate(entry.next_hops):
            marker = "*" if index == 0 else " "
            src = f", from {source}" if source else ""
            lines.append(
                f"  {marker} {hop_via}{src}, {_hms(entry.age)} ago, via {hop_egress}"
            )
            lines.append(f"      Route metric is {entry.metric}, traffic share count is 1")
        return "\n".join(lines)
    # static / candidate default
    lines.append(f"  Known via \"static\", distance {entry.distance}, metric {entry.metric}")
    lines.append("  Routing Descriptor Blocks:")
    via, egress = entry.next_hops[0]
    target = via if via is not None else f"directly connected, via {egress}"
    lines.append(f"  * {target}")
    lines.append(f"      Route metric is {entry.metric}, traffic share count is 1")
    return "\n".join(lines)


def _ospf_source_for(ctx, via: Optional[str]) -> Optional[str]:
    bundle = _bundle(ctx)
    if bundle is None or via is None:
        return None
    for neighbour in bundle.ospf.neighbors(_node_name(ctx)):
        if neighbour.address == via:
            return neighbour.neighbor_id
    return None


@command(
    "show ip route",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "route": "IP routing table",
    },
)
def _show_ip_route(ctx):
    return _render_routing_table(ctx)


@command(
    "show ip route ( connected | static | ospf | rip | eigrp | bgp | local )",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "route": "IP routing table",
        "connected": "Connected",
        "static": "Static routes",
        "ospf": "Open Shortest Path First (OSPF)",
        "rip": "Routing Information Protocol (RIP)",
        "eigrp": "Enhanced Interior Gateway Routing Protocol (EIGRP)",
        "bgp": "Border Gateway Protocol (BGP)",
        "local": "Local routes",
    },
)
def _show_ip_route_proto(ctx):
    proto = ctx.path[-1]
    return _render_routing_table(ctx, proto=proto)


@command(
    "show ip route {addr:A.B.C.D}",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "route": "IP routing table",
        "addr": "Network to display",
    },
)
def _show_ip_route_addr(ctx):
    return _render_routing_table(ctx, address=ctx.args["addr"])


# --------------------------------------------------------------------------- #
# show ip interface [brief | X]                                               #
# --------------------------------------------------------------------------- #
def _interface_method(interface) -> str:
    if interface.address_source == "dhcp":
        return "DHCP"
    if interface.ip_address:
        return "manual"
    return "unset"


@command(
    "show ip interface brief",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "interface": "IP interface status and configuration",
        "brief": "Brief summary of IP status and configuration",
    },
)
def _show_ip_interface_brief(ctx):
    bundle = _bundle(ctx)
    node = ctx.node
    header = (
        f"{'Interface':<22} {'IP-Address':<15} {'OK?':<3} {'Method':<6} "
        f"{'Status':<21} {'Protocol'}"
    )
    lines = [header]
    for interface in sorted(node.interfaces.values(), key=lambda item: natural_key(item.name)):
        if bundle is not None:
            status, protocol = bundle.l2.line_state(node.name, interface.name)
        else:
            status = "administratively down" if interface.shutdown else "up"
            protocol = "down" if interface.shutdown else "up"
        protocol_text = "up" if protocol == "up" else "down"
        ip_text = interface.ip_address or "unassigned"
        method = _interface_method(interface)
        lines.append(
            f"{interface.name:<22} {ip_text:<15} {'YES':<3} {method:<6} "
            f"{status:<21} {protocol_text}"
        )
    return "\n".join(lines)


@command(
    "show ip interface [{intf:INTERFACE}]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "interface": "IP interface status and configuration",
        "intf": "Interface name",
    },
)
def _show_ip_interface(ctx):
    bundle = _bundle(ctx)
    node = ctx.node
    requested = ctx.args.get("intf")
    if requested is not None:
        interface = node.interfaces.get(canonical_interface(requested))
        if interface is None:
            # Valid-shape but non-existent (e.g. an uncreated Loopback/Vlan):
            # IOS prints no L3 detail for it.
            return None
        interfaces = [interface]
    else:
        interfaces = sorted(node.interfaces.values(), key=lambda item: natural_key(item.name))

    blocks: List[str] = []
    for interface in interfaces:
        if bundle is not None:
            status, protocol = bundle.l2.line_state(node.name, interface.name)
        else:
            status = "administratively down" if interface.shutdown else "up"
            protocol = "down" if interface.shutdown else "up"
        protocol_text = "up" if protocol == "up" else "down"
        lines = [f"{interface.name} is {status}, line protocol is {protocol_text}"]
        if interface.ip_address and interface.netmask:
            try:
                network = ipaddress.ip_network(
                    f"{interface.ip_address}/{interface.netmask}", strict=False
                )
                lines.append(
                    f"  Internet address is {interface.ip_address}/{network.prefixlen}"
                )
            except ValueError:
                lines.append(f"  Internet address is {interface.ip_address}")
            lines.append("  Broadcast address is 255.255.255.255")
            for secondary_ip, secondary_mask in interface.secondary_addresses:
                try:
                    plen = ipaddress.ip_network(
                        f"{secondary_ip}/{secondary_mask}", strict=False
                    ).prefixlen
                    lines.append(
                        f"  Secondary address {secondary_ip}/{plen}"
                    )
                except ValueError:
                    pass
            lines.append(f"  MTU is {interface.mtu or 1500} bytes")
            if interface.helper_addresses:
                for helper in interface.helper_addresses:
                    lines.append(f"  Helper address is {helper}")
            else:
                lines.append("  Helper address is not set")
            lines.append(
                f"  Outgoing access list is "
                f"{interface.access_group_out or 'not set'}"
            )
            lines.append(
                f"  Inbound  access list is {interface.access_group_in or 'not set'}"
            )
            lines.append("  Proxy ARP is enabled")
            lines.append("  ICMP redirects are always sent")
        else:
            lines.append("  Internet protocol processing disabled")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


# --------------------------------------------------------------------------- #
# show ip protocols                                                           #
# --------------------------------------------------------------------------- #
@command(
    "show ip protocols",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "protocols": "IP routing protocol process parameters and statistics",
    },
)
def _show_ip_protocols(ctx):
    bundle = _bundle(ctx)
    if bundle is None:
        return ""
    summaries = bundle.ospf.process_summary(_node_name(ctx))
    if not summaries:
        return "*** IP Routing is NSF aware ***"
    lines = ["*** IP Routing is NSF aware ***", ""]
    for summary in summaries:
        lines.append(f'Routing Protocol is "ospf {summary.process_id}"')
        lines.append("  Outgoing update filter list for all interfaces is not set")
        lines.append("  Incoming update filter list for all interfaces is not set")
        lines.append(f"  Router ID {summary.router_id or 'not set'}")
        area_count = len(summary.areas)
        lines.append(
            f"  Number of areas in this router is {area_count}. "
            f"{area_count} normal 0 stub 0 nssa"
        )
        lines.append(f"  Maximum path: {summary.maximum_paths}")
        lines.append("  Routing for Networks:")
        for net, wild, area in summary.networks:
            lines.append(f"    {net} {wild} area {area}")
        if summary.passive_interfaces:
            lines.append("  Passive Interface(s):")
            for name in summary.passive_interfaces:
                lines.append(f"    {name}")
        lines.append("  Routing Information Sources:")
        lines.append(f"    {'Gateway':<16}{'Distance':<14}{'Last Update'}")
        for source in summary.sources:
            lines.append(
                f"    {source.router_id:<16}{str(source.distance):<14}{source.last_update}"
            )
        lines.append(f"  Distance: (default is {summary.distance})")
        lines.append("")
    return "\n".join(lines).rstrip("\n")


# --------------------------------------------------------------------------- #
# show ip ospf (+ neighbor / interface / database)                            #
# --------------------------------------------------------------------------- #
def _ospf_running(ctx) -> bool:
    return bool(
        [p for p in ctx.node.ospf_processes.values() if not p.shutdown]
    )


@command(
    "show ip ospf",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "ospf": "OSPF information",
    },
)
def _show_ip_ospf(ctx):
    bundle = _bundle(ctx)
    if bundle is None or not ctx.node.ospf_processes:
        return ""
    summaries = bundle.ospf.process_summary(_node_name(ctx))
    lines: List[str] = []
    for summary in summaries:
        lines.append(
            f' Routing Process "ospf {summary.process_id}" with ID '
            f"{summary.router_id or '0.0.0.0'}"
        )
        lines.append(" Supports only single TOS(TOS0) routes")
        lines.append(" Supports opaque LSA")
        lines.append(" Initial SPF schedule delay 5000 msecs")
        lines.append(" Minimum hold time between two consecutive SPFs 10000 msecs")
        lines.append(" Maximum wait time between two consecutive SPFs 10000 msecs")
        lines.append(
            f" Reference bandwidth unit is {summary.reference_bandwidth_mbps} mbps"
        )
        for area in summary.areas:
            area_name = "BACKBONE(0)" if area == 0 else str(area)
            interfaces = [
                detail
                for detail in bundle.ospf.interfaces(_node_name(ctx))
                if detail.area == area
            ]
            lines.append(f"    Area {area_name}")
            lines.append(
                f"        Number of interfaces in this area is {len(interfaces)}"
            )
            lines.append("        Area has no authentication")
            lines.append("        SPF algorithm executed 1 times")
    return "\n".join(lines)


@command(
    "show ip ospf neighbor [detail]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "ospf": "OSPF information",
        "neighbor": "Neighbor list",
        "detail": "Detailed neighbor information",
    },
)
def _show_ip_ospf_neighbor(ctx):
    bundle = _bundle(ctx)
    if bundle is None or not ctx.node.ospf_processes:
        return ""
    neighbours = bundle.ospf.neighbors(_node_name(ctx))
    if "detail" in ctx.path:
        return _render_neighbor_detail(ctx, neighbours)
    header = (
        f"{'Neighbor ID':<15} {'Pri':>3}   {'State':<15} {'Dead Time':<11} "
        f"{'Address':<15} {'Interface'}"
    )
    lines = [header]
    for neighbour in neighbours:
        lines.append(
            f"{neighbour.neighbor_id:<15} {neighbour.priority:>3}   "
            f"{neighbour.state:<15} {neighbour.dead_time:<11} "
            f"{neighbour.address:<15} {neighbour.local_interface}"
        )
    return "\n".join(lines)


def _render_neighbor_detail(ctx, neighbours) -> str:
    bundle = _bundle(ctx)
    details = {detail.name: detail for detail in bundle.ospf.interfaces(_node_name(ctx))}
    blocks: List[str] = []
    for neighbour in neighbours:
        detail = details.get(neighbour.local_interface)
        state = neighbour.state.split("/", 1)[0]
        lines = [
            f" Neighbor {neighbour.neighbor_id}, interface address {neighbour.address}",
            f"    In the area {neighbour.area} via interface {neighbour.local_interface}",
            f"    Neighbor priority is {neighbour.priority}, State is {state}, 6 state changes",
        ]
        if detail is not None:
            lines.append(
                f"    DR is {detail.dr_address or '0.0.0.0'} "
                f"BDR is {detail.bdr_address or '0.0.0.0'}"
            )
        lines.append("    Options is 0x12 in Hello (E-bit, L-bit)")
        lines.append(f"    Dead timer due in {neighbour.dead_time}")
        lines.append(f"    Neighbor is up for {_hms(neighbour.uptime)}")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


@command(
    "show ip ospf interface brief",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "ospf": "OSPF information",
        "interface": "Interface information",
        "brief": "Brief summary per interface",
    },
)
def _show_ip_ospf_interface_brief(ctx):
    bundle = _bundle(ctx)
    if bundle is None or not ctx.node.ospf_processes:
        return ""
    details = bundle.ospf.interfaces(_node_name(ctx))
    header = (
        f"{'Interface':<12} {'PID':<5} {'Area':<15} {'IP Address/Mask':<18} "
        f"{'Cost':<5} {'State':<5} {'Nbrs F/C'}"
    )
    lines = [header]
    for detail in details:
        try:
            plen = ipaddress.ip_network(
                f"{detail.ip}/{detail.netmask}", strict=False
            ).prefixlen
            addr = f"{detail.ip}/{plen}"
        except (ValueError, TypeError):
            addr = f"{detail.ip}"
        lines.append(
            f"{_short_if(detail.name):<12} {detail.process_id:<5} {detail.area:<15} "
            f"{addr:<18} {detail.cost:<5} {detail.state:<5} "
            f"{detail.adjacent_count}/{detail.neighbor_count}"
        )
    return "\n".join(lines)


@command(
    "show ip ospf interface [{intf:INTERFACE}]",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "ospf": "OSPF information",
        "interface": "Interface information",
        "intf": "Interface name",
    },
)
def _show_ip_ospf_interface(ctx):
    bundle = _bundle(ctx)
    if bundle is None or not ctx.node.ospf_processes:
        return ""
    requested = ctx.args.get("intf")
    details = bundle.ospf.interfaces(_node_name(ctx))
    if requested is not None:
        canonical = canonical_interface(requested)
        details = [detail for detail in details if detail.name == canonical]
    blocks: List[str] = []
    for detail in details:
        line_status, line_protocol = bundle.l2.line_state(_node_name(ctx), detail.name)
        protocol_text = "up" if line_protocol == "up" else "down"
        lines = [
            f"{detail.name} is {line_status}, line protocol is {protocol_text}",
            f"  Internet Address {detail.ip}/{_mask_to_plen(detail.netmask)}, "
            f"Area {detail.area}, Attached via Network Statement",
            f"  Process ID {detail.process_id}, Router ID {detail.router_id}, "
            f"Network Type {detail.network_type.upper()}, Cost: {detail.cost}",
            f"  Transmit Delay is 1 sec, State {detail.state}, Priority {detail.priority}",
        ]
        if detail.network_type == "broadcast":
            lines.append(
                f"  Designated Router (ID) {detail.dr_id or '0.0.0.0'}, "
                f"Interface address {detail.dr_address or '0.0.0.0'}"
            )
            lines.append(
                f"  Backup Designated router (ID) {detail.bdr_id or '0.0.0.0'}, "
                f"Interface address {detail.bdr_address or '0.0.0.0'}"
            )
        lines.append(
            f"  Timer intervals configured, Hello {detail.hello}, Dead {detail.dead}, "
            f"Wait {detail.dead}, Retransmit 5"
        )
        lines.append(
            f"  Neighbor Count is {detail.neighbor_count}, "
            f"Adjacent neighbor count is {detail.adjacent_count}"
        )
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


@command(
    "show ip ospf database",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "ospf": "OSPF information",
        "database": "Database summary",
    },
)
def _show_ip_ospf_database(ctx):
    bundle = _bundle(ctx)
    if bundle is None or not ctx.node.ospf_processes:
        return ""
    database = bundle.ospf.database(_node_name(ctx))
    router_id = bundle.ospf.router_id(_node_name(ctx)) or "0.0.0.0"
    pid = next(iter(ctx.node.ospf_processes), 1)
    lines = [f"            OSPF Router with ID ({router_id}) (Process ID {pid})", ""]
    for area in sorted(database):
        entries = database[area]
        router_lsas = [lsa for lsa in entries if lsa.lsa_type == "router"]
        network_lsas = [lsa for lsa in entries if lsa.lsa_type == "network"]
        if router_lsas:
            lines.append(f"                Router Link States (Area {area})")
            lines.append("")
            lines.append(
                f"{'Link ID':<15} {'ADV Router':<15} {'Age':<11} {'Seq#':<10} "
                f"{'Checksum':<8} Link count"
            )
            for lsa in router_lsas:
                lines.append(
                    f"{lsa.link_id:<15} {lsa.adv_router:<15} {lsa.age:<11} "
                    f"0x{lsa.seq:08x} 0x{lsa.checksum:06x} {lsa.link_count}"
                )
            lines.append("")
        if network_lsas:
            lines.append(f"                Net Link States (Area {area})")
            lines.append("")
            lines.append(
                f"{'Link ID':<15} {'ADV Router':<15} {'Age':<11} {'Seq#':<10} "
                f"{'Checksum'}"
            )
            for lsa in network_lsas:
                lines.append(
                    f"{lsa.link_id:<15} {lsa.adv_router:<15} {lsa.age:<11} "
                    f"0x{lsa.seq:08x} 0x{lsa.checksum:06x}"
                )
            lines.append("")
    return "\n".join(lines).rstrip("\n")


# --------------------------------------------------------------------------- #
# show arp / show ip arp                                                      #
# --------------------------------------------------------------------------- #
def _render_arp(ctx) -> str:
    bundle = _bundle(ctx)
    if bundle is None:
        return ""
    rows = bundle.l3.arp_table(_node_name(ctx), now=ctx.now())
    header = (
        f"{'Protocol':<10}{'Address':<17}{'Age (min)':>9}  "
        f"{'Hardware Addr':<16}{'Type':<7}{'Interface'}"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"{row.protocol:<10}{row.address:<17}{row.age:>9}  "
            f"{row.mac:<16}{row.type:<7}{row.interface}"
        )
    return "\n".join(lines)


@command(
    "show arp",
    modes=(EXEC,),
    privilege=1,
    help={"show": "Show running system information", "arp": "ARP table"},
)
def _show_arp(ctx):
    return _render_arp(ctx)


@command(
    "show ip arp",
    modes=(EXEC,),
    privilege=1,
    help={
        "show": "Show running system information",
        "ip": "IP information",
        "arp": "IP ARP table",
    },
)
def _show_ip_arp(ctx):
    return _render_arp(ctx)


# --------------------------------------------------------------------------- #
# ping / traceroute                                                           #
# --------------------------------------------------------------------------- #
def _emit_ping(ctx, target: str, repeat: int, size: int, timeout: int):
    bundle = _bundle(ctx)
    if bundle is None:
        yield "% Unable to reach the network engine."
        return
    result = bundle.l3.ping(
        _node_name(ctx), target, repeat=repeat, size=size, timeout=timeout, now=ctx.now()
    )
    if not result.resolved:
        yield "% Unrecognized host or address, or protocol not running."
        return
    yield "Type escape sequence to abort.\n"
    yield (
        f"Sending {result.sent}, {size}-byte ICMP Echos to {result.target}, "
        f"timeout is {timeout} seconds:\n"
    )
    for probe in result.probes:
        yield probe
        yield Sleep(_PROBE_DELAY)
    yield "\n"
    if result.success > 0:
        yield (
            f"Success rate is {result.success_rate} percent "
            f"({result.success}/{result.sent}), round-trip min/avg/max = "
            f"{int(round(result.rtt_min))}/{int(round(result.rtt_avg))}/"
            f"{int(round(result.rtt_max))} ms"
        )
    else:
        yield (
            f"Success rate is {result.success_rate} percent "
            f"({result.success}/{result.sent})"
        )


@command(
    "ping [{target:WORD}]",
    modes=(EXEC,),
    privilege=1,
    help={"ping": "Send echo messages", "target": "Ping destination address or hostname"},
)
def _ping(ctx):
    target = ctx.args.get("target")
    if target:
        yield from _emit_ping(ctx, target, repeat=5, size=100, timeout=2)
        return
    # Bare ``ping`` -> the IOS extended-ping dialog.
    yield Prompt("Protocol [ip]: ")
    target = (yield Prompt("Target IP address: ")).strip()
    if not target:
        yield "% A decimal number between 0 and 4294967295."
        return
    repeat_raw = (yield Prompt("Repeat count [5]: ")).strip()
    size_raw = (yield Prompt("Datagram size [100]: ")).strip()
    timeout_raw = (yield Prompt("Timeout in seconds [2]: ")).strip()
    yield Prompt("Extended commands [n]: ")
    yield Prompt("Sweep range of sizes [n]: ")
    repeat = int(repeat_raw) if repeat_raw.isdigit() else 5
    size = int(size_raw) if size_raw.isdigit() else 100
    timeout = int(timeout_raw) if timeout_raw.isdigit() else 2
    yield from _emit_ping(ctx, target, repeat=repeat, size=size, timeout=timeout)


@command(
    "traceroute {target:WORD}",
    modes=(EXEC,),
    privilege=1,
    help={
        "traceroute": "Trace route to destination",
        "target": "Trace route destination address or hostname",
    },
)
def _traceroute(ctx):
    bundle = _bundle(ctx)
    if bundle is None:
        yield "% Unable to reach the network engine."
        return
    result = bundle.l3.traceroute(_node_name(ctx), ctx.args["target"], now=ctx.now())
    if not result.resolved:
        yield "% Unrecognized host or address, or protocol not running."
        return
    yield "Type escape sequence to abort.\n"
    yield f"Tracing the route to {result.target}\n"
    yield "VRF info: (vrf in name/id, vrf out name/id)\n"
    for hop in result.hops:
        address = None
        probe_cells: List[str] = []
        for probe in hop.probes:
            if probe.address is not None and address is None:
                address = probe.address
            if probe.rtt is not None:
                probe_cells.append(f"{int(round(probe.rtt))} msec")
            else:
                probe_cells.append("*")
        if address is None:
            yield f"{hop.ttl:3d} " + " ".join("*" for _ in hop.probes) + "\n"
        else:
            yield f"{hop.ttl:3d} {address} " + " ".join(probe_cells) + "\n"
        yield Sleep(_PROBE_DELAY)


# --------------------------------------------------------------------------- #
# clear ip ospf process / clear arp-cache / clear ip arp                      #
# --------------------------------------------------------------------------- #
@command(
    "clear ip ospf process",
    modes=(EXEC,),
    privilege=15,
    help={
        "clear": "Reset functions",
        "ip": "IP information",
        "ospf": "OSPF information",
        "process": "Reset OSPF process",
    },
)
def _clear_ip_ospf_process(ctx):
    answer = yield Prompt("Reset ALL OSPF processes? [no]: ")
    if (answer or "").strip().lower() in ("y", "yes"):
        now = ctx.now()
        for process in ctx.node.ospf_processes.values():
            process.cleared_at = now
        ctx.mark_dirty()
    return


@command(
    "clear arp-cache",
    modes=(EXEC,),
    privilege=15,
    help={"clear": "Reset functions", "arp-cache": "Clear the entire ARP cache"},
)
def _clear_arp_cache(ctx):
    bundle = _bundle(ctx)
    if bundle is not None:
        bundle.l3.clear_arp(_node_name(ctx))
        ctx.mark_dirty()
    return None


@command(
    "clear ip arp",
    modes=(EXEC,),
    privilege=15,
    help={
        "clear": "Reset functions",
        "ip": "IP information",
        "arp": "Clear IP ARP cache",
    },
)
def _clear_ip_arp(ctx):
    bundle = _bundle(ctx)
    if bundle is not None:
        bundle.l3.clear_arp(_node_name(ctx))
        ctx.mark_dirty()
    return None


# --------------------------------------------------------------------------- #
# Interface short-name helper (for OSPF brief)                                #
# --------------------------------------------------------------------------- #
def _short_if(name: str) -> str:
    canonical = canonical_interface(name)
    table = (
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("Ethernet", "Et"),
        ("Port-channel", "Po"),
        ("Loopback", "Lo"),
        ("Serial", "Se"),
        ("Tunnel", "Tu"),
        ("Vlan", "Vl"),
    )
    for prefix, short in table:
        if canonical.startswith(prefix):
            return short + canonical[len(prefix):]
    return canonical


def _mask_to_plen(netmask: Optional[str]) -> int:
    if not netmask:
        return 0
    try:
        return ipaddress.ip_network(f"0.0.0.0/{netmask}", strict=False).prefixlen
    except ValueError:
        return 0
