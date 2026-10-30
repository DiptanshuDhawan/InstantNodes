"""Deterministic layer-3 engine: addressing, routing table, and forwarding.

The engine is side-effect free except for the explicitly documented mutations
performed by :meth:`L3Engine.ping` (ARP cache, interface counters) when
``dry_run`` is False.  It reads :class:`NodeState` objects and the shared
:class:`adapters.NetworkCallbacks` bundle, from which it only ever consults
``segment_of`` and ``line_protocol_up``; ``find_ip`` and ``reachable`` are
computed here.

OSPF routes arrive through an injected ``ospf`` object (an
:class:`simulator.ospf.OspfEngine`, duck-typed as ``.routes(node)`` returning
:class:`simulator.ospf.OspfRoute`-shaped objects and ``.router_id(node)``).
Pass ``ospf=None`` to run without dynamic routing (static/connected only).

Public API
----------
``L3Engine(nodes, links, callbacks, now, ospf=None)``

* ``endpoints(node=None) -> list[IPEndpoint]``
* ``find_ip(address) -> Optional[IPEndpoint]``
* ``routing_table(node) -> RoutingTable`` (``.lookup(address)``)
* ``lookup(node, address) -> Optional[RouteEntry]``
* ``forward(src, dst, src_address=None, ttl=255) -> ForwardResult``
* ``ping(src, dst, repeat=5, size=100, timeout=2, source=None, now=None, dry_run=False) -> PingResult``
* ``traceroute(src, dst, max_ttl=30, probes=3, timeout=3, source=None, now=None) -> TracerouteResult``
* ``arp_table(node, now=None) -> list[ArpRow]`` / ``clear_arp(node)``
* ``reachable(src, dst, now=None) -> bool`` (wired into ``callbacks.reachable``)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Dict, Hashable, Iterable, List, Optional, Tuple

from .models import (
    ArpEntry,
    InterfaceState,
    NodeState,
    canonical_interface,
    format_mac,
    natural_key,
)
from .adapters import NetworkCallbacks


Link = Tuple[str, str, str, str]

# Administrative distances.
AD_CONNECTED = 0
AD_STATIC = 1
AD_OSPF = 110

PROBE_SUCCESS = "!"
PROBE_TIMEOUT = "."
PROBE_UNREACHABLE = "U"

# Deterministic per-hop round-trip contribution (milliseconds).
RTT_PER_HOP_MS = 1.0


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class IPEndpoint:
    node: str
    interface: str
    address: ipaddress.IPv4Address
    network: ipaddress.IPv4Network
    segment: Hashable
    secondary: bool = False


@dataclass
class RouteEntry:
    code: str  # "C", "L", "S", "S*", "O", "O*E2", ...
    network: ipaddress.IPv4Network
    distance: int
    metric: int
    next_hops: List[Tuple[Optional[str], str]]  # (next_hop_ip|None, egress)
    age: float = 0.0
    source: str = "connected"

    @property
    def is_default(self) -> bool:
        return self.network.prefixlen == 0


@dataclass
class SubnetGroup:
    major: ipaddress.IPv4Network
    variably_subnetted: bool
    masks: int
    route_count: int


@dataclass
class RoutingTable:
    node: str
    entries: List[RouteEntry]
    gateway_of_last_resort: Optional[str] = None
    subnet_groups: List[SubnetGroup] = field(default_factory=list)

    def lookup(self, address) -> Optional[RouteEntry]:
        try:
            target = ipaddress.IPv4Address(str(address))
        except ipaddress.AddressValueError:
            return None
        best: Optional[RouteEntry] = None
        for entry in self.entries:
            if entry.code == "L":
                continue  # local /32 host entries are not forwarding routes
            if target in entry.network:
                if best is None or entry.network.prefixlen > best.network.prefixlen:
                    best = entry
                elif (
                    entry.network.prefixlen == best.network.prefixlen
                    and (entry.distance, entry.metric) < (best.distance, best.metric)
                ):
                    best = entry
        return best


@dataclass
class L2Leg:
    src: Tuple[str, str]  # (node, interface)
    dst: Tuple[str, str]
    segment: Hashable


@dataclass
class ForwardHop:
    node: str
    ingress_ip: Optional[str]
    ingress: Optional[str]
    egress: Optional[str]
    next_hop: Optional[str]
    segment: Hashable = None


@dataclass
class ForwardResult:
    status: str  # delivered | no-route | ttl-exceeded | arp-failure | host-unreachable
    hops: List[ForwardHop]
    path: List[Tuple[str, str]]  # (node, ingress_ip) per node reached beyond source
    legs: List[L2Leg]
    responder: Optional[str]
    dest: Optional[str]
    dest_address: str

    @property
    def delivered(self) -> bool:
        return self.status == "delivered"


@dataclass
class PingResult:
    target: str
    resolved: bool
    probes: List[str]
    success: int
    sent: int
    success_rate: int
    rtt_min: float
    rtt_avg: float
    rtt_max: float
    source_address: Optional[str] = None
    error: Optional[str] = None

    def summary(self) -> str:
        return "".join(self.probes)


@dataclass
class TraceProbe:
    address: Optional[str]
    rtt: Optional[float]


@dataclass
class TraceHop:
    ttl: int
    probes: List[TraceProbe]
    status: str  # ok | unreachable | host-unreachable | timeout
    done: bool


@dataclass
class TracerouteResult:
    target: str
    resolved: bool
    hops: List[TraceHop]
    reached: bool
    source_address: Optional[str] = None


@dataclass
class ArpRow:
    address: str
    age: str
    mac: str
    interface: str
    protocol: str = "Internet"
    type: str = "ARPA"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class L3Engine:
    """Computes addressing, routing tables and packet forwarding."""

    def __init__(
        self,
        nodes: Dict[str, NodeState],
        links: Iterable[Link],
        callbacks: NetworkCallbacks,
        now: float,
        ospf=None,
    ) -> None:
        self.nodes = nodes
        self.links: List[Link] = [
            (a, canonical_interface(ai), b, canonical_interface(bi))
            for a, ai, b, bi in links
        ]
        self.callbacks = callbacks
        self.now = float(now)
        self.ospf = ospf
        #: Optional ``Callable[[List[L2Leg], float], None]`` that teaches the
        #: switches the MAC addresses of a live ping (installed by
        #: :func:`simulator.engines.build_bundle`; ``None`` in unit tests).
        self.mac_learner = None
        #: Optional ``Callable[[List[L2Leg]], bool]``: False when a secure
        #: switchport on the legs would drop the frames (port security).
        self.mac_filter = None
        self._endpoints_cache: Optional[List[IPEndpoint]] = None
        self._by_node: Dict[str, List[IPEndpoint]] = {}
        self._by_segment: Dict[Hashable, List[IPEndpoint]] = {}
        self._by_address: Dict[str, IPEndpoint] = {}
        self._table_cache: Dict[str, RoutingTable] = {}

    # ---- low-level helpers ----------------------------------------------
    def _up(self, node_name: str, interface_name: str) -> bool:
        return bool(self.callbacks.line_protocol_up(node_name, interface_name))

    def _segment(self, node_name: str, interface_name: str) -> Hashable:
        return self.callbacks.segment_of(node_name, interface_name)

    def _interface(self, node_name: str, interface_name: str) -> Optional[InterfaceState]:
        node = self.nodes.get(node_name)
        if node is None:
            return None
        return node.interfaces.get(canonical_interface(interface_name))

    # ---- endpoints ------------------------------------------------------
    def _build_endpoints(self) -> None:
        if self._endpoints_cache is not None:
            return
        endpoints: List[IPEndpoint] = []
        for node_name, node in self.nodes.items():
            for interface in node.interfaces.values():
                if not self._up(node_name, interface.name):
                    continue
                segment = self._segment(node_name, interface.name)
                records: List[Tuple[str, str, bool]] = []
                if interface.ip_address and interface.netmask:
                    records.append((interface.ip_address, interface.netmask, False))
                for secondary_ip, secondary_mask in interface.secondary_addresses:
                    records.append((secondary_ip, secondary_mask, True))
                for address, netmask, secondary in records:
                    try:
                        network = ipaddress.ip_network(
                            f"{address}/{netmask}", strict=False
                        )
                        parsed = ipaddress.IPv4Address(address)
                    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                        continue
                    endpoint = IPEndpoint(
                        node_name, interface.name, parsed, network, segment, secondary
                    )
                    endpoints.append(endpoint)
        self._endpoints_cache = endpoints
        for endpoint in endpoints:
            self._by_node.setdefault(endpoint.node, []).append(endpoint)
            self._by_segment.setdefault(endpoint.segment, []).append(endpoint)
            self._by_address.setdefault(str(endpoint.address), endpoint)

    def endpoints(self, node: Optional[str] = None) -> List[IPEndpoint]:
        self._build_endpoints()
        if node is None:
            return list(self._endpoints_cache or [])
        return list(self._by_node.get(node, []))

    def find_ip(self, address: str) -> Optional[IPEndpoint]:
        self._build_endpoints()
        return self._by_address.get(str(address))

    def _owns(self, node_name: str, address: ipaddress.IPv4Address) -> bool:
        self._build_endpoints()
        for endpoint in self._by_node.get(node_name, []):
            if endpoint.address == address:
                return True
        return False

    def _owner_on_segment(
        self, segment: Hashable, address: ipaddress.IPv4Address
    ) -> Optional[IPEndpoint]:
        self._build_endpoints()
        for endpoint in self._by_segment.get(segment, []):
            if endpoint.address == address:
                return endpoint
        return None

    def _connected_interface(
        self, node_name: str, address: ipaddress.IPv4Address
    ) -> Optional[IPEndpoint]:
        """Return the local endpoint whose subnet contains *address*."""
        self._build_endpoints()
        best: Optional[IPEndpoint] = None
        for endpoint in self._by_node.get(node_name, []):
            if address in endpoint.network:
                if best is None or endpoint.network.prefixlen > best.network.prefixlen:
                    best = endpoint
        return best

    # ---- routing table --------------------------------------------------
    def _resolve_egress(
        self, node_name: str, next_hop: str
    ) -> Optional[str]:
        """Return the egress interface used to reach *next_hop* (connected)."""
        try:
            target = ipaddress.IPv4Address(next_hop)
        except ipaddress.AddressValueError:
            return None
        endpoint = self._connected_interface(node_name, target)
        return endpoint.interface if endpoint else None

    def routing_table(self, node_name: str) -> RoutingTable:
        cached = self._table_cache.get(node_name)
        if cached is not None:
            return cached
        node = self.nodes.get(node_name)
        if node is None:
            table = RoutingTable(node_name, [])
            self._table_cache[node_name] = table
            return table

        candidates: List[RouteEntry] = []

        # Connected + local routes for every up interface with an address.
        for endpoint in self.endpoints(node_name):
            candidates.append(
                RouteEntry(
                    "C", endpoint.network, AD_CONNECTED, 0,
                    [(None, endpoint.interface)], 0.0, "connected",
                )
            )
            host = ipaddress.ip_network(f"{endpoint.address}/32")
            candidates.append(
                RouteEntry(
                    "L", host, AD_CONNECTED, 0,
                    [(None, endpoint.interface)], 0.0, "local",
                )
            )

        # Static routes (routers honour them; hosts rely on default-gateway).
        if node.ip_routing:
            for static in node.static_routes:
                entry = self._static_route_entry(node_name, static)
                if entry is not None:
                    candidates.append(entry)

        # OSPF routes.
        if self.ospf is not None and node.kind == "router" and node.ip_routing:
            for route in self.ospf.routes(node_name):
                next_hops = [
                    (str(via), canonical_interface(egress))
                    for via, egress in route.next_hops
                ]
                candidates.append(
                    RouteEntry(
                        route.code, route.network, route.distance, route.metric,
                        next_hops, float(route.age), "ospf",
                    )
                )

        # Host / switch default gateway becomes a candidate default route.
        if not node.ip_routing and node.default_gateway:
            egress = self._resolve_egress(node_name, node.default_gateway)
            if egress is not None:
                candidates.append(
                    RouteEntry(
                        "S*", ipaddress.ip_network("0.0.0.0/0"), AD_STATIC, 0,
                        [(node.default_gateway, egress)], 0.0, "gateway",
                    )
                )

        entries = self._install_best(node_name, candidates)
        gateway = None
        for entry in entries:
            if entry.is_default and entry.next_hops:
                gateway = entry.next_hops[0][0]
                break
        table = RoutingTable(
            node_name, entries, gateway, self._subnet_groups(entries)
        )
        self._table_cache[node_name] = table
        return table

    def _static_route_entry(self, node_name: str, static) -> Optional[RouteEntry]:
        try:
            network = ipaddress.ip_network(
                f"{static.prefix}/{static.mask}", strict=False
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return None
        code = "S*" if network.prefixlen == 0 else "S"
        distance = int(static.distance) if static.distance is not None else AD_STATIC
        if static.interface and not static.next_hop:
            return RouteEntry(
                code, network, distance, 0,
                [(None, canonical_interface(static.interface))], 0.0, "static",
            )
        if static.next_hop:
            egress = static.interface or self._resolve_egress(node_name, static.next_hop)
            if egress is None:
                # Recursive resolution through an already-known route.
                egress = self._recursive_egress(node_name, static.next_hop)
            if egress is None:
                return None  # unresolved next hop -> not installed
            return RouteEntry(
                code, network, distance, 0,
                [(static.next_hop, canonical_interface(egress))], 0.0, "static",
            )
        return None

    def _recursive_egress(self, node_name: str, next_hop: str) -> Optional[str]:
        """Resolve a non-connected static next hop one level through OSPF."""
        if self.ospf is None:
            return None
        node = self.nodes.get(node_name)
        if node is None or node.kind != "router":
            return None
        try:
            target = ipaddress.IPv4Address(next_hop)
        except ipaddress.AddressValueError:
            return None
        best = None
        for route in self.ospf.routes(node_name):
            if target in route.network and route.next_hops:
                if best is None or route.network.prefixlen > best.network.prefixlen:
                    best = route
        if best is None:
            return None
        return canonical_interface(best.next_hops[0][1])

    def _install_best(
        self, node_name: str, candidates: List[RouteEntry]
    ) -> List[RouteEntry]:
        max_paths = 4
        by_prefix: Dict[str, List[RouteEntry]] = {}
        for entry in candidates:
            by_prefix.setdefault(entry.network.with_prefixlen, []).append(entry)
        installed: List[RouteEntry] = []
        for prefix, group in by_prefix.items():
            best_distance = min(entry.distance for entry in group)
            at_distance = [e for e in group if e.distance == best_distance]
            best_metric = min(entry.metric for entry in at_distance)
            winners = [e for e in at_distance if e.metric == best_metric]
            primary = winners[0]
            merged: List[Tuple[Optional[str], str]] = []
            for winner in winners:
                for hop in winner.next_hops:
                    if hop not in merged:
                        merged.append(hop)
            merged.sort(key=lambda hop: (_ip_key(hop[0]), natural_key(hop[1])))
            installed.append(
                RouteEntry(
                    primary.code, primary.network, primary.distance,
                    primary.metric, merged[:max_paths], primary.age, primary.source,
                )
            )
        installed.sort(
            key=lambda entry: (
                int(entry.network.network_address),
                entry.network.prefixlen,
            )
        )
        return installed

    @staticmethod
    def _subnet_groups(entries: List[RouteEntry]) -> List[SubnetGroup]:
        groups: Dict[ipaddress.IPv4Network, set] = {}
        for entry in entries:
            if entry.is_default:
                continue
            major = _classful_supernet(entry.network)
            groups.setdefault(major, set()).add(entry.network.prefixlen)
        result = []
        for major, masks in groups.items():
            result.append(
                SubnetGroup(
                    major=major,
                    variably_subnetted=len(masks) > 1,
                    masks=len(masks),
                    route_count=len(masks),
                )
            )
        result.sort(key=lambda group: int(group.major.network_address))
        return result

    def lookup(self, node_name: str, address) -> Optional[RouteEntry]:
        return self.routing_table(node_name).lookup(address)

    # ---- forwarding -----------------------------------------------------
    def _resolve_target(self, destination: str) -> Optional[ipaddress.IPv4Address]:
        try:
            return ipaddress.IPv4Address(str(destination))
        except ipaddress.AddressValueError:
            pass
        if destination in self.nodes:
            owned = self.endpoints(destination)
            if owned:
                return min((e.address for e in owned), key=int)
        return None

    def _choose_hop(
        self, entry: RouteEntry, dst_ip: ipaddress.IPv4Address
    ) -> Tuple[Optional[str], str]:
        via, egress = entry.next_hops[0]
        if via is None:
            via = str(dst_ip)  # interface/connected static -> ARP for the dest
        return via, egress

    def forward(
        self,
        src_node: str,
        destination: str,
        src_address: Optional[str] = None,
        ttl: int = 255,
    ) -> ForwardResult:
        dst_ip = self._resolve_target(destination)
        if dst_ip is None:
            return ForwardResult(
                "no-route", [], [], [], src_node, None, str(destination)
            )
        hops: List[ForwardHop] = []
        legs: List[L2Leg] = []
        path: List[Tuple[str, str]] = []
        current = src_node
        ingress_ip: Optional[str] = None
        visited = set()
        guard = len(self.nodes) + 2

        while True:
            guard -= 1
            if guard < 0:
                return ForwardResult(
                    "ttl-exceeded", hops, path, legs, current, None, str(dst_ip)
                )
            if current != src_node:
                path.append((current, ingress_ip or ""))

            if self._owns(current, dst_ip):
                hops.append(ForwardHop(current, ingress_ip, None, None, None))
                return ForwardResult(
                    "delivered", hops, path, legs, current, current, str(dst_ip)
                )

            connected = self._connected_interface(current, dst_ip)
            if connected is not None:
                segment = connected.segment
                owner = self._owner_on_segment(segment, dst_ip)
                if owner is None:
                    hops.append(
                        ForwardHop(current, ingress_ip, None, connected.interface,
                                   str(dst_ip), segment)
                    )
                    return ForwardResult(
                        "arp-failure", hops, path, legs, current, None, str(dst_ip)
                    )
                legs.append(
                    L2Leg((current, connected.interface), (owner.node, owner.interface),
                          segment)
                )
                hops.append(
                    ForwardHop(current, ingress_ip, None, connected.interface,
                               str(dst_ip), segment)
                )
                path.append((owner.node, str(dst_ip)))
                hops.append(ForwardHop(owner.node, str(dst_ip), connected.interface,
                                       None, None, segment))
                return ForwardResult(
                    "delivered", hops, path, legs, owner.node, owner.node, str(dst_ip)
                )

            entry = self.routing_table(current).lookup(dst_ip)
            if entry is None:
                hops.append(ForwardHop(current, ingress_ip, None, None, None))
                return ForwardResult(
                    "no-route", hops, path, legs, current, None, str(dst_ip)
                )
            via, egress = self._choose_hop(entry, dst_ip)
            segment = self._segment(current, egress)
            try:
                via_ip = ipaddress.IPv4Address(via)
            except ipaddress.AddressValueError:
                hops.append(ForwardHop(current, ingress_ip, None, egress, via, segment))
                return ForwardResult(
                    "no-route", hops, path, legs, current, None, str(dst_ip)
                )
            owner = self._owner_on_segment(segment, via_ip)
            if owner is None:
                hops.append(ForwardHop(current, ingress_ip, None, egress, via, segment))
                return ForwardResult(
                    "arp-failure", hops, path, legs, current, None, str(dst_ip)
                )
            legs.append(
                L2Leg((current, egress), (owner.node, owner.interface), segment)
            )
            hops.append(ForwardHop(current, ingress_ip, None, egress, via, segment))

            if current in visited:
                return ForwardResult(
                    "host-unreachable", hops, path, legs, current, None, str(dst_ip)
                )
            visited.add(current)
            ttl -= 1
            if ttl <= 0:
                path.append((owner.node, via))
                return ForwardResult(
                    "ttl-exceeded", hops, path, legs, owner.node, None, str(dst_ip)
                )
            ingress_ip = via
            current = owner.node

    # ---- source-address + first-hop helpers -----------------------------
    def _egress_interface(
        self, node_name: str, dst_ip: ipaddress.IPv4Address
    ) -> Optional[str]:
        connected = self._connected_interface(node_name, dst_ip)
        if connected is not None:
            return connected.interface
        entry = self.routing_table(node_name).lookup(dst_ip)
        if entry is not None and entry.next_hops:
            return entry.next_hops[0][1]
        return None

    def _source_address(
        self, node_name: str, dst_ip: ipaddress.IPv4Address
    ) -> Optional[str]:
        if self._owns(node_name, dst_ip):
            return str(dst_ip)
        egress = self._egress_interface(node_name, dst_ip)
        if egress is None:
            return None
        interface = self._interface(node_name, egress)
        if interface is not None and interface.ip_address:
            return interface.ip_address
        # Egress is a sub-interface or SVI chosen by route; fall back to any ip.
        owned = self.endpoints(node_name)
        for endpoint in owned:
            if endpoint.interface == canonical_interface(egress):
                return str(endpoint.address)
        return str(owned[0].address) if owned else None

    def _first_hop(
        self, node_name: str, dst_ip: ipaddress.IPv4Address
    ) -> Optional[str]:
        if self._owns(node_name, dst_ip):
            return None
        connected = self._connected_interface(node_name, dst_ip)
        if connected is not None:
            return str(dst_ip)
        entry = self.routing_table(node_name).lookup(dst_ip)
        if entry is not None and entry.next_hops:
            via = entry.next_hops[0][0]
            return via if via is not None else str(dst_ip)
        return None

    # ---- ping -----------------------------------------------------------
    def _is_ios(self, node_name: str) -> bool:
        node = self.nodes.get(node_name)
        return node is not None and node.cli_profile != "vpcs"

    def _arp_known(self, node_name: str, address: str, now: float) -> bool:
        node = self.nodes.get(node_name)
        if node is None:
            return False
        entry = node.arp_cache.get(address)
        if entry is None:
            return False
        if entry.static:
            return True
        return (now - entry.learned_at) <= node.arp_timeout

    def ping(
        self,
        src_node: str,
        destination: str,
        repeat: int = 5,
        size: int = 100,
        timeout: int = 2,
        source: Optional[str] = None,
        now: Optional[float] = None,
        dry_run: bool = False,
    ) -> PingResult:
        now = self.now if now is None else float(now)
        dst_ip = self._resolve_target(destination)
        if dst_ip is None:
            return PingResult(
                str(destination), False, [], 0, repeat, 0, 0.0, 0.0, 0.0,
                error="invalid or unknown destination",
            )
        src_ip = source or self._source_address(src_node, dst_ip)
        first_hop = self._first_hop(src_node, dst_ip)
        is_ios = self._is_ios(src_node)
        arp_known = first_hop is None or self._arp_known(src_node, first_hop, now)

        probes: List[str] = []
        rtts: List[float] = []
        for index in range(repeat):
            forward = self.forward(src_node, str(dst_ip), src_address=src_ip)
            if forward.status == "no-route":
                probes.append(PROBE_UNREACHABLE)
                continue
            if not forward.delivered:
                probes.append(PROBE_TIMEOUT)
                continue

            # Round-trip requirement: the echo reply must find its way home.
            if forward.dest == src_node or src_ip is None:
                return_ok = True
                return_forward = None
            else:
                return_forward = self.forward(forward.dest, src_ip)
                return_ok = return_forward.delivered
            if not return_ok:
                probes.append(PROBE_TIMEOUT)
                continue

            # IOS loses the first echo while it resolves ARP for the first hop.
            if index == 0 and is_ios and not arp_known and first_hop is not None:
                probes.append(PROBE_TIMEOUT)
                arp_known = True
                if not dry_run:
                    self._learn_legs(forward.legs, now)
                continue

            # Switches learn the sender's MAC on the way (both directions); a
            # port-security violation drops this echo (and may err-disable).
            if not dry_run:
                dropped = self._learn_legs(forward.legs, now)
                if not dropped and return_forward is not None:
                    dropped = self._learn_legs(return_forward.legs, now)
                if dropped:
                    probes.append(PROBE_TIMEOUT)
                    continue

            probes.append(PROBE_SUCCESS)
            rtt = max(RTT_PER_HOP_MS, RTT_PER_HOP_MS * len(forward.path))
            rtts.append(rtt)
            if not dry_run:
                self._count_legs(forward.legs, size, now)

        success = probes.count(PROBE_SUCCESS)
        rate = int(round(100 * success / repeat)) if repeat else 0
        return PingResult(
            target=str(dst_ip),
            resolved=True,
            probes=probes,
            success=success,
            sent=repeat,
            success_rate=rate,
            rtt_min=min(rtts) if rtts else 0.0,
            rtt_avg=(sum(rtts) / len(rtts)) if rtts else 0.0,
            rtt_max=max(rtts) if rtts else 0.0,
            source_address=src_ip,
        )

    # ---- traceroute -----------------------------------------------------
    def traceroute(
        self,
        src_node: str,
        destination: str,
        max_ttl: int = 30,
        probes: int = 3,
        timeout: int = 3,
        source: Optional[str] = None,
        now: Optional[float] = None,
    ) -> TracerouteResult:
        dst_ip = self._resolve_target(destination)
        if dst_ip is None:
            return TracerouteResult(str(destination), False, [], False)
        src_ip = source or self._source_address(src_node, dst_ip)
        result = self.forward(src_node, str(dst_ip))
        path = result.path
        hops: List[TraceHop] = []
        reached = False
        # The source itself cannot forward (own address, or no route at all).
        if not path:
            if result.status == "delivered":
                hops.append(
                    TraceHop(
                        1,
                        [TraceProbe(str(dst_ip), RTT_PER_HOP_MS) for _ in range(probes)],
                        "ok",
                        True,
                    )
                )
                return TracerouteResult(str(dst_ip), True, hops, True, src_ip)
            status = "unreachable" if result.status == "no-route" else "host-unreachable"
            hops.append(
                TraceHop(1, [TraceProbe(None, None) for _ in range(probes)], status, True)
            )
            return TracerouteResult(str(dst_ip), True, hops, False, src_ip)
        for ttl in range(1, max_ttl + 1):
            if ttl <= len(path):
                node_name, address = path[ttl - 1]
                is_last = ttl == len(path)
                if is_last and result.status == "delivered":
                    hops.append(
                        TraceHop(ttl, [TraceProbe(address, ttl * RTT_PER_HOP_MS)
                                       for _ in range(probes)], "ok", True)
                    )
                    reached = True
                    break
                if is_last and result.status in ("no-route",):
                    hops.append(
                        TraceHop(ttl, [TraceProbe(address, ttl * RTT_PER_HOP_MS)],
                                 "unreachable", True)
                    )
                    break
                if is_last and result.status in ("host-unreachable", "arp-failure"):
                    hops.append(
                        TraceHop(ttl, [TraceProbe(address, ttl * RTT_PER_HOP_MS)],
                                 "host-unreachable", True)
                    )
                    break
                hops.append(
                    TraceHop(ttl, [TraceProbe(address, ttl * RTT_PER_HOP_MS)
                                   for _ in range(probes)], "ok", False)
                )
            else:
                if result.status == "delivered":
                    break
                hops.append(
                    TraceHop(ttl, [TraceProbe(None, None) for _ in range(probes)],
                             "timeout", False)
                )
        return TracerouteResult(str(dst_ip), True, hops, reached, src_ip)

    # ---- ARP ------------------------------------------------------------
    def _learn_legs(self, legs: List[L2Leg], now: float) -> bool:
        """Learn ARP (and, via ``mac_learner``, switch MACs) along ``legs``.

        Returns True when a switch dropped the frame (port security).  When
        learning err-disabled a switchport the cached topology is invalidated.
        """
        for leg in legs:
            self._learn_one(leg.src[0], leg.src[1], leg.dst[0], leg.dst[1], now)
            self._learn_one(leg.dst[0], leg.dst[1], leg.src[0], leg.src[1], now)
        if self.mac_learner is None:
            return False
        outcome = self.mac_learner(legs, now)
        if outcome == "errdisabled":
            # The forwarding topology changed, so cached lookups are stale.
            self.invalidate()
        return bool(outcome)

    def invalidate(self) -> None:
        """Drop cached endpoints and routing tables (topology changed)."""
        self._endpoints_cache = None
        self._by_node = {}
        self._by_segment = {}
        self._by_address = {}
        self._table_cache = {}

    def _learn_one(
        self, learner: str, learner_if: str, peer: str, peer_if: str, now: float
    ) -> None:
        learner_node = self.nodes.get(learner)
        peer_node = self.nodes.get(peer)
        if learner_node is None or peer_node is None:
            return
        peer_interface = peer_node.interfaces.get(canonical_interface(peer_if))
        if peer_interface is None or not peer_interface.ip_address:
            return
        mac = peer_node.interface_mac(peer_if)
        if not mac:
            return
        learner_node.arp_cache[peer_interface.ip_address] = ArpEntry(
            address=peer_interface.ip_address,
            mac=mac,
            interface=canonical_interface(learner_if),
            learned_at=now,
            static=False,
        )

    def _count_legs(self, legs: List[L2Leg], size: int, now: float) -> None:
        for leg in legs:
            self._count_one(leg.src[0], leg.src[1], size, now, outbound=True)
            self._count_one(leg.dst[0], leg.dst[1], size, now, outbound=False)

    def _count_one(
        self, node_name: str, interface_name: str, size: int, now: float, outbound: bool
    ) -> None:
        interface = self._interface(node_name, interface_name)
        if interface is None:
            return
        counters = interface.counters
        if outbound:
            counters.packets_out += 1
            counters.bytes_out += size
            interface.last_output = now
        else:
            counters.packets_in += 1
            counters.bytes_in += size
            interface.last_input = now

    def arp_table(self, node_name: str, now: Optional[float] = None) -> List[ArpRow]:
        now = self.now if now is None else float(now)
        node = self.nodes.get(node_name)
        if node is None:
            return []
        rows: List[ArpRow] = []
        own_addresses = set()
        for endpoint in self.endpoints(node_name):
            own_addresses.add(str(endpoint.address))
            mac = node.interface_mac(endpoint.interface)
            if not mac:
                continue
            rows.append(
                ArpRow(
                    address=str(endpoint.address),
                    age="-",
                    mac=format_mac(mac, "cisco"),
                    interface=endpoint.interface,
                )
            )
        for address, entry in node.arp_cache.items():
            if address in own_addresses:
                continue
            if not entry.static and (now - entry.learned_at) > node.arp_timeout:
                continue  # aged out
            age = "-" if entry.static else str(int((now - entry.learned_at) // 60))
            rows.append(
                ArpRow(
                    address=address,
                    age=age,
                    mac=format_mac(entry.mac, "cisco"),
                    interface=entry.interface,
                )
            )
        rows.sort(key=lambda row: _ip_key(row.address))
        return rows

    def clear_arp(self, node_name: str) -> None:
        node = self.nodes.get(node_name)
        if node is None:
            return
        for address in [a for a, e in node.arp_cache.items() if not e.static]:
            node.arp_cache.pop(address, None)

    # ---- reachability (callbacks.reachable) -----------------------------
    def reachable(
        self, src_node: str, destination: str, now: Optional[float] = None
    ) -> bool:
        dst_ip = self._resolve_target(destination)
        if dst_ip is None:
            return False
        forward = self.forward(src_node, str(dst_ip))
        if not forward.delivered:
            return False
        if self.mac_filter is not None and not self.mac_filter(forward.legs):
            return False
        if forward.dest == src_node:
            return True
        src_ip = self._source_address(src_node, dst_ip)
        if src_ip is None:
            return False
        reply = self.forward(forward.dest, src_ip)
        if not reply.delivered:
            return False
        return self.mac_filter is None or bool(self.mac_filter(reply.legs))


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------
def _ip_key(address: Optional[str]) -> int:
    if not address:
        return -1
    try:
        return int(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError:
        return -1


def _classful_supernet(network: ipaddress.IPv4Network) -> ipaddress.IPv4Network:
    """Return the classful (A/B/C) network that contains *network*."""
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
    return ipaddress.ip_network(
        f"{network.network_address}/{prefix}", strict=False
    )
