"""Deterministic OSPFv2 engine: adjacency, DR/BDR, LSDB and SPF routes.

The engine is pure and side-effect free.  It reads :class:`NodeState` objects
but never mutates them.  Topology/L2 awareness arrives through the shared
:class:`adapters.NetworkCallbacks` bundle; OSPF only ever consults
``callbacks.segment_of`` and ``callbacks.line_protocol_up`` (it computes
reachability itself).  Build a fresh engine after any L2/interface change.

Public API (consumed by the CLI and by :mod:`simulator.l3`)
-----------------------------------------------------------
``OspfEngine(nodes, links, callbacks, now)``

* ``router_id(node) -> Optional[str]``
* ``routes(node) -> list[OspfRoute]`` (the L3 contract; see ``OspfRoute``)
* ``neighbors(node) -> list[OspfNeighbor]`` (``show ip ospf neighbor``)
* ``interfaces(node) -> list[OspfInterfaceDetail]`` (``show ip ospf interface``)
* ``database(node) -> dict[int, list[LsaEntry]]`` (``show ip ospf database``)
* ``process_summary(node) -> list[ProcessSummary]`` (``show ip protocols``)
* compatibility helpers ``ospf_neighbors(node)`` / ``route_entries(node, ospf_only)``
  matching the legacy :class:`network.NetworkEngine`.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import heapq
import ipaddress
from typing import Dict, Hashable, Iterable, List, Optional, Tuple

from .models import (
    NodeState,
    canonical_interface,
    natural_key,
)
from .adapters import NetworkCallbacks


Link = Tuple[str, str, str, str]

DEFAULT_HELLO = 10
DEFAULT_DEAD = 40
DEFAULT_PRIORITY = 1
DEFAULT_BANDWIDTH_KBPS = 10000  # IOL Ethernet is 10 Mbit/s by default
LOOPBACK_COST = 1
OSPF_DISTANCE = 110
DEFAULT_MAXIMUM_PATHS = 4

NETWORK_BROADCAST = "broadcast"
NETWORK_P2P = "point-to-point"
NETWORK_LOOPBACK = "loopback"


def normalise_network_statement(address: str, bits: str) -> Tuple[str, str]:
    """``network <address> <bits> area N`` as IOS stores it.

    IOS takes wildcard bits or a subnet mask: a contiguous mask with leading
    one bits (``255.255.255.0``) becomes wildcard bits (``0.0.0.255``), and the
    host bits of the address are cleared (``10.1.1.1 0.0.0.255`` is stored as
    ``10.1.1.0 0.0.0.255``).  ``0.0.0.0 0.0.0.0`` is the match-all form and
    becomes ``0.0.0.0 255.255.255.255``.  Raises ``ValueError`` for an invalid
    dotted quad.
    """
    value = int(ipaddress.IPv4Address(address))
    wildcard = int(ipaddress.IPv4Address(bits))
    if value == 0 and wildcard == 0:
        wildcard = 0xFFFFFFFF
    elif wildcard & 0x80000000 and wildcard != 0xFFFFFFFF:
        inverted = (~wildcard) & 0xFFFFFFFF
        if inverted & (inverted + 1) == 0:  # leading ones, then zeros: a mask
            wildcard = inverted
    value &= (~wildcard) & 0xFFFFFFFF
    return str(ipaddress.IPv4Address(value)), str(ipaddress.IPv4Address(wildcard))


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class OspfInterface:
    """One OSPF-enabled interface, resolved with its effective parameters."""

    node: str
    name: str
    ip: str
    network: ipaddress.IPv4Network
    area: int
    process_id: int
    router_id: str
    cost: int
    priority: int
    hello: int
    dead: int
    network_type: str
    passive: bool
    segment: Hashable
    loopback: bool

    @property
    def key(self) -> Tuple[str, str]:
        return (self.node, self.name)


@dataclass
class OspfNeighbor:
    neighbor_id: str
    neighbor: str
    priority: int
    state: str
    dead_time: str
    address: str
    local_interface: str
    area: int
    uptime: float
    role: str


@dataclass
class OspfInterfaceDetail:
    name: str
    ip: Optional[str]
    netmask: Optional[str]
    area: int
    process_id: int
    router_id: str
    cost: int
    state: str
    priority: int
    dr_id: Optional[str]
    dr_address: Optional[str]
    bdr_id: Optional[str]
    bdr_address: Optional[str]
    hello: int
    dead: int
    network_type: str
    passive: bool
    neighbor_count: int
    adjacent_count: int


@dataclass
class OspfRoute:
    """A route produced by SPF; the shape consumed by :mod:`simulator.l3`."""

    network: ipaddress.IPv4Network
    code: str  # "O", "O IA", "O E2", "O*E2"
    distance: int
    metric: int
    next_hops: List[Tuple[str, str]]  # (next_hop_ip, egress_interface)
    age: float


@dataclass
class LsaEntry:
    lsa_type: str  # "router" | "network"
    link_id: str
    adv_router: str
    age: int
    seq: int
    checksum: int
    link_count: int
    area: int


@dataclass
class RouteSource:
    router_id: str
    distance: int
    last_update: str


@dataclass
class ProcessSummary:
    process_id: int
    router_id: Optional[str]
    areas: List[int]
    networks: List[Tuple[str, str, int]]
    passive_interfaces: List[str]
    reference_bandwidth_mbps: int
    maximum_paths: int
    distance: int
    shutdown: bool
    sources: List[RouteSource] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ip_int(address: Optional[str]) -> int:
    if not address:
        return -1
    try:
        return int(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError:
        return -1


def _hms(seconds: float) -> str:
    seconds = int(max(0, seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _wildcard_matches(address_int: int, network_int: int, wildcard_int: int) -> bool:
    mask = (~wildcard_int) & 0xFFFFFFFF
    return (address_int & mask) == (network_int & mask)


def interface_ospf_area(interface, process, process_id: int) -> Optional[int]:
    """Area ``interface`` runs in for OSPF ``process_id``, from configuration.

    ``ip ospf <pid> area <a>`` on the interface wins; otherwise the first
    ``network`` statement of the process that matches the primary address.
    ``None`` when the interface is not in that process.
    """
    if interface.ospf_process is not None:
        if interface.ospf_process != process_id:
            return None
        return int(interface.ospf_area or 0)
    address_int = _ip_int(interface.ip_address)
    if address_int < 0:
        return None
    for network, wildcard, area in process.networks:
        if _wildcard_matches(address_int, _ip_int(network), _ip_int(wildcard)):
            return int(area)
    return None


class OspfEngine:
    """Computes OSPF adjacency, LSDB and routes from canonical node state."""

    def __init__(
        self,
        nodes: Dict[str, NodeState],
        links: Iterable[Link],
        callbacks: NetworkCallbacks,
        now: float,
    ) -> None:
        self.nodes = nodes
        self.links: List[Link] = [
            (a, canonical_interface(ai), b, canonical_interface(bi))
            for a, ai, b, bi in links
        ]
        self.callbacks = callbacks
        self.now = float(now)
        self._node_ifaces: Dict[str, List[OspfInterface]] = {}
        self._all_cache: Optional[List[OspfInterface]] = None
        self._groups_cache: Optional[Dict[tuple, List[OspfInterface]]] = None

    # ---- interface resolution -------------------------------------------
    def invalidate(self) -> None:
        """Drop cached OSPF interfaces (the L2 topology changed underneath)."""
        self._node_ifaces = {}
        self._all_cache = None
        self._groups_cache = None

    def _up(self, node_name: str, interface_name: str) -> bool:
        return bool(self.callbacks.line_protocol_up(node_name, interface_name))

    def _segment(self, node_name: str, interface_name: str) -> Hashable:
        return self.callbacks.segment_of(node_name, interface_name)

    def _up_ip_interfaces(self, node_name: str):
        """Yield (interface, network) for every up interface with an IPv4."""
        node = self.nodes.get(node_name)
        if node is None:
            return
        for interface in node.interfaces.values():
            if not interface.ip_address or interface.network is None:
                continue
            if not self._up(node_name, interface.name):
                continue
            yield interface

    def _router_id_for_process(self, node_name: str, process) -> Optional[str]:
        if process.router_id:
            return process.router_id
        node = self.nodes.get(node_name)
        if node is None:
            return None
        loopbacks = [
            interface.ip_address
            for interface in self._up_ip_interfaces(node_name)
            if interface.name.startswith("Loopback")
        ]
        if loopbacks:
            return max(loopbacks, key=_ip_int)
        others = [
            interface.ip_address for interface in self._up_ip_interfaces(node_name)
        ]
        if others:
            return max(others, key=_ip_int)
        return None

    def _interface_area(self, interface, process, process_id: int) -> Optional[int]:
        """Return the area this interface runs in for *process*, or ``None``."""
        return interface_ospf_area(interface, process, process_id)

    def _node_ospf_interfaces(self, node_name: str) -> List[OspfInterface]:
        cached = self._node_ifaces.get(node_name)
        if cached is not None:
            return cached
        result: List[OspfInterface] = []
        node = self.nodes.get(node_name)
        if node is None or node.kind != "router":
            self._node_ifaces[node_name] = result
            return result

        claimed: Dict[str, bool] = {}
        for process_id in sorted(node.ospf_processes):
            process = node.ospf_processes[process_id]
            if process.shutdown:
                continue
            router_id = self._router_id_for_process(node_name, process)
            if router_id is None:
                continue
            passive_set = {canonical_interface(name) for name in process.passive_interfaces}
            non_passive = {
                canonical_interface(name) for name in process.non_passive_interfaces
            }
            for interface in self._up_ip_interfaces(node_name):
                name = interface.name
                if name in claimed:
                    continue
                area = self._interface_area(interface, process, process_id)
                if area is None:
                    continue
                claimed[name] = True
                loopback = name.startswith("Loopback")
                if loopback:
                    network = ipaddress.ip_network(f"{interface.ip_address}/32")
                    network_type = NETWORK_LOOPBACK
                    cost = LOOPBACK_COST
                else:
                    network = interface.network
                    if interface.ospf_network_type:
                        network_type = (
                            NETWORK_P2P
                            if "point" in interface.ospf_network_type
                            else interface.ospf_network_type
                        )
                    else:
                        network_type = NETWORK_BROADCAST
                    if interface.ospf_cost is not None:
                        cost = int(interface.ospf_cost)
                    else:
                        bandwidth = interface.bandwidth_kbps or DEFAULT_BANDWIDTH_KBPS
                        cost = max(1, (process.reference_bandwidth_mbps * 1000) // bandwidth)
                passive = (
                    name in passive_set
                    or (process.passive_default and name not in non_passive)
                )
                result.append(
                    OspfInterface(
                        node=node_name,
                        name=name,
                        ip=interface.ip_address,
                        network=network,
                        area=area,
                        process_id=process_id,
                        router_id=router_id,
                        cost=int(cost),
                        priority=int(
                            interface.ospf_priority
                            if interface.ospf_priority is not None
                            else DEFAULT_PRIORITY
                        ),
                        hello=int(interface.ospf_hello_interval or DEFAULT_HELLO),
                        dead=int(interface.ospf_dead_interval or DEFAULT_DEAD),
                        network_type=network_type,
                        passive=bool(passive),
                        segment=self._segment(node_name, name),
                        loopback=loopback,
                    )
                )
        result.sort(key=lambda item: natural_key(item.name))
        self._node_ifaces[node_name] = result
        return result

    def _all_ospf_interfaces(self) -> List[OspfInterface]:
        if self._all_cache is None:
            out: List[OspfInterface] = []
            for node_name in self.nodes:
                out.extend(self._node_ospf_interfaces(node_name))
            self._all_cache = out
        return self._all_cache

    # ---- adjacency / DR-BDR ---------------------------------------------
    def _groups(self) -> Dict[tuple, List[OspfInterface]]:
        """Group transit/p2p interfaces that are mutually adjacent."""
        if self._groups_cache is not None:
            return self._groups_cache
        groups: Dict[tuple, List[OspfInterface]] = defaultdict(list)
        for oi in self._all_ospf_interfaces():
            if oi.passive or oi.loopback:
                continue
            if oi.network_type not in (NETWORK_BROADCAST, NETWORK_P2P):
                continue
            if oi.segment is None:
                continue
            key = (
                oi.area,
                oi.segment,
                oi.network.with_prefixlen,
                oi.hello,
                oi.dead,
                oi.network_type,
            )
            groups[key].append(oi)
        self._groups_cache = groups
        return groups

    def _group_for(self, oi: OspfInterface) -> List[OspfInterface]:
        key = (
            oi.area,
            oi.segment,
            oi.network.with_prefixlen,
            oi.hello,
            oi.dead,
            oi.network_type,
        )
        return self._groups().get(key, [])

    @staticmethod
    def _dr_bdr(members: List[OspfInterface]):
        candidates = [member for member in members if member.priority > 0]
        candidates.sort(
            key=lambda member: (member.priority, _ip_int(member.router_id)),
            reverse=True,
        )
        designated = candidates[0] if candidates else None
        backup = candidates[1] if len(candidates) > 1 else None
        return designated, backup

    def _neighbours_of(self, oi: OspfInterface) -> List[OspfInterface]:
        members = self._group_for(oi)
        return [
            member
            for member in members
            if member.node != oi.node and member.router_id != oi.router_id
        ]

    def _dead_time(self, dead: int) -> str:
        # Deterministic sawtooth that stays just below the dead interval.
        span = 10 if dead > 10 else max(1, dead)
        remaining = dead - 1 - (int(self.now) % span)
        return _hms(remaining)

    def _uptime(self) -> float:
        return float(int(self.now) % 3600)

    # ---- public: neighbours ---------------------------------------------
    def neighbors(self, node_name: str) -> List[OspfNeighbor]:
        rows: List[OspfNeighbor] = []
        for oi in self._node_ospf_interfaces(node_name):
            if oi.passive or oi.loopback:
                continue
            members = self._group_for(oi)
            designated, backup = self._dr_bdr(members)

            def role_of(member: OspfInterface) -> str:
                if oi.network_type == NETWORK_P2P:
                    return "-"
                if designated and member.key == designated.key:
                    return "DR"
                if backup and member.key == backup.key:
                    return "BDR"
                return "DROTHER"

            local_role = role_of(oi)
            for neighbour in self._neighbours_of(oi):
                neighbour_role = role_of(neighbour)
                if oi.network_type == NETWORK_P2P:
                    state = "FULL/  -"
                elif local_role in ("DR", "BDR") or neighbour_role in ("DR", "BDR"):
                    state = f"FULL/{neighbour_role}"
                else:
                    state = f"2WAY/{neighbour_role}"
                rows.append(
                    OspfNeighbor(
                        neighbor_id=neighbour.router_id,
                        neighbor=neighbour.node,
                        priority=neighbour.priority,
                        state=state,
                        dead_time=self._dead_time(oi.dead),
                        address=neighbour.ip,
                        local_interface=oi.name,
                        area=oi.area,
                        uptime=self._uptime(),
                        role=neighbour_role,
                    )
                )
        rows.sort(
            key=lambda row: (
                row.area,
                _ip_int(row.neighbor_id),
                natural_key(row.local_interface),
            )
        )
        return rows

    # ---- public: interface detail ---------------------------------------
    def interfaces(self, node_name: str) -> List[OspfInterfaceDetail]:
        details: List[OspfInterfaceDetail] = []
        for oi in self._node_ospf_interfaces(node_name):
            netmask = str(oi.network.netmask) if not oi.loopback else "255.255.255.255"
            if oi.loopback:
                state = "LOOP"
                dr_id = dr_addr = bdr_id = bdr_addr = None
                neighbour_count = adjacent_count = 0
            elif oi.network_type == NETWORK_P2P:
                state = "P2P"
                dr_id = dr_addr = bdr_id = bdr_addr = None
                neighbours = self._neighbours_of(oi)
                neighbour_count = adjacent_count = len(neighbours)
            else:
                members = self._group_for(oi)
                designated, backup = self._dr_bdr(members)
                if designated and oi.key == designated.key:
                    state = "DR"
                elif backup and oi.key == backup.key:
                    state = "BDR"
                elif oi.passive:
                    state = "DR"
                else:
                    state = "DROTHER"
                dr_id = designated.router_id if designated else None
                dr_addr = designated.ip if designated else None
                bdr_id = backup.router_id if backup else None
                bdr_addr = backup.ip if backup else None
                neighbours = self._neighbours_of(oi)
                neighbour_count = len(neighbours)
                adjacent_count = sum(
                    1
                    for neighbour in neighbours
                    if (designated and neighbour.key == designated.key)
                    or (backup and neighbour.key == backup.key)
                    or (designated and oi.key == designated.key)
                    or (backup and oi.key == backup.key)
                )
            if oi.passive:
                neighbour_count = adjacent_count = 0
            details.append(
                OspfInterfaceDetail(
                    name=oi.name,
                    ip=oi.ip,
                    netmask=netmask,
                    area=oi.area,
                    process_id=oi.process_id,
                    router_id=oi.router_id,
                    cost=oi.cost,
                    state=state,
                    priority=oi.priority,
                    dr_id=dr_id,
                    dr_address=dr_addr,
                    bdr_id=bdr_id,
                    bdr_address=bdr_addr,
                    hello=oi.hello,
                    dead=oi.dead,
                    network_type=oi.network_type,
                    passive=oi.passive,
                    neighbor_count=neighbour_count,
                    adjacent_count=adjacent_count,
                )
            )
        details.sort(key=lambda item: natural_key(item.name))
        return details

    # ---- SPF ------------------------------------------------------------
    def _area_adjacency(self, area: int):
        """Return (adj, reverse) edge maps among routers in *area*."""
        adj: Dict[str, List[tuple]] = defaultdict(list)
        reverse: Dict[str, List[tuple]] = defaultdict(list)
        for key, members in self._groups().items():
            if key[0] != area:
                continue
            for left in members:
                for right in members:
                    if left.node == right.node or left.router_id == right.router_id:
                        continue
                    adj[left.node].append((right.node, left.cost, right.ip, left.name))
                    reverse[right.node].append((left.node, left.cost, right.ip, left.name))
        return adj, reverse

    def _spf(self, source: str, area: int):
        """Dijkstra over the area graph; return (dist, firsthop)."""
        adj, reverse = self._area_adjacency(area)
        dist: Dict[str, int] = {source: 0}
        heap: List[tuple] = [(0, source)]
        while heap:
            distance, node_name = heapq.heappop(heap)
            if distance > dist.get(node_name, float("inf")):
                continue
            for neighbour, weight, _ip, _egress in adj.get(node_name, ()):  # noqa: E501
                candidate = distance + weight
                if candidate < dist.get(neighbour, float("inf")):
                    dist[neighbour] = candidate
                    heapq.heappush(heap, (candidate, neighbour))

        firsthop: Dict[str, frozenset] = {source: frozenset()}
        for node_name in sorted(dist, key=lambda item: (dist[item], item)):
            if node_name == source:
                continue
            hops = set()
            for predecessor, weight, via_ip, egress in reverse.get(node_name, ()):  # noqa: E501
                if predecessor not in dist:
                    continue
                if dist[predecessor] + weight != dist[node_name]:
                    continue
                if predecessor == source:
                    hops.add((via_ip, egress))
                else:
                    hops |= firsthop.get(predecessor, frozenset())
            firsthop[node_name] = frozenset(hops)
        return dist, firsthop

    def _source_process_values(self, node_name: str) -> Tuple[int, int]:
        """Return (distance, maximum_paths) for the node's OSPF process."""
        node = self.nodes.get(node_name)
        distance = OSPF_DISTANCE
        max_paths = DEFAULT_MAXIMUM_PATHS
        if node is not None and node.ospf_processes:
            active = [
                process
                for process in node.ospf_processes.values()
                if not process.shutdown
            ]
            if active:
                distance = min(process.distance for process in active)
                max_paths = min(process.maximum_paths for process in active)
        return distance, max_paths

    @staticmethod
    def _has_default_route(node: NodeState) -> bool:
        for route in node.static_routes:
            if _ip_int(route.prefix) == 0 and _ip_int(route.mask) == 0:
                return True
        return False

    def routes(self, node_name: str) -> List[OspfRoute]:
        node = self.nodes.get(node_name)
        if node is None or node.kind != "router" or not node.ip_routing:
            return []
        by_area: Dict[int, List[OspfInterface]] = defaultdict(list)
        for oi in self._all_ospf_interfaces():
            by_area[oi.area].append(oi)

        distance, max_paths = self._source_process_values(node_name)
        age = float(int(self.now) % 1800)
        best: Dict[ipaddress.IPv4Network, OspfRoute] = {}
        area_spf: Dict[int, tuple] = {}

        for area, ifaces in by_area.items():
            dist, firsthop = self._spf(node_name, area)
            area_spf[area] = (dist, firsthop)
            attached: Dict[ipaddress.IPv4Network, List[tuple]] = defaultdict(list)
            for oi in ifaces:
                attached[oi.network].append((oi.node, oi.cost, oi))
            for network, owners in attached.items():
                if any(owner == node_name for owner, _cost, _oi in owners):
                    continue  # directly connected -> handled as a C route by L3
                metric: Optional[int] = None
                hops: set = set()
                for owner, cost, _oi in owners:
                    if owner not in dist:
                        continue
                    candidate = dist[owner] + cost
                    if metric is None or candidate < metric:
                        metric = candidate
                        hops = set(firsthop.get(owner, frozenset()))
                    elif candidate == metric:
                        hops |= firsthop.get(owner, frozenset())
                if metric is None or not hops:
                    continue
                self._merge_route(
                    best,
                    OspfRoute(
                        network=network,
                        code="O",
                        distance=distance,
                        metric=metric,
                        next_hops=self._order_hops(hops, max_paths),
                        age=age,
                    ),
                )

        self._emit_default(node_name, area_spf, distance, max_paths, age, best)

        return sorted(
            best.values(),
            key=lambda route: (
                int(route.network.network_address),
                route.network.prefixlen,
            ),
        )

    @staticmethod
    def _order_hops(hops, max_paths: int) -> List[Tuple[str, str]]:
        ordered = sorted(hops, key=lambda hop: (_ip_int(hop[0]), natural_key(hop[1])))
        return ordered[:max_paths]

    @staticmethod
    def _merge_route(best: Dict, route: OspfRoute) -> None:
        existing = best.get(route.network)
        if existing is None:
            best[route.network] = route
            return
        # Lower administrative distance wins, then lower metric; intra-area O
        # beats external on an equal footing for our single-area labs.
        if (route.distance, route.metric) < (existing.distance, existing.metric):
            best[route.network] = route
        elif (route.distance, route.metric) == (existing.distance, existing.metric):
            merged = {tuple(hop) for hop in existing.next_hops} | {
                tuple(hop) for hop in route.next_hops
            }
            existing.next_hops = sorted(
                merged, key=lambda hop: (_ip_int(hop[0]), natural_key(hop[1]))
            )

    def _emit_default(
        self,
        source: str,
        area_spf: Dict[int, tuple],
        distance: int,
        max_paths: int,
        age: float,
        best: Dict,
    ) -> None:
        default_network = ipaddress.ip_network("0.0.0.0/0")
        metric: Optional[int] = None
        hops: set = set()
        for node_name, node in self.nodes.items():
            if node_name == source or node.kind != "router":
                continue
            originates = False
            for process in node.ospf_processes.values():
                if process.shutdown or not process.default_information_originate:
                    continue
                if process.default_information_always or self._has_default_route(node):
                    originates = True
                    break
            if not originates:
                continue
            for _area, (dist, firsthop) in area_spf.items():
                if node_name not in dist:
                    continue
                candidate = dist[node_name]
                if metric is None or candidate < metric:
                    metric = candidate
                    hops = set(firsthop.get(node_name, frozenset()))
                elif candidate == metric:
                    hops |= firsthop.get(node_name, frozenset())
        if metric is None or not hops:
            return
        best[default_network] = OspfRoute(
            network=default_network,
            code="O*E2",
            distance=distance,
            metric=1,
            next_hops=self._order_hops(hops, max_paths),
            age=age,
        )

    # ---- LSDB -----------------------------------------------------------
    def database(self, node_name: str) -> Dict[int, List[LsaEntry]]:
        node = self.nodes.get(node_name)
        if node is None or node.kind != "router" or not node.ospf_processes:
            return {}
        local_areas = {oi.area for oi in self._node_ospf_interfaces(node_name)}
        lsdb: Dict[int, List[LsaEntry]] = {}
        age = int(self.now) % 1800
        by_area_router: Dict[int, Dict[str, List[OspfInterface]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for oi in self._all_ospf_interfaces():
            by_area_router[oi.area][oi.router_id].append(oi)

        for area in sorted(local_areas):
            entries: List[LsaEntry] = []
            for router_id in sorted(by_area_router[area], key=_ip_int):
                owned = by_area_router[area][router_id]
                entries.append(
                    LsaEntry(
                        lsa_type="router",
                        link_id=router_id,
                        adv_router=router_id,
                        age=age,
                        seq=0x80000001,
                        checksum=self._checksum("router", router_id, area),
                        link_count=len(owned),
                        area=area,
                    )
                )
            seen_segments = set()
            for key, members in self._groups().items():
                if key[0] != area or len(members) < 2:
                    continue
                designated, _backup = self._dr_bdr(members)
                if designated is None or designated.segment in seen_segments:
                    continue
                seen_segments.add(designated.segment)
                entries.append(
                    LsaEntry(
                        lsa_type="network",
                        link_id=designated.ip,
                        adv_router=designated.router_id,
                        age=age,
                        seq=0x80000001,
                        checksum=self._checksum("network", designated.ip, area),
                        link_count=len(members),
                        area=area,
                    )
                )
            lsdb[area] = entries
        return lsdb

    @staticmethod
    def _checksum(kind: str, identifier: str, area: int) -> int:
        token = f"{kind}:{identifier}:{area}"
        return (abs(hash(token)) % 0xFFFE) + 1

    # ---- process summary -------------------------------------------------
    def process_summary(self, node_name: str) -> List[ProcessSummary]:
        node = self.nodes.get(node_name)
        if node is None or node.kind != "router":
            return []
        summaries: List[ProcessSummary] = []
        node_ifaces = self._node_ospf_interfaces(node_name)
        for process_id in sorted(node.ospf_processes):
            process = node.ospf_processes[process_id]
            areas = sorted(
                {oi.area for oi in node_ifaces if oi.process_id == process_id}
            )
            sources = []
            for neighbour in self.neighbors(node_name):
                if neighbour.state.startswith("FULL"):
                    sources.append(
                        RouteSource(
                            router_id=neighbour.neighbor_id,
                            distance=process.distance,
                            last_update=_hms(self._uptime()),
                        )
                    )
            summaries.append(
                ProcessSummary(
                    process_id=process_id,
                    router_id=self._router_id_for_process(node_name, process),
                    areas=areas,
                    networks=list(process.networks),
                    passive_interfaces=sorted(
                        {canonical_interface(name) for name in process.passive_interfaces},
                        key=natural_key,
                    ),
                    reference_bandwidth_mbps=process.reference_bandwidth_mbps,
                    maximum_paths=process.maximum_paths,
                    distance=process.distance,
                    shutdown=process.shutdown,
                    sources=sources,
                )
            )
        return summaries

    # ---- the L3 contract -------------------------------------------------
    def router_id(self, node_name: str) -> Optional[str]:
        node = self.nodes.get(node_name)
        if node is None or not node.ospf_processes:
            return None
        for process_id in sorted(node.ospf_processes):
            process = node.ospf_processes[process_id]
            if process.shutdown:
                continue
            router_id = self._router_id_for_process(node_name, process)
            if router_id:
                return router_id
        return None

    # ---- diagnostics (read-only, for grading feedback) -------------------
    def _silent_neighbours(self, node_name: str, oi: OspfInterface) -> List[str]:
        """Routers on ``oi``'s link with an up IPv4 interface not running OSPF."""
        enabled = {item.key for item in self._all_ospf_interfaces()}
        found: List[str] = []
        for other_name, other in self.nodes.items():
            if other_name == node_name or other.kind != "router":
                continue
            for interface in self._up_ip_interfaces(other_name):
                if (other_name, interface.name) in enabled:
                    continue
                if self._segment(other_name, interface.name) == oi.segment:
                    found.append(f"{other_name} {interface.name}")
        return found

    def diagnose(self, node_name: str) -> List[str]:
        """Why ``node_name`` has no FULL adjacency, in plain language.

        Mirrors the adjacency rules of :meth:`_groups` (same area, link,
        subnet, hello/dead timers and network type; not passive) and changes
        nothing.  Returns an empty list when no reason is found.
        """
        node = self.nodes.get(node_name)
        if node is None or node.kind != "router":
            return []
        processes = [node.ospf_processes[pid] for pid in sorted(node.ospf_processes)]
        if not processes:
            return ["no OSPF process is configured"]
        if all(process.shutdown for process in processes):
            return ["the OSPF process is shut down"]
        if self.router_id(node_name) is None:
            return ["OSPF has no router ID because no interface with an IPv4 address is up"]
        mine = [oi for oi in self._node_ospf_interfaces(node_name) if not oi.loopback]
        if not mine:
            return [
                "no up interface is enabled for OSPF; check the network statements "
                "and their wildcard masks"
            ]
        others = [
            oi for oi in self._all_ospf_interfaces()
            if oi.node != node_name and not oi.loopback
        ]
        problems: List[str] = []
        for oi in mine:
            if oi.passive:
                problems.append(f"{oi.name} is a passive interface, so it sends no hellos")
                continue
            if oi.segment is None:
                problems.append(f"{oi.name} has no working link")
                continue
            peers = [other for other in others if other.segment == oi.segment]
            if not peers:
                silent = self._silent_neighbours(node_name, oi)
                if silent:
                    problems.append(
                        f"{', '.join(silent)} on the link of {oi.name} does not run OSPF"
                    )
                else:
                    problems.append(f"no other OSPF router is on the link of {oi.name}")
                continue
            for peer in peers:
                label = f"{peer.node} {peer.name}"
                if peer.passive:
                    problems.append(f"{label} is a passive interface")
                if peer.area != oi.area:
                    problems.append(
                        f"area mismatch: {oi.name} is in area {oi.area}, "
                        f"{label} is in area {peer.area}"
                    )
                if peer.network.with_prefixlen != oi.network.with_prefixlen:
                    problems.append(
                        f"subnet mismatch: {oi.name} is on {oi.network.with_prefixlen}, "
                        f"{label} is on {peer.network.with_prefixlen}"
                    )
                if (peer.hello, peer.dead) != (oi.hello, oi.dead):
                    problems.append(
                        f"timer mismatch: {oi.name} uses hello {oi.hello}/dead {oi.dead}, "
                        f"{label} uses hello {peer.hello}/dead {peer.dead}"
                    )
                if peer.network_type != oi.network_type:
                    problems.append(
                        f"network type mismatch: {oi.name} is {oi.network_type}, "
                        f"{label} is {peer.network_type}"
                    )
                if peer.router_id == oi.router_id:
                    problems.append(f"{label} uses the same router ID {oi.router_id}")
                if (
                    oi.network_type == NETWORK_BROADCAST
                    and oi.priority == 0
                    and peer.priority == 0
                ):
                    problems.append(
                        f"{oi.name} and {label} both have OSPF priority 0, so no DR is "
                        "elected and the neighbors stay in 2WAY"
                    )
        unique: List[str] = []
        for problem in problems:
            if problem not in unique:
                unique.append(problem)
        return unique

    # ---- legacy compatibility -------------------------------------------
    def ospf_neighbors(self, node_name: str) -> List[dict]:
        """Shape-compatible with the legacy ``NetworkEngine.ospf_neighbors``."""
        rows = []
        for neighbour in self.neighbors(node_name):
            rows.append(
                {
                    "neighbor": neighbour.neighbor,
                    "neighbor_ip": neighbour.address,
                    "local_interface": neighbour.local_interface,
                    "area": neighbour.area,
                    "state": neighbour.state.split("/", 1)[0],
                }
            )
        return rows

    def route_entries(self, node_name: str, ospf_only: bool = False) -> List[str]:
        lines: List[str] = []
        if not ospf_only:
            seen = set()
            for oi in self._node_ospf_interfaces(node_name):
                if oi.network in seen:
                    continue
                seen.add(oi.network)
                lines.append(
                    f"C    {oi.network.with_prefixlen} is directly connected, {oi.name}"
                )
        for route in self.routes(node_name):
            if not route.next_hops:
                continue
            via_ip, egress = route.next_hops[0]
            lines.append(
                f"{route.code:<4} {route.network.with_prefixlen} "
                f"[{route.distance}/{route.metric}] via {via_ip}, "
                f"{_hms(route.age)}, {egress}"
            )
        return lines
