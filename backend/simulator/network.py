"""Network answers for grading and ``runtime.network()`` (Phase 3 facade).

Until Phase 3 this module held its own simplified network model.  Every answer
now comes from the protocol engines in :mod:`simulator.engines` (L2 fabric, L3
forwarding, OSPF, services) -- the same engines the live CLI uses -- so the
grader agrees with what a student sees in the console: ``can_reach`` is the
round trip ``ping`` performs, OSPF neighbours are the FULL adjacencies ``show ip
ospf neighbor`` lists, EtherChannel status is ``show etherchannel summary``,
and SSH/Telnet decisions are the VTY policy ``ssh``/``telnet`` enforce.

The public method names and return shapes of the old ``NetworkEngine`` are
kept for the grader, ``SimulationSnapshot`` and the tests.

``recompute_dhcp`` implements the simulator's automatic DHCP retry: every
DHCP-enabled host is re-leased from scratch through
:meth:`ServicesEngine.dhcp_request` whenever configuration changes, so a host
always holds the lease its current topology allows.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Dict, Iterable, List, Optional, Tuple

from .l3 import IPEndpoint
from .models import NodeState, canonical_interface, natural_key

Link = Tuple[str, str, str, str]

__all__ = ["NetworkEngine", "IPEndpoint", "Link"]


def _hms(seconds: float) -> str:
    total = int(max(0, seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class NetworkEngine:
    """Engine-backed network queries over ``nodes``/``links`` at time ``now``.

    The engine bundle is built lazily and reused for every query; build a new
    ``NetworkEngine`` (or call :meth:`invalidate`) after changing state.
    """

    #: Upper bound on addresses probed per DHCP allocation (see services.py).
    DHCP_CANDIDATE_PROBE_LIMIT = 4096

    def __init__(
        self,
        nodes: Dict[str, NodeState],
        links: Iterable[Link],
        now: Optional[float] = None,
    ) -> None:
        self.nodes = nodes
        self.links: List[Link] = [
            (a, canonical_interface(ai), b, canonical_interface(bi))
            for a, ai, b, bi in links
        ]
        self.now = time.time() if now is None else float(now)
        self._bundle = None

    # ------------------------------------------------------------------ #
    # Engine bundle                                                       #
    # ------------------------------------------------------------------ #
    @property
    def bundle(self):
        if self._bundle is None:
            from .engines import build_bundle

            self._bundle = build_bundle(self.nodes, self.links, self.now)
        return self._bundle

    def invalidate(self) -> None:
        """Drop the cached bundle (call after mutating node state)."""
        self._bundle = None

    def _has_interface(self, node_name: str, interface_name: str) -> bool:
        node = self.nodes.get(node_name)
        return node is not None and canonical_interface(interface_name) in node.interfaces

    # ------------------------------------------------------------------ #
    # Interfaces, links, segments, addresses                              #
    # ------------------------------------------------------------------ #
    def interface_oper_up(self, node_name: str, interface_name: str) -> bool:
        """True when the interface is up/up (``show ip interface brief``)."""
        if not self._has_interface(node_name, interface_name):
            return False
        return bool(
            self.bundle.callbacks.line_protocol_up(
                node_name, canonical_interface(interface_name)
            )
        )

    def line_state(self, node_name: str, interface_name: str) -> Tuple[str, str]:
        """``(status, protocol)`` exactly as ``show interfaces`` prints them."""
        if not self._has_interface(node_name, interface_name):
            return ("down", "down")
        return tuple(  # type: ignore[return-value]
            self.bundle.l2.line_state(node_name, canonical_interface(interface_name))
        )

    def link_status(self, link: Link) -> str:
        left_name, left_interface, right_name, right_interface = link
        if self.interface_oper_up(left_name, left_interface) and self.interface_oper_up(
            right_name, right_interface
        ):
            return "up"
        return "down"

    def interface_segment(
        self, node_name: str, interface_name: str, union: object = None
    ) -> Optional[object]:
        if not self._has_interface(node_name, interface_name):
            return None
        return self.bundle.callbacks.segment_of(
            node_name, canonical_interface(interface_name)
        )

    def ip_endpoints(self, union: object = None) -> List[IPEndpoint]:
        """Addresses on up interfaces (primary and secondary)."""
        return list(self.bundle.l3.endpoints())

    def find_ip(self, address: str, union: object = None) -> Optional[IPEndpoint]:
        return self.bundle.l3.find_ip(str(address))

    # ------------------------------------------------------------------ #
    # EtherChannel                                                        #
    # ------------------------------------------------------------------ #
    def channel_status(self, node_name: str, group: int) -> dict:
        """``{"formed": bool, "members": {interface: bundled}}`` for one group.

        ``members`` lists every interface configured with ``channel-group
        <group>``; ``formed`` is True while at least one member is bundled.
        """
        node = self.nodes.get(node_name)
        if node is None:
            return {"formed": False, "members": {}}
        members = {
            name: False
            for name in sorted(
                (
                    interface.name
                    for interface in node.interfaces.values()
                    if interface.channel_group == group
                ),
                key=natural_key,
            )
        }
        formed = False
        for channel in self.bundle.l2.etherchannels(node_name):
            if channel.group != group:
                continue
            # A shut Port-channel is not in use even when LACP pairs the members.
            in_use = bool(channel.in_use)
            for member in channel.members:
                members[canonical_interface(member.interface)] = bool(member.bundled) and in_use
            formed = in_use and any(member.bundled for member in channel.members)
        return {"formed": formed, "members": members}

    # ------------------------------------------------------------------ #
    # OSPF and routing                                                    #
    # ------------------------------------------------------------------ #
    def ospf_neighbors(self, node_name: str) -> List[dict]:
        """FULL OSPF adjacencies of ``node_name`` (legacy dict shape)."""
        if node_name not in self.nodes:
            return []
        return [
            row
            for row in self.bundle.ospf.ospf_neighbors(node_name)
            if str(row.get("state", "")).upper() == "FULL"
        ]

    def route_entries(self, node_name: str, ospf_only: bool = False) -> List[str]:
        """Routing table lines (``ospf_only`` keeps only OSPF-learned routes)."""
        if node_name not in self.nodes:
            return []
        lines: List[str] = []
        for entry in self.bundle.l3.routing_table(node_name).entries:
            if entry.code == "L":
                continue
            if ospf_only and not entry.code.startswith("O"):
                continue
            prefix = entry.network.with_prefixlen
            hops = entry.next_hops or [(None, "")]
            next_hop, egress = hops[0]
            if next_hop is None:
                lines.append(f"{entry.code:<4} {prefix} is directly connected, {egress}")
                continue
            tail = f", {_hms(entry.age)}, {egress}" if egress else ""
            lines.append(
                f"{entry.code:<4} {prefix} [{entry.distance}/{entry.metric}] via {next_hop}{tail}"
            )
        return lines

    # ------------------------------------------------------------------ #
    # Reachability                                                        #
    # ------------------------------------------------------------------ #
    def can_reach(self, source_name: str, target_address: str) -> bool:
        """Round-trip IPv4 reachability, as an echo request/reply would need."""
        if source_name not in self.nodes:
            return False
        try:
            target = str(ipaddress.IPv4Address(str(target_address).strip()))
        except ipaddress.AddressValueError:
            return False
        return bool(self.bundle.l3.reachable(source_name, target))

    # ------------------------------------------------------------------ #
    # NTP                                                                 #
    # ------------------------------------------------------------------ #
    def ntp_info(self, node_name: str, visiting: object = None) -> dict:
        node = self.nodes.get(node_name)
        if node is None:
            return {"synchronized": False, "stratum": 16, "reference": None, "reason": "node missing"}
        status = self.bundle.services.ntp_status(node_name, now=self.now)
        if not status.synchronized:
            return {"synchronized": False, "stratum": 16, "reference": None, "reason": "no valid server"}
        reason = "local master" if node.ntp_master is not None and not node.ntp_servers else "upstream synchronized"
        return {
            "synchronized": True,
            "stratum": status.stratum,
            "reference": status.reference,
            "reason": reason,
        }

    def ntp_associations(self, node_name: str) -> List[dict]:
        if node_name not in self.nodes:
            return []
        rows = self.bundle.services.ntp_associations(node_name, now=self.now)
        return [
            {
                "address": row.address,
                "selected": row.marker == "*",
                "reachable": str(row.reach) != "0",
                "authenticated": bool(row.authenticated),
            }
            for row in rows
        ]

    # ------------------------------------------------------------------ #
    # Remote access (VTY policy)                                          #
    # ------------------------------------------------------------------ #
    def _vty(self, source_name: str, target_address: str, transport: str):
        return self.bundle.services.vty_access(
            source_name, str(target_address), transport, now=self.now
        )

    @staticmethod
    def _failure(decision) -> str:
        if decision.code == "timeout":
            return "Destination unreachable"
        if decision.code == "refused":
            return "Connection refused by remote host"
        message = (decision.message or "").strip()
        return message.lstrip("%").strip() or "Connection failed"

    def _target(self, decision, target_address: str) -> Tuple[Optional[NodeState], str]:
        target = self.nodes.get(decision.target_node) if decision.target_node else None
        return target, (target.hostname if target is not None else str(target_address))

    def ssh_policy_allowed(self, source_name: str, target_address: str) -> Tuple[bool, str]:
        """Reachability, SSH server state and VTY ``transport input`` policy."""
        if source_name not in self.nodes:
            return False, "Destination unreachable"
        decision = self._vty(source_name, target_address, "ssh")
        if not decision.allowed:
            return False, self._failure(decision)
        _target, hostname = self._target(decision, target_address)
        return True, f"Open {hostname}"

    def ssh_allowed(
        self, source_name: str, username: str, target_address: str
    ) -> Tuple[bool, str]:
        if source_name not in self.nodes:
            return False, "Destination unreachable"
        decision = self._vty(source_name, target_address, "ssh")
        if not decision.allowed:
            return False, self._failure(decision)
        target, hostname = self._target(decision, target_address)
        if decision.login_mode == "local" and (target is None or not target.user_exists(username)):
            return False, "Authentication failed"
        return True, f"Open {hostname} as {username}"

    def ssh_authenticate(
        self,
        source_name: str,
        username: str,
        password: str,
        target_address: str,
    ) -> Tuple[bool, str]:
        """VTY policy plus the exact credential the target's login mode needs."""
        if source_name not in self.nodes:
            return False, "Destination unreachable"
        decision = self._vty(source_name, target_address, "ssh")
        if not decision.allowed:
            return False, self._failure(decision)
        target, hostname = self._target(decision, target_address)
        if target is None:
            return False, "Destination unreachable"
        accepted = self.bundle.services.vty_authenticate(
            target.name, decision.login_mode, username, password, line=decision.target_line
        )
        if not accepted:
            return False, "Authentication failed"
        return True, f"Open {hostname} as {username}"

    def telnet_allowed(self, source_name: str, target_address: str) -> Tuple[bool, str]:
        if source_name not in self.nodes:
            return False, "Destination unreachable"
        decision = self._vty(source_name, target_address, "telnet")
        if not decision.allowed:
            return False, self._failure(decision)
        _target, hostname = self._target(decision, target_address)
        return True, f"Open {hostname}"

    # ------------------------------------------------------------------ #
    # DHCP                                                                #
    # ------------------------------------------------------------------ #
    def recompute_dhcp(self) -> None:
        """Re-lease every DHCP-enabled host from scratch (automatic retry).

        Hosts are processed in name order; a host that keeps the same address
        keeps its lease start time.  Hosts that no longer use DHCP lose their
        bindings.  Allocation follows ``ServicesEngine.dhcp_request`` (pool of
        the router interface on the host's segment or via ``ip helper-address``,
        excluded addresses, addresses in use, ``no service dhcp``).

        Leases are sticky, as on a real DHCP server: a host that already holds
        a valid binding is served first (in lease-start order) and keeps its
        address while it stays on the same pool; new clients take the next free
        address.  A binding is dropped when its host stops using DHCP, when the
        address left the pool network or became excluded or statically used,
        or when the host can no longer reach a server.

        A kept lease also keeps its start and expiry times, except for a host
        whose client state was reset (``dhcp_client.leased_at is None``, set by
        the VPCS ``ip dhcp`` command): that host ran a new DORA, so the server
        renews its binding from now.
        """
        hosts = {
            name
            for name, node in self.nodes.items()
            if node.kind == "host" and node.dhcp_enabled
        }
        renewing = {
            name for name in hosts
            if getattr(self.nodes[name].dhcp_client, "leased_at", None) is None
        }
        static_in_use = set()
        for node in self.nodes.values():
            for interface in node.interfaces.values():
                if interface.ip_address and interface.address_source != "dhcp":
                    static_in_use.add(interface.ip_address)
                for secondary, _mask in interface.secondary_addresses:
                    static_in_use.add(secondary)

        def excluded(server: NodeState, address: str) -> bool:
            value = int(ipaddress.IPv4Address(address))
            for start, end in server.dhcp_excluded:
                try:
                    low = int(ipaddress.IPv4Address(start))
                    high = int(ipaddress.IPv4Address(end))
                except ValueError:
                    continue
                if min(low, high) <= value <= max(low, high):
                    return True
            return False

        previous: Dict[str, Tuple[str, float, Optional[float], object]] = {}
        for server in self.nodes.values():
            for pool in server.dhcp_pools.values():
                pool.leases.clear()
                network = pool.network
                for address, binding in list(pool.bindings.items()):
                    client = self.nodes.get(binding.client_node or "")
                    if client is None or client.kind != "host":
                        continue
                    valid = (
                        client.name in hosts
                        and network is not None
                        and ipaddress.IPv4Address(address) in network
                        and not excluded(server, address)
                        and address not in static_in_use
                    )
                    earlier = previous.get(client.name)
                    if valid and (earlier is None or binding.leased_at > earlier[1]):
                        if earlier is not None:
                            earlier[3].bindings.pop(earlier[0], None)  # type: ignore[attr-defined]
                        previous[client.name] = (address, binding.leased_at, binding.expires_at, pool)
                    else:
                        del pool.bindings[address]
        for name in hosts:
            node = self.nodes[name]
            interface = node.first_host_interface()
            if interface.address_source == "dhcp":
                interface.ip_address = None
                interface.netmask = None
                interface.address_source = None
            node.default_gateway = None
        self._bundle = None
        if not hosts:
            return
        order = sorted(hosts, key=lambda name: (name not in previous,
                                                previous.get(name, ("", 0.0))[1], name))
        services = self.bundle.services
        for name in order:
            result = services.dhcp_request(name, now=self.now)
            for server in self.nodes.values():
                for pool in server.dhcp_pools.values():
                    for address, binding in list(pool.bindings.items()):
                        if binding.client_node != name:
                            continue
                        keep = (
                            result.success
                            and address == result.address
                            and pool.name == result.pool_name
                            and server.name == result.server_node
                        )
                        if not keep:
                            del pool.bindings[address]  # stale lease elsewhere
            if not result.success:
                continue
            earlier = previous.get(name)
            if earlier is None or earlier[0] != result.address or name in renewing:
                continue
            server = self.nodes.get(result.server_node or "")
            pool = server.dhcp_pools.get(result.pool_name or "") if server is not None else None
            binding = pool.bindings.get(result.address) if pool is not None else None
            if binding is not None and pool is earlier[3]:
                binding.leased_at = earlier[1]
                binding.expires_at = earlier[2]
                client_state = self.nodes[name].dhcp_client
                if client_state is not None:
                    client_state.leased_at = earlier[1]
        self._bundle = None
