"""Deterministic Layer-2 fabric for the native network simulator.

``L2Fabric`` computes IOL L2 (Catalyst 3560-like) switch behaviour, IOL router
and VPCS/IOS host attachment, entirely from :class:`~simulator.models.NodeState`
fields and the link list.  Everything is a pure function of the current model
state -- the only mutation the fabric ever performs is explicit MAC learning
(and the port-security / bpduguard err-disable that learning/BPDU reception
implies), always via the documented ``learn`` entry point.  Nothing sleeps and
nothing prints.

The fabric answers the questions the IOS ``show`` commands need:

* physical / sub-interface / SVI / Port-channel / loopback line state,
* ``show interfaces status`` port state,
* ``show interfaces switchport`` and ``show interfaces trunk`` (DTP + encap
  negotiation, allowed / active / forwarding VLAN sets),
* ``show etherchannel summary`` / ``port-channel`` and ``show lacp neighbor``
  (real LACP/PAgP/on negotiation),
* ``show spanning-tree`` PVST+ per-VLAN election,
* the broadcast-domain segmentation used by the L3 engine
  (:meth:`segment_of`, :meth:`segment_members`, :meth:`l2_path`),
* ``show mac address-table`` learning and aging.

All results are returned as frozen dataclasses (defined below); callers render
them.  Segment identifiers are opaque hashable tuples that are only meaningful
within one ``L2Fabric`` instance.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import (
    Dict,
    FrozenSet,
    Hashable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from . import models
from .models import (
    NodeState,
    PLATFORM_ROUTER,
    PLATFORM_SWITCH,
    PLATFORM_VPCS,
    canonical_interface,
    format_mac,
    interface_parent,
    interface_vlan,
    natural_key,
)

Link = Tuple[str, str, str, str]
Point = Tuple[str, str]
Segment = Hashable

ALL_VLANS: FrozenSet[int] = frozenset(range(1, 4095))

#: :meth:`L2Fabric.learn` outcomes.
LEARN_FORWARDED = ""
LEARN_DROPPED = "dropped"
LEARN_ERRDISABLED = "errdisabled"

# IEEE 802.1D-1998 "short" path cost for a 10 Mbit IOL Ethernet port.
DEFAULT_STP_COST = 100
DEFAULT_BRIDGE_PRIORITY = 32768
DEFAULT_PORT_PRIORITY = 128
STP_HELLO_TIME = 2
STP_MAX_AGE = 20
STP_FORWARD_DELAY = 15
STP_AGING_TIME = 300
DEFAULT_MAC_AGING = 300


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PortStatus:
    """Operational port state for ``show interfaces status``."""

    node: str
    interface: str
    admin_down: bool
    line_up: bool
    protocol_up: bool
    err_disabled_reason: Optional[str]
    status_text: str          # connected | notconnect | disabled | err-disabled | suspended
    vlan_text: str            # access VLAN number | "trunk" | "routed"


@dataclass(frozen=True)
class SwitchportInfo:
    """``show interfaces switchport`` view of a port."""

    node: str
    interface: str
    is_switchport: bool
    admin_mode: str           # dynamic auto | dynamic desirable | access | trunk
    oper_mode: str            # static access | trunk | down | routed
    access_vlan: int
    native_vlan: int
    admin_encapsulation: str  # negotiate | dot1q | isl
    oper_encapsulation: str   # n-isl | 802.1q | isl | native
    negotiation: bool         # DTP enabled (not nonegotiate)
    allowed_vlans: FrozenSet[int]
    active_vlans: Tuple[int, ...]
    forwarding_vlans: Tuple[int, ...]
    voice_vlan: Optional[int]
    channel_group: Optional[int]


@dataclass(frozen=True)
class TrunkRow:
    """One row of ``show interfaces trunk``."""

    interface: str
    port: str                 # short name (Et0/0, Po1)
    mode: str                 # on | desirable | auto
    encapsulation: str        # 802.1q | n-isl | isl
    status: str               # trunking
    native_vlan: int
    allowed_vlans: Tuple[int, ...]
    allowed_active_vlans: Tuple[int, ...]
    forwarding_vlans: Tuple[int, ...]


@dataclass(frozen=True)
class ChannelMember:
    """A physical member inside an EtherChannel group."""

    interface: str
    port: str                 # short name
    flags: str                # P | I | s | D | H | w (may combine)
    bundled: bool
    peer_node: Optional[str]
    peer_interface: Optional[str]


@dataclass(frozen=True)
class Etherchannel:
    """``show etherchannel summary`` group view."""

    group: int
    port_channel: str         # Port-channel1
    port: str                 # short name Po1
    protocol: str             # LACP | PAgP | -
    layer: str                # L2 | L3
    flags: str                # SU | SD | RU | RD
    in_use: bool
    members: Tuple[ChannelMember, ...]


@dataclass(frozen=True)
class LacpNeighbor:
    """One ``show lacp neighbor`` row (partner data for a local member)."""

    interface: str            # local member short name
    partner_mac: str          # cisco-formatted system id
    partner_port: str         # peer member short name
    partner_port_number: int
    partner_sys_priority: int
    partner_port_priority: int
    partner_oper_key: int
    flags: str                # LACP actor/partner state, e.g. SA
    age: Optional[float]


@dataclass(frozen=True)
class StpPort:
    """One port row in a PVST+ instance."""

    interface: str
    port: str                 # short name
    role: str                 # Root | Desg | Altn | Back
    state: str                # FWD | BLK
    cost: int
    priority: int             # port priority (128)
    port_number: int
    prio_nbr: str             # "128.1"
    type: str                 # "P2p" or "P2p Edge"
    edge: bool


@dataclass(frozen=True)
class StpInfo:
    """A PVST+ spanning-tree instance for one VLAN as seen by one bridge."""

    node: str
    vlan: int
    is_root: bool
    root_priority: int
    root_address: str
    root_cost: int
    root_port: Optional[str]
    bridge_priority: int
    bridge_address: str
    hello_time: int
    max_age: int
    forward_delay: int
    aging_time: int
    ports: Tuple[StpPort, ...]


@dataclass(frozen=True)
class MacTableEntry:
    """One ``show mac address-table`` entry."""

    vlan: int
    mac: str                  # cisco format
    type: str                 # DYNAMIC | STATIC
    port: str                 # short name


@dataclass(frozen=True)
class PortSecurityInfo:
    """``show port-security interface`` view."""

    interface: str
    enabled: bool
    max_addresses: int
    violation: str
    sticky: bool
    total_addresses: int
    status: str               # Secure-up | Secure-down | Secure-shutdown
    last_source: Optional[str]


class _UnionFind:
    """Tiny deterministic union-find over hashable tokens."""

    def __init__(self) -> None:
        self.parent: Dict[Hashable, Hashable] = {}

    def add(self, item: Hashable) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: Hashable) -> Hashable:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        # Path compression.
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, left: Hashable, right: Hashable) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        # Deterministic: smaller repr becomes the representative.
        if repr(left_root) <= repr(right_root):
            self.parent[right_root] = left_root
        else:
            self.parent[left_root] = right_root


class L2Fabric:
    """Layer-2 fabric computed from :class:`NodeState` records and links."""

    def __init__(
        self,
        nodes: Dict[str, NodeState],
        links: Sequence[Link],
        now: Optional[float] = None,
    ) -> None:
        self.nodes = nodes
        self.now = now
        self.links: List[Link] = []
        self._peer: Dict[Point, Point] = {}
        for raw in links:
            a, ai, b, bi = raw
            ai = canonical_interface(ai)
            bi = canonical_interface(bi)
            link = (a, ai, b, bi)
            self.links.append(link)
            self._peer[(a, ai)] = (b, bi)
            self._peer[(b, bi)] = (a, ai)

        # Lazily populated caches (keyed so a fabric is single-use per state).
        self._etherchannel_cache: Dict[str, Dict[int, Etherchannel]] = {}
        self._stp_cache: Dict[int, dict] = {}
        self._segment_state: Optional[dict] = None
        self._errdis_cache: Dict[Point, Optional[str]] = {}
        #: Optional ``Callable[[str, str, str], None]`` -- ``(kind, node, message)``
        #: for state changes caused by traffic (port-security violations).  The
        #: runtime installs it to emit syslog and refresh its cached engines.
        self.event_sink = None

    # =====================================================================
    # Topology helpers
    # =====================================================================
    def peer(self, node: str, iface: str) -> Optional[Point]:
        """Return ``(node, iface)`` on the other end of the cable, or ``None``."""
        return self._peer.get((node, canonical_interface(iface)))

    # ------------------------------------------------------------------
    # Interface classification
    # ------------------------------------------------------------------
    def _node(self, name: str) -> Optional[NodeState]:
        return self.nodes.get(name)

    def _iface(self, node: str, iface: str):
        n = self.nodes.get(node)
        if n is None:
            return None
        return n.interfaces.get(canonical_interface(iface))

    def _is_switch(self, name: str) -> bool:
        n = self.nodes.get(name)
        return bool(n and n.kind == "switch")

    def _is_vpcs(self, name: str) -> bool:
        n = self.nodes.get(name)
        return bool(n and n.platform == PLATFORM_VPCS)

    @staticmethod
    def _is_physical(name: str) -> bool:
        return models.is_physical_interface(name)

    @staticmethod
    def _is_subinterface(name: str) -> bool:
        return interface_parent(canonical_interface(name)) is not None

    @staticmethod
    def _is_svi(name: str) -> bool:
        return canonical_interface(name).startswith("Vlan")

    @staticmethod
    def _is_portchannel(name: str) -> bool:
        return canonical_interface(name).startswith("Port-channel")

    @staticmethod
    def _is_loopback(name: str) -> bool:
        return canonical_interface(name).startswith("Loopback")

    @staticmethod
    def _short_ifname(name: str) -> str:
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

    @staticmethod
    def _iol_port_number(name: str) -> int:
        """IOL STP port number: e0/0=1, e0/1=2 ... e1/0=5; Port-channelN=64+N."""
        canonical = canonical_interface(name)
        if canonical.startswith("Port-channel"):
            try:
                return 64 + int(canonical[len("Port-channel"):])
            except ValueError:
                return 64
        match = models._slot_port(canonical)
        if match is None:
            return 1
        slot, port = match
        return slot * models.PORTS_PER_SLOT + port + 1

    # ------------------------------------------------------------------
    # Admin / physical connectivity
    # ------------------------------------------------------------------
    def _admin_up(self, node: str, iface: str) -> bool:
        """True when the interface is not administratively shut down.

        VPCS NICs have no ``shutdown`` concept and are always admin up.
        """
        n = self.nodes.get(node)
        if n is None:
            return False
        i = n.interfaces.get(canonical_interface(iface))
        if i is None:
            return False
        if n.platform == PLATFORM_VPCS:
            return True
        return not i.shutdown

    def _cable_both_admin_up(self, node: str, iface: str) -> bool:
        """Cable present and both endpoints administratively up (ignores err-disable)."""
        point = (node, canonical_interface(iface))
        peer = self._peer.get(point)
        if peer is None:
            return False
        return self._admin_up(node, point[1]) and self._admin_up(peer[0], peer[1])

    def _portfast_enabled(self, node: str, iface: str) -> bool:
        i = self._iface(node, iface)
        n = self.nodes.get(node)
        if i is None or n is None:
            return False
        if i.stp_portfast is not None:
            return i.stp_portfast
        # Global "portfast default" applies to non-trunking switchports (IOS:
        # access ports), judged from configuration and DTP rather than from the
        # port's line state: line state depends on err-disable, which depends
        # on portfast through BPDU guard.  Channel members take their STP
        # settings from the Port-channel, so the default skips them.
        if n.stp_portfast_default:
            if i.channel_group is not None or not self._is_switchport(node, iface):
                return False
            return not self._oper_is_trunk(node, iface)
        return False

    def _bpduguard_errdis(self, node: str, iface: str) -> bool:
        """A portfast+bpduguard edge port that faces a switch err-disables on BPDUs."""
        i = self._iface(node, iface)
        n = self.nodes.get(node)
        if i is None or n is None or n.kind != "switch":
            return False
        bg = i.stp_bpduguard if i.stp_bpduguard is not None else n.stp_bpduguard_default
        if not (bg and self._portfast_enabled(node, iface)):
            return False
        peer = self.peer(node, iface)
        if peer is None or not self._is_switch(peer[0]):
            return False
        return self._cable_both_admin_up(node, iface)

    def _err_disabled(self, node: str, iface: str) -> Optional[str]:
        """Return the err-disable reason (model field, port-security, or bpduguard)."""
        point = (node, canonical_interface(iface))
        if point in self._errdis_cache:
            return self._errdis_cache[point]
        # Provisional answer while this port is evaluated: BPDU guard can reach
        # this port's own err-disable state again (through DTP and the peer's
        # EtherChannel state).  The port counts as not err-disabled during its
        # own evaluation -- it is up until a BPDU arrives -- which ends the
        # recursion.
        self._errdis_cache[point] = None
        reason: Optional[str] = None
        i = self.nodes.get(node).interfaces.get(point[1]) if self.nodes.get(node) else None
        if i is not None and i.err_disabled_reason:
            reason = i.err_disabled_reason
        elif self._bpduguard_errdis(node, point[1]):
            reason = "bpduguard"
        self._errdis_cache[point] = reason
        return reason

    def _phys_line_up(self, node: str, iface: str) -> bool:
        """Physical/host-NIC line protocol: cable + both admin up + no err-disable.

        IOL exception: a routed Ethernet port of an IOL L3 image (router or
        IOS host) with no cable attached is up/up while administratively up,
        because IOL has no carrier detection on unconnected ports.  Labs rely
        on this to advertise stub LANs on unconnected router interfaces.
        Switchports and VPCS NICs still need a cable (``notconnect``), and a
        cabled port still goes down when the far end is shut or err-disabled.
        """
        canonical = canonical_interface(iface)
        if self._unconnected_routed_port(node, canonical):
            return not self._err_disabled(node, canonical)
        if not self._cable_both_admin_up(node, canonical):
            return False
        if self._err_disabled(node, canonical):
            return False
        peer = self._peer.get((node, canonical))
        if peer and self._err_disabled(peer[0], peer[1]):
            return False
        return True

    def _unconnected_routed_port(self, node: str, canonical: str) -> bool:
        """True for an admin-up, uncabled physical port on an IOL L3 image."""
        if (node, canonical) in self._peer:
            return False
        n = self.nodes.get(node)
        if n is None or n.platform != PLATFORM_ROUTER:
            return False
        if not self._is_physical(canonical) or self._is_subinterface(canonical):
            return False
        return self._admin_up(node, canonical)

    # ------------------------------------------------------------------
    # Line state
    # ------------------------------------------------------------------
    def line_state(self, node: str, iface: str) -> Tuple[str, str]:
        """Return ``(status, protocol)`` exactly as IOS prints it.

        One of ``("up","up")``, ``("down","down")``,
        ``("administratively down","down")``, ``("down","down (err-disabled)")``
        or ``("up","down (suspended)")`` for an EtherChannel member that LACP/PAgP
        suspended (it carries no traffic).
        """
        n = self.nodes.get(node)
        if n is None:
            return ("down", "down")
        canonical = canonical_interface(iface)
        i = n.interfaces.get(canonical)
        if i is None:
            return ("down", "down")

        if self._is_subinterface(canonical):
            return self._subinterface_state(node, canonical)
        if self._is_loopback(canonical):
            if i.shutdown:
                return ("administratively down", "down")
            return ("up", "up")
        if self._is_svi(canonical):
            return self._svi_state(node, canonical)
        if self._is_portchannel(canonical):
            if i.shutdown:
                return ("administratively down", "down")
            return ("up", "up") if self._bundled_member_count(node, canonical) > 0 else ("down", "down")

        # Physical port or host NIC.
        if not self._admin_up(node, canonical):
            return ("administratively down", "down")
        if self._err_disabled(node, canonical):
            return ("down", "down (err-disabled)")
        if self._phys_line_up(node, canonical):
            if i.channel_group is not None and self._member_state(node, canonical) == "s":
                return ("up", "down (suspended)")
            return ("up", "up")
        return ("down", "down")

    def _subinterface_state(self, node: str, canonical: str) -> Tuple[str, str]:
        i = self._iface(node, canonical)
        if i is not None and i.shutdown:
            return ("administratively down", "down")
        parent = interface_parent(canonical)
        if not parent or self._iface(node, parent) is None:
            return ("down", "down")
        parent_state = self.line_state(node, parent)
        if parent_state[0] == "administratively down":
            return ("administratively down", "down")
        if parent_state == ("up", "up"):
            return ("up", "up")
        return ("down", "down")

    def _svi_state(self, node: str, canonical: str) -> Tuple[str, str]:
        i = self._iface(node, canonical)
        n = self.nodes.get(node)
        if i is not None and i.shutdown:
            return ("administratively down", "down")
        vlan = interface_vlan(canonical)
        if vlan is None or n is None or vlan not in n.vlans:
            return ("down", "down")
        if self._vlan_has_forwarding_port(node, vlan):
            return ("up", "up")
        return ("down", "down")

    # ------------------------------------------------------------------
    # Port status (show interfaces status)
    # ------------------------------------------------------------------
    def port_status(self, node: str, iface: str) -> Optional[PortStatus]:
        """Operational state for ``show interfaces status``; ``None`` if absent."""
        n = self.nodes.get(node)
        if n is None:
            return None
        canonical = canonical_interface(iface)
        i = n.interfaces.get(canonical)
        if i is None:
            return None

        status, protocol = self.line_state(node, canonical)
        admin_down = status == "administratively down"
        err_reason = self._err_disabled(node, canonical) if (
            self._is_physical(canonical) and not self._is_subinterface(canonical)
        ) else (i.err_disabled_reason or None)
        protocol_up = protocol == "up"

        if self._is_physical(canonical) and not self._is_subinterface(canonical):
            line_up = self._phys_line_up(node, canonical)
        elif self._is_portchannel(canonical):
            line_up = protocol_up
        else:
            line_up = protocol_up

        member_flag = self._member_state(node, canonical)

        if admin_down:
            status_text = "disabled"
        elif err_reason:
            status_text = "err-disabled"
        elif member_flag == "s":
            status_text = "suspended"
        elif line_up or protocol_up:
            status_text = "connected"
        else:
            status_text = "notconnect"

        vlan_text = self._vlan_text(node, canonical)
        return PortStatus(
            node=node,
            interface=canonical,
            admin_down=admin_down,
            line_up=line_up,
            protocol_up=protocol_up,
            err_disabled_reason=err_reason,
            status_text=status_text,
            vlan_text=vlan_text,
        )

    def _vlan_text(self, node: str, canonical: str) -> str:
        n = self.nodes.get(node)
        if n is None:
            return "routed"
        if not self._is_switch(node):
            # Routers / hosts: physical ports are routed, subinterfaces tagged.
            return "routed"
        info = self.switchport(node, canonical)
        if info is None:
            return "routed"
        if info.oper_mode == "routed":
            return "routed"
        if info.oper_mode == "trunk":
            return "trunk"
        return str(info.access_vlan)

    # ------------------------------------------------------------------
    # Switchport / DTP
    # ------------------------------------------------------------------
    def _governing(self, node: str, iface: str):
        """Return the ``InterfaceState`` whose switchport config governs a port.

        A channel member inherits the Port-channel's switchport configuration.
        """
        i = self._iface(node, iface)
        if i is None:
            return None, canonical_interface(iface)
        if i.channel_group is not None:
            po_name = f"Port-channel{i.channel_group}"
            po = self._iface(node, po_name)
            if po is not None:
                return po, po_name
        return i, canonical_interface(iface)

    def _is_switchport(self, node: str, iface: str) -> bool:
        n = self.nodes.get(node)
        i = self._iface(node, iface)
        if n is None or i is None or n.kind != "switch":
            return False
        canonical = canonical_interface(iface)
        if self._is_svi(canonical) or self._is_loopback(canonical) or self._is_subinterface(canonical):
            return False
        gov, _ = self._governing(node, iface)
        return not (gov is not None and gov.routed_port)

    def _admin_mode(self, node: str, iface: str) -> str:
        gov, _ = self._governing(node, iface)
        raw = gov.switchport_mode if gov is not None else None
        return "dynamic auto" if raw is None else raw

    def _port_operational(self, node: str, iface: str) -> bool:
        return self.line_state(node, iface) == ("up", "up")

    def _dtp_peer(self, node: str, iface: str) -> Optional[Point]:
        """The DTP peer attachment (collapsing bundled members onto a Po)."""
        canonical = canonical_interface(iface)
        if self._is_portchannel(canonical):
            try:
                group = int(canonical[len("Port-channel"):])
            except ValueError:
                return None
            for m in self._group_members(node, group):
                if self._member_state(node, m) == "P":
                    peer = self.peer(node, m)
                    if peer is None:
                        continue
                    pif = self._iface(peer[0], peer[1])
                    if pif and pif.channel_group is not None and self._member_state(peer[0], peer[1]) == "P":
                        return (peer[0], f"Port-channel{pif.channel_group}")
                    return peer
            return None
        peer = self.peer(node, canonical)
        if peer is None:
            return None
        pif = self._iface(peer[0], peer[1])
        if pif and pif.channel_group is not None and self._member_state(peer[0], peer[1]) == "P":
            return (peer[0], f"Port-channel{pif.channel_group}")
        return peer

    def _oper_is_trunk(self, node: str, iface: str) -> bool:
        """DTP outcome: does this switch port operate as a trunk?"""
        if not self._is_switchport(node, iface):
            return False
        role = self._admin_mode(node, iface)
        if role == "access":
            return False
        if role == "trunk":
            return True
        peer = self._dtp_peer(node, iface)
        if peer is None or not self._is_switch(peer[0]):
            return False
        peer_role = self._admin_mode(peer[0], peer[1])
        peer_gov, _ = self._governing(peer[0], peer[1])
        peer_nonegotiate = bool(peer_gov and peer_gov.nonegotiate)
        if peer_nonegotiate:
            return False
        if role == "dynamic desirable":
            return peer_role in ("trunk", "dynamic desirable", "dynamic auto")
        if role == "dynamic auto":
            return peer_role in ("trunk", "dynamic desirable")
        return False

    def _oper_mode(self, node: str, iface: str) -> str:
        gov, _ = self._governing(node, iface)
        if not self._is_switch(node):
            return "routed"
        if gov is not None and gov.routed_port:
            return "routed"
        if not self._is_switchport(node, iface):
            return "routed"
        if not self._port_operational(node, iface):
            return "down"
        return "trunk" if self._oper_is_trunk(node, iface) else "static access"

    def _allowed_vlans(self, node: str, iface: str) -> FrozenSet[int]:
        gov, _ = self._governing(node, iface)
        if gov is None or gov.trunk_allowed_vlans is None:
            return ALL_VLANS
        return frozenset(gov.trunk_allowed_vlans)

    def _native_vlan(self, node: str, iface: str) -> int:
        gov, _ = self._governing(node, iface)
        return gov.trunk_native_vlan if gov is not None else 1

    def _access_vlan(self, node: str, iface: str) -> int:
        gov, _ = self._governing(node, iface)
        return gov.access_vlan if gov is not None else 1

    def _active_vlans(self, node: str, iface: str) -> List[int]:
        n = self.nodes.get(node)
        if n is None:
            return []
        allowed = self._allowed_vlans(node, iface)
        return sorted(v for v in n.vlans if v in allowed)

    def _trunk_oper_encapsulation(self, node: str, iface: str) -> str:
        gov, _ = self._governing(node, iface)
        local = gov.trunk_encapsulation if gov is not None else None
        peer_encap = None
        peer = self._dtp_peer(node, iface)
        if peer is not None and self._is_switch(peer[0]):
            peer_gov, _ = self._governing(peer[0], peer[1])
            peer_encap = peer_gov.trunk_encapsulation if peer_gov is not None else None
        if local == "dot1q" or peer_encap == "dot1q":
            return "802.1q"
        if local == "isl" or peer_encap == "isl":
            return "isl"
        return "n-isl"

    def switchport(self, node: str, iface: str) -> Optional[SwitchportInfo]:
        """``show interfaces switchport`` view; ``None`` for non-L2 interfaces."""
        n = self.nodes.get(node)
        i = self._iface(node, iface)
        if n is None or i is None:
            return None
        canonical = canonical_interface(iface)
        if self._is_svi(canonical) or self._is_loopback(canonical) or self._is_subinterface(canonical):
            return None

        is_sp = self._is_switchport(node, iface)
        oper_mode = self._oper_mode(node, iface)
        admin_mode = self._admin_mode(node, iface) if is_sp else "routed"
        gov, _ = self._governing(node, iface)

        admin_encap_raw = gov.trunk_encapsulation if gov is not None else None
        admin_encap = {None: "negotiate", "dot1q": "dot1q", "isl": "isl"}.get(
            admin_encap_raw, "negotiate"
        )
        if oper_mode == "trunk":
            oper_encap = self._trunk_oper_encapsulation(node, iface)
        else:
            oper_encap = "native"

        allowed = self._allowed_vlans(node, iface)
        active = tuple(self._active_vlans(node, iface)) if oper_mode == "trunk" else tuple()
        forwarding = tuple(
            self._port_forwarding_vlans(node, iface)
        ) if oper_mode == "trunk" else tuple()

        return SwitchportInfo(
            node=node,
            interface=canonical,
            is_switchport=is_sp,
            admin_mode=admin_mode,
            oper_mode=oper_mode,
            access_vlan=self._access_vlan(node, iface),
            native_vlan=self._native_vlan(node, iface),
            admin_encapsulation=admin_encap,
            oper_encapsulation=oper_encap,
            negotiation=not bool(gov and gov.nonegotiate),
            allowed_vlans=allowed,
            active_vlans=active,
            forwarding_vlans=forwarding,
            voice_vlan=gov.voice_vlan if gov is not None else None,
            channel_group=i.channel_group,
        )

    def trunks(self, node: str) -> List[TrunkRow]:
        """Rows for ``show interfaces trunk`` (operational trunk ports only)."""
        n = self.nodes.get(node)
        if n is None or n.kind != "switch":
            return []
        rows: List[TrunkRow] = []
        for logical in self._bridge_logical_ports(node):
            if self._oper_mode(node, logical) != "trunk":
                continue
            admin = self._admin_mode(node, logical)
            mode = {
                "trunk": "on",
                "dynamic desirable": "desirable",
                "dynamic auto": "auto",
            }.get(admin, "on")
            rows.append(
                TrunkRow(
                    interface=logical,
                    port=self._short_ifname(logical),
                    mode=mode,
                    encapsulation=self._trunk_oper_encapsulation(node, logical),
                    status="trunking",
                    native_vlan=self._native_vlan(node, logical),
                    allowed_vlans=tuple(sorted(self._allowed_vlans(node, logical))),
                    allowed_active_vlans=tuple(self._active_vlans(node, logical)),
                    forwarding_vlans=tuple(self._port_forwarding_vlans(node, logical)),
                )
            )
        rows.sort(key=lambda r: natural_key(r.interface))
        return rows

    # ------------------------------------------------------------------
    # EtherChannel
    # ------------------------------------------------------------------
    _LACP_MODES = frozenset({"active", "passive"})
    _PAGP_MODES = frozenset({"desirable", "auto"})

    def _member_mode(self, node: str, iface: str) -> str:
        i = self._iface(node, iface)
        if i is None or i.channel_mode is None:
            return "on"
        return i.channel_mode

    def _group_members(self, node: str, group: int) -> List[str]:
        n = self.nodes.get(node)
        if n is None:
            return []
        names = [
            i.name
            for i in n.interfaces.values()
            if i.channel_group == group
            and self._is_physical(i.name)
            and not self._is_subinterface(i.name)
        ]
        return sorted(names, key=natural_key)

    def _groups(self, node: str) -> Dict[int, List[str]]:
        n = self.nodes.get(node)
        if n is None:
            return {}
        groups: Dict[int, List[str]] = {}
        for i in n.interfaces.values():
            if (
                i.channel_group is not None
                and self._is_physical(i.name)
                and not self._is_subinterface(i.name)
            ):
                groups.setdefault(i.channel_group, []).append(i.name)
        return {g: sorted(v, key=natural_key) for g, v in groups.items()}

    def _po_mode_key(self, node: str, group: int):
        """Switchport-mode identity a Port-channel must share with its peer."""
        n = self.nodes.get(node)
        po = n.interfaces.get(f"Port-channel{group}") if n else None
        if n is None or n.kind != "switch":
            return ("l3",)
        if po is None:
            return ("access", 1)
        if po.routed_port:
            return ("l3",)
        mode = po.switchport_mode or "dynamic auto"
        if mode == "trunk":
            return ("trunk",)
        return ("access", po.access_vlan)

    def _modes_bundle(self, local_mode: str, peer_mode: str) -> bool:
        if local_mode in self._LACP_MODES and peer_mode in self._LACP_MODES:
            return not (local_mode == "passive" and peer_mode == "passive")
        if local_mode in self._PAGP_MODES and peer_mode in self._PAGP_MODES:
            return not (local_mode == "auto" and peer_mode == "auto")
        if local_mode == "on" and peer_mode == "on":
            return True
        return False

    def _compute_etherchannels(self, node: str) -> Dict[int, Etherchannel]:
        if node in self._etherchannel_cache:
            return self._etherchannel_cache[node]
        n = self.nodes.get(node)
        result: Dict[int, Etherchannel] = {}
        if n is None:
            self._etherchannel_cache[node] = result
            return result

        for group, names in self._groups(node).items():
            po_name = f"Port-channel{group}"
            po = n.interfaces.get(po_name)
            modes = {self._member_mode(node, m) for m in names}
            if modes & self._LACP_MODES:
                protocol = "LACP"
            elif modes & self._PAGP_MODES:
                protocol = "PAgP"
            else:
                protocol = "-"

            candidate: Dict[str, Tuple[str, int]] = {}
            for m in names:
                if not self._phys_line_up(node, m):
                    continue
                peer = self.peer(node, m)
                if peer is None:
                    continue
                pif = self._iface(peer[0], peer[1])
                if pif is None or pif.channel_group is None:
                    continue
                if not self._modes_bundle(self._member_mode(node, m), self._member_mode(peer[0], peer[1])):
                    continue
                if self._po_mode_key(node, group) != self._po_mode_key(peer[0], pif.channel_group):
                    continue
                candidate[m] = (peer[0], pif.channel_group)

            dominant: Optional[Tuple[str, int]] = None
            if candidate:
                counts: Dict[Tuple[str, int], int] = {}
                for value in candidate.values():
                    counts[value] = counts.get(value, 0) + 1
                best = max(counts.values())
                dominant = sorted(k for k, v in counts.items() if v == best)[0]

            members: List[ChannelMember] = []
            for m in names:
                peer = self.peer(node, m)
                peer_node = peer[0] if peer else None
                peer_iface = peer[1] if peer else None
                if not self._phys_line_up(node, m):
                    flag, bundled = "D", False
                elif m in candidate and candidate[m] == dominant:
                    flag, bundled = "P", True
                elif self._member_mode(node, m) == "on":
                    flag, bundled = "I", False
                else:
                    flag, bundled = "s", False
                members.append(
                    ChannelMember(
                        interface=m,
                        port=self._short_ifname(m),
                        flags=flag,
                        bundled=bundled,
                        peer_node=peer_node,
                        peer_interface=peer_iface,
                    )
                )

            layer = "L3" if (po is not None and po.routed_port) else "L2"
            in_use = any(mm.bundled for mm in members) and not (po is not None and po.shutdown)
            flags = ("R" if layer == "L3" else "S") + ("U" if in_use else "D")
            result[group] = Etherchannel(
                group=group,
                port_channel=po_name,
                port=self._short_ifname(po_name),
                protocol=protocol,
                layer=layer,
                flags=flags,
                in_use=in_use,
                members=tuple(members),
            )

        self._etherchannel_cache[node] = result
        return result

    def etherchannels(self, node: str) -> List[Etherchannel]:
        """EtherChannel groups on ``node`` for ``show etherchannel summary``."""
        groups = self._compute_etherchannels(node)
        return [groups[g] for g in sorted(groups)]

    def _member_state(self, node: str, iface: str) -> Optional[str]:
        """Flag char (P/I/s/D) if ``iface`` is a channel member, else ``None``."""
        i = self._iface(node, iface)
        if i is None or i.channel_group is None:
            return None
        channel = self._compute_etherchannels(node).get(i.channel_group)
        if channel is None:
            return None
        canonical = canonical_interface(iface)
        for member in channel.members:
            if member.interface == canonical:
                return member.flags
        return None

    def _bundled_member_count(self, node: str, po: str) -> int:
        canonical = canonical_interface(po)
        try:
            group = int(canonical[len("Port-channel"):])
        except (ValueError, TypeError):
            return 0
        channel = self._compute_etherchannels(node).get(group)
        if channel is None:
            return 0
        return sum(1 for m in channel.members if m.bundled)

    def _logical_port(self, node: str, iface: str) -> str:
        """Collapse a bundled member onto its Port-channel for STP/segments."""
        i = self._iface(node, iface)
        if i is None or i.channel_group is None:
            return canonical_interface(iface)
        if self._member_state(node, iface) == "P":
            return f"Port-channel{i.channel_group}"
        return canonical_interface(iface)

    def lacp_neighbors(self, node: str, group: Optional[int] = None) -> List[LacpNeighbor]:
        """Partner data for ``show lacp neighbor`` across LACP members."""
        rows: List[LacpNeighbor] = []
        channels = self._compute_etherchannels(node)
        for g in sorted(channels):
            if group is not None and g != group:
                continue
            channel = channels[g]
            if channel.protocol != "LACP":
                continue
            for member in channel.members:
                if member.peer_node is None or not self._phys_line_up(node, member.interface):
                    continue
                peer_node = self.nodes.get(member.peer_node)
                if peer_node is None:
                    continue
                peer_iface = self._iface(member.peer_node, member.peer_interface)
                if peer_iface is None or peer_iface.channel_group is None:
                    continue
                peer_mode = self._member_mode(member.peer_node, member.peer_interface)
                activity = "A" if peer_mode == "active" else "P"
                rows.append(
                    LacpNeighbor(
                        interface=member.port,
                        partner_mac=format_mac(peer_node.base_mac(), "cisco"),
                        partner_port=self._short_ifname(member.peer_interface),
                        partner_port_number=self._iol_port_number(member.peer_interface),
                        partner_sys_priority=DEFAULT_BRIDGE_PRIORITY,
                        partner_port_priority=DEFAULT_BRIDGE_PRIORITY,
                        partner_oper_key=peer_iface.channel_group,
                        flags="S" + activity,
                        age=None,
                    )
                )
        return rows

    # ------------------------------------------------------------------
    # Spanning tree (PVST+)
    # ------------------------------------------------------------------
    def _port_cost(self, node: str, logical: str) -> int:
        i = self._iface(node, logical)
        if i is None:
            return DEFAULT_STP_COST
        if self._is_portchannel(logical):
            if i.stp_cost:
                return i.stp_cost
            k = self._bundled_member_count(node, logical)
            # Aggregate the IOL 10 Mbit short path cost across bundled members.
            return max(1, round(DEFAULT_STP_COST / max(k, 1)))
        if i.stp_cost:
            return i.stp_cost
        return DEFAULT_STP_COST

    def _bridge_logical_ports(self, node: str) -> List[str]:
        """Logical ports of a switch that could take part in STP (members -> Po)."""
        n = self.nodes.get(node)
        if n is None or n.kind != "switch":
            return []
        result: List[str] = []
        for i in n.interfaces.values():
            name = i.name
            if self._is_svi(name) or self._is_loopback(name) or self._is_subinterface(name):
                continue
            if self._is_portchannel(name):
                if self.line_state(node, name) == ("up", "up"):
                    result.append(name)
                continue
            if not self._is_physical(name):
                continue
            if i.channel_group is not None and self._member_state(node, name) == "P":
                continue  # represented by its Port-channel
            if i.channel_group is not None and self._member_state(node, name) == "s":
                continue  # suspended members carry no traffic
            if not self._phys_line_up(node, name):
                continue
            result.append(name)
        return sorted(result, key=natural_key)

    def _port_carries_vlan(self, node: str, logical: str, vlan: int) -> bool:
        if not self._port_operational(node, logical):
            return False
        mode = self._oper_mode(node, logical)
        if mode == "trunk":
            n = self.nodes.get(node)
            return bool(n and vlan in n.vlans and vlan in self._allowed_vlans(node, logical))
        if mode == "static access":
            return vlan == self._access_vlan(node, logical)
        return False

    def _bridge_id(self, node: str, vlan: int) -> Tuple[int, int]:
        n = self.nodes[node]
        priority = n.stp_priorities.get(vlan, DEFAULT_BRIDGE_PRIORITY) + vlan
        return (priority, int(n.base_mac(), 16))

    def _stp_vlan(self, vlan: int) -> dict:
        """Compute the PVST+ topology for ``vlan`` across every switch (cached)."""
        if vlan in self._stp_cache:
            return self._stp_cache[vlan]

        bridges = [
            sw for sw in self.nodes
            if self._is_switch(sw) and vlan in self.nodes[sw].vlans
        ]
        bridge_set = set(bridges)
        ports_by_bridge: Dict[str, List[str]] = {
            sw: [p for p in self._bridge_logical_ports(sw) if self._port_carries_vlan(sw, p, vlan)]
            for sw in bridges
        }

        adj: Dict[str, List[Tuple[str, str, str, int]]] = {sw: [] for sw in bridges}
        seen: Set[Tuple[Point, Point]] = set()
        for sw in bridges:
            for la in ports_by_bridge[sw]:
                peer = self._dtp_peer(sw, la)
                if peer is None or peer[0] not in bridge_set:
                    continue
                pn, lb = peer
                if lb not in ports_by_bridge.get(pn, []):
                    continue
                key = tuple(sorted([(sw, la), (pn, lb)]))
                if key in seen:
                    continue
                seen.add(key)
                cost_a = self._port_cost(sw, la)
                cost_b = self._port_cost(pn, lb)
                adj[sw].append((pn, la, lb, cost_b))
                adj[pn].append((sw, lb, la, cost_a))

        # Connected components.
        comp_id: Dict[str, int] = {}
        comps: List[List[str]] = []
        for sw in bridges:
            if sw in comp_id:
                continue
            stack = [sw]
            comp_id[sw] = len(comps)
            comp: List[str] = []
            while stack:
                x = stack.pop()
                comp.append(x)
                for (y, _, _, _) in adj[x]:
                    if y not in comp_id:
                        comp_id[y] = len(comps)
                        stack.append(y)
            comps.append(comp)

        bridge_info: Dict[str, dict] = {}
        port_state: Dict[Point, dict] = {}
        for comp in comps:
            root = min(comp, key=lambda sw: self._bridge_id(sw, vlan))
            dist: Dict[str, int] = {root: 0}
            best_offer: Dict[str, tuple] = {root: (0, self._bridge_id(root, vlan), (0, 0), (0, 0))}
            root_port: Dict[str, Optional[str]] = {root: None}
            finalized: Set[str] = set()
            pq: List[Tuple[int, Tuple[int, int], str]] = [(0, self._bridge_id(root, vlan), root)]
            while pq:
                _, _, X = heapq.heappop(pq)
                if X in finalized:
                    continue
                finalized.add(X)
                for (Y, x_port, y_port, cost_y) in adj[X]:
                    if Y in finalized:
                        continue
                    cand = dist[X] + cost_y
                    offer = (
                        cand,
                        self._bridge_id(X, vlan),
                        (DEFAULT_PORT_PRIORITY, self._iol_port_number(x_port)),
                        (DEFAULT_PORT_PRIORITY, self._iol_port_number(y_port)),
                    )
                    if Y not in best_offer or offer < best_offer[Y]:
                        best_offer[Y] = offer
                        dist[Y] = cand
                        root_port[Y] = y_port
                        heapq.heappush(pq, (cand, self._bridge_id(Y, vlan), Y))

            for sw in comp:
                bridge_info[sw] = {
                    "rpc": dist.get(sw, 0),
                    "is_root": sw == root,
                    "root_port": root_port.get(sw),
                    "root_name": root,
                    "root_bid": self._bridge_id(root, vlan),
                }
            for sw in comp:
                for p in ports_by_bridge[sw]:
                    peer = self._dtp_peer(sw, p)
                    is_internal = (
                        peer is not None
                        and peer[0] in bridge_set
                        and peer[1] in ports_by_bridge.get(peer[0], [])
                    )
                    if bridge_info[sw]["is_root"]:
                        role, state = "Desg", "FWD"
                    elif root_port.get(sw) == p and is_internal:
                        role, state = "Root", "FWD"
                    elif not is_internal:
                        role, state = "Desg", "FWD"
                    else:
                        nb = peer[0]
                        if (dist.get(sw, 0), self._bridge_id(sw, vlan)) < (
                            dist.get(nb, 0), self._bridge_id(nb, vlan)
                        ):
                            role, state = "Desg", "FWD"
                        else:
                            role, state = "Altn", "BLK"
                    port_state[(sw, p)] = {
                        "role": role,
                        "state": state,
                        "cost": self._port_cost(sw, p),
                        "portnum": self._iol_port_number(p),
                    }

        result = {
            "bridges": bridge_info,
            "ports": port_state,
            "ports_by_bridge": ports_by_bridge,
        }
        self._stp_cache[vlan] = result
        return result

    def _vlan_has_forwarding_port(self, node: str, vlan: int) -> bool:
        info = self._stp_vlan(vlan)
        for (sw, _), st in info["ports"].items():
            if sw == node and st["state"] == "FWD":
                return True
        return False

    def _port_forwarding_vlans(self, node: str, iface: str) -> List[int]:
        logical = self._logical_port(node, iface)
        result: List[int] = []
        for v in self._active_vlans(node, iface):
            info = self._stp_vlan(v)
            st = info["ports"].get((node, logical))
            if st and st["state"] == "FWD":
                result.append(v)
        return result

    def stp(self, node: str, vlan: int) -> Optional[StpInfo]:
        """PVST+ instance for ``vlan`` as seen by ``node``; ``None`` if absent."""
        n = self.nodes.get(node)
        if n is None or n.kind != "switch" or vlan not in n.vlans:
            return None
        info = self._stp_vlan(vlan)
        binfo = info["bridges"].get(node)
        if binfo is None:
            return None
        root_name = binfo["root_name"]
        root_node = self.nodes[root_name]
        root_priority = binfo["root_bid"][0]
        ports: List[StpPort] = []
        for p in info["ports_by_bridge"].get(node, []):
            st = info["ports"][(node, p)]
            edge = self._portfast_enabled(node, p)
            ports.append(
                StpPort(
                    interface=p,
                    port=self._short_ifname(p),
                    role=st["role"],
                    state=st["state"],
                    cost=st["cost"],
                    priority=DEFAULT_PORT_PRIORITY,
                    port_number=st["portnum"],
                    prio_nbr=f"{DEFAULT_PORT_PRIORITY}.{st['portnum']}",
                    type="P2p Edge" if edge else "P2p",
                    edge=edge,
                )
            )
        ports.sort(key=lambda sp: natural_key(sp.interface))
        bridge_priority = n.stp_priorities.get(vlan, DEFAULT_BRIDGE_PRIORITY) + vlan
        return StpInfo(
            node=node,
            vlan=vlan,
            is_root=binfo["is_root"],
            root_priority=root_priority,
            root_address=format_mac(root_node.base_mac(), "cisco"),
            root_cost=binfo["rpc"],
            root_port=self._short_ifname(binfo["root_port"]) if binfo["root_port"] else None,
            bridge_priority=bridge_priority,
            bridge_address=format_mac(n.base_mac(), "cisco"),
            hello_time=STP_HELLO_TIME,
            max_age=STP_MAX_AGE,
            forward_delay=STP_FORWARD_DELAY,
            aging_time=n.mac_aging_time,
            ports=tuple(ports),
        )

    def stp_vlans(self, node: str) -> List[int]:
        """VLANs that have a PVST+ instance on ``node``."""
        n = self.nodes.get(node)
        if n is None or n.kind != "switch":
            return []
        return sorted(n.vlans)

    # ------------------------------------------------------------------
    # Broadcast-domain segmentation
    # ------------------------------------------------------------------
    def _port_untagged_and_tagged(self, node: str, logical: str) -> Tuple[Optional[int], Set[int]]:
        """Return ``(untagged_vlan, tagged_vlans)`` a forwarding L2 port carries."""
        if not self._port_operational(node, logical):
            return None, set()
        mode = self._oper_mode(node, logical)
        if mode == "static access":
            v = self._access_vlan(node, logical)
            info = self._stp_vlan(v)
            st = info["ports"].get((node, self._logical_port(node, logical)))
            if st and st["state"] == "FWD":
                return v, set()
            return None, set()
        if mode == "trunk":
            fwd = set(self._port_forwarding_vlans(node, logical))
            native = self._native_vlan(node, logical)
            untagged = native if native in fwd else None
            return untagged, {v for v in fwd if v != native}
        return None, set()

    def _switch_port_vlan_for_tag(self, sw: str, la: str, tag: Optional[int]) -> Optional[int]:
        """Resolve the VLAN a switch port assigns to a frame with ``tag`` (None=untagged)."""
        untagged, tagged = self._port_untagged_and_tagged(sw, la)
        if tag is None:
            return untagged
        if tag in tagged:
            return tag
        if untagged is not None and tag == untagged:
            return untagged
        return None

    def _subinterfaces(self, node: str, parent: str) -> List[str]:
        n = self.nodes.get(node)
        if n is None:
            return []
        parent = canonical_interface(parent)
        return [
            i.name
            for i in n.interfaces.values()
            if interface_parent(i.name) == parent
            and self.line_state(node, i.name) == ("up", "up")
        ]

    @staticmethod
    def _add_path_edge(graph: Dict[Segment, list], ta, pa, tb, pb) -> None:
        graph.setdefault(ta, []).append((tb, pa, pb))
        graph.setdefault(tb, []).append((ta, pb, pa))

    def _join_switch_device(self, uf, graph, sw, swi, dev, devi) -> None:
        la = self._logical_port(sw, swi)
        if not self._port_operational(sw, la):
            return
        if self.line_state(dev, devi) == ("up", "up"):
            vlan = self._switch_port_vlan_for_tag(sw, la, None)
            if vlan is not None:
                uf.union(("sv", sw, vlan), ("ep", dev, devi))
                self._add_path_edge(graph, ("sv", sw, vlan), la, ("ep", dev, devi), devi)
        for sub in self._subinterfaces(dev, devi):
            si = self._iface(dev, sub)
            tag = None if (si and si.encapsulation_native) else (si.encapsulation_vlan if si else None)
            vlan = self._switch_port_vlan_for_tag(sw, la, tag)
            if vlan is not None:
                uf.union(("sv", sw, vlan), ("ep", dev, sub))
                self._add_path_edge(graph, ("sv", sw, vlan), la, ("ep", dev, sub), sub)

    def _join_l3_l3(self, uf, graph, a, ai, b, bi) -> None:
        def tag_map(node: str, iface: str) -> Dict[Optional[int], Tuple[Segment, str]]:
            result: Dict[Optional[int], Tuple[Segment, str]] = {}
            if (
                self._is_physical(iface)
                and not self._is_subinterface(iface)
                and self.line_state(node, iface) == ("up", "up")
            ):
                result[None] = (("ep", node, iface), iface)
            for sub in self._subinterfaces(node, iface):
                si = self._iface(node, sub)
                tag = None if (si and si.encapsulation_native) else (si.encapsulation_vlan if si else None)
                result[tag] = (("ep", node, sub), sub)
            return result

        ma = tag_map(a, ai)
        mb = tag_map(b, bi)
        for tag in set(ma) & set(mb):
            (ta, pa), (tb, pb) = ma[tag], mb[tag]
            uf.union(ta, tb)
            self._add_path_edge(graph, ta, pa, tb, pb)

    def _build_segments(self) -> dict:
        if self._segment_state is not None:
            return self._segment_state

        uf = _UnionFind()
        graph: Dict[Segment, list] = {}
        active: Set[Segment] = set()
        point: Dict[Segment, Point] = {}

        for name, node in self.nodes.items():
            if node.kind == "switch":
                for v in node.vlans:
                    uf.add(("sv", name, v))

        for name, node in self.nodes.items():
            for i in list(node.interfaces.values()):
                iface = i.name
                up = self.line_state(name, iface) == ("up", "up")
                if self._is_svi(iface):
                    if node.kind == "switch":
                        v = interface_vlan(iface)
                        tok = ("sv", name, v)
                        uf.add(tok)
                        if up and v in node.vlans:
                            active.add(tok)
                            point.setdefault(tok, (name, iface))
                    continue
                if self._is_loopback(iface):
                    if up:
                        tok = ("ep", name, iface)
                        uf.add(tok)
                        active.add(tok)
                        point[tok] = (name, iface)
                    continue
                if node.kind == "switch":
                    gov, _ = self._governing(name, iface)
                    is_port = (
                        self._is_portchannel(iface)
                        or (self._is_physical(iface) and not self._is_subinterface(iface))
                    )
                    if is_port and gov is not None and gov.routed_port and up:
                        tok = ("ep", name, iface)
                        uf.add(tok)
                        active.add(tok)
                        point[tok] = (name, iface)
                    continue
                # Router / host L3 attachment points.
                if self._is_portchannel(iface) or self._is_subinterface(iface) or (
                    self._is_physical(iface) and not self._is_subinterface(iface)
                ):
                    if up:
                        tok = ("ep", name, iface)
                        uf.add(tok)
                        active.add(tok)
                        point[tok] = (name, iface)

        for (a, ai, b, bi) in self.links:
            na = self.nodes.get(a)
            nb = self.nodes.get(b)
            if na is None or nb is None:
                continue
            a_sw = na.kind == "switch"
            b_sw = nb.kind == "switch"
            if a_sw and b_sw:
                la = self._logical_port(a, ai)
                lb = self._logical_port(b, bi)
                if not (self._port_operational(a, la) and self._port_operational(b, lb)):
                    continue
                ua, ta_set = self._port_untagged_and_tagged(a, la)
                transmissions: List[Tuple[int, Optional[int]]] = []
                if ua is not None:
                    transmissions.append((ua, None))
                for t in ta_set:
                    transmissions.append((t, t))
                for (vA, tag) in transmissions:
                    vB = self._switch_port_vlan_for_tag(b, lb, tag)
                    if vB is not None:
                        uf.union(("sv", a, vA), ("sv", b, vB))
                        self._add_path_edge(graph, ("sv", a, vA), la, ("sv", b, vB), lb)
            elif a_sw:
                self._join_switch_device(uf, graph, a, ai, b, bi)
            elif b_sw:
                self._join_switch_device(uf, graph, b, bi, a, ai)
            else:
                self._join_l3_l3(uf, graph, a, ai, b, bi)

        self._segment_state = {
            "uf": uf,
            "graph": graph,
            "active": active,
            "point": point,
        }
        return self._segment_state

    def _point_token(self, node: str, iface: str) -> Segment:
        canonical = canonical_interface(iface)
        if self._is_svi(canonical):
            return ("sv", node, interface_vlan(canonical))
        return ("ep", node, canonical)

    def segment_of(self, node: str, iface: str) -> Optional[Segment]:
        """Opaque broadcast-domain id for an L3 attachment point, or ``None``.

        ``None`` is returned when the node/interface is unknown or the
        attachment is not currently forwarding (shut, no cable, STP-blocked,
        err-disabled, autostate-down SVI, or in a deleted VLAN).
        """
        n = self.nodes.get(node)
        if n is None:
            return None
        canonical = canonical_interface(iface)
        if canonical not in n.interfaces:
            return None
        state = self._build_segments()
        tok = self._point_token(node, canonical)
        if tok not in state["active"]:
            return None
        return state["uf"].find(tok)

    def segment_members(self, segment: Segment) -> List[Point]:
        """Every active L3 attachment point sharing ``segment``."""
        if segment is None:
            return []
        state = self._build_segments()
        uf = state["uf"]
        members = [
            state["point"][tok]
            for tok in state["active"]
            if uf.find(tok) == segment
        ]
        return sorted(members, key=lambda pt: (pt[0], natural_key(pt[1])))

    def l2_path(self, src: Point, dst: Point) -> Optional[List[dict]]:
        """Switch-by-switch path (``switch``, ``vlan``, ``ingress``, ``egress``) hops.

        Returns ``[]`` for a direct (switch-less) same-segment pair and ``None``
        when the two attachment points are not in the same broadcast domain.
        """
        state = self._build_segments()
        uf = state["uf"]
        graph = state["graph"]
        src_tok = self._point_token(src[0], canonical_interface(src[1]))
        dst_tok = self._point_token(dst[0], canonical_interface(dst[1]))
        if src_tok not in state["active"] or dst_tok not in state["active"]:
            return None
        if uf.find(src_tok) != uf.find(dst_tok):
            return None
        if src_tok == dst_tok:
            return []

        # Breadth-first search for a shortest token path.
        predecessor: Dict[Segment, Optional[Segment]] = {src_tok: None}
        queue = [src_tok]
        cursor = 0
        while cursor < len(queue):
            current = queue[cursor]
            cursor += 1
            if current == dst_tok:
                break
            for (neighbor, _, _) in graph.get(current, []):
                if neighbor not in predecessor:
                    predecessor[neighbor] = current
                    queue.append(neighbor)
        if dst_tok not in predecessor:
            return None

        order: List[Segment] = []
        node = dst_tok
        while node is not None:
            order.append(node)
            node = predecessor[node]
        order.reverse()

        def port_on(tok: Segment, other: Segment) -> Optional[str]:
            for (neighbor, local_port, _) in graph.get(tok, []):
                if neighbor == other:
                    return local_port
            return None

        hops: List[dict] = []
        for index, tok in enumerate(order):
            if not (isinstance(tok, tuple) and tok[0] == "sv"):
                continue
            _, sw, vlan = tok
            ingress = f"Vlan{vlan}" if index == 0 else port_on(tok, order[index - 1])
            egress = f"Vlan{vlan}" if index == len(order) - 1 else port_on(tok, order[index + 1])
            hops.append({"switch": sw, "vlan": vlan, "ingress": ingress, "egress": egress})
        return hops

    # ------------------------------------------------------------------
    # MAC learning and aging
    # ------------------------------------------------------------------
    def learn(self, path: Sequence[dict], src_mac: str, now: Optional[float] = None) -> str:
        """Record ``src_mac`` on each hop's ingress port (dynamic MAC learning).

        Returns :data:`LEARN_FORWARDED` when the frame crossed every hop,
        :data:`LEARN_DROPPED` when a secure port dropped it (``protect`` /
        ``restrict``), or :data:`LEARN_ERRDISABLED` when it err-disabled a
        ``violation shutdown`` port.  After an err-disable the fabric's derived
        state is rebuilt on the next query; callers holding results computed
        from the old topology (L3 forwarding, cached bundles) must refresh too.
        """
        if now is None:
            now = self.now
        try:
            mac = models.normalise_mac(src_mac)
        except ValueError:
            return LEARN_FORWARDED
        for hop in path:
            sw = hop.get("switch")
            vlan = hop.get("vlan")
            ingress = hop.get("ingress")
            n = self.nodes.get(sw)
            if n is None or n.kind != "switch" or vlan is None or not ingress:
                continue
            if self._is_svi(ingress):
                continue  # frame originated on this switch's SVI
            port = canonical_interface(ingress)
            i = self._iface(sw, port)
            stamp = now if now is not None else 0.0
            if i is not None and i.port_security_enabled:
                outcome = self._secure_admit(sw, n, i, int(vlan), mac, stamp)
                if outcome != LEARN_FORWARDED:
                    return outcome  # the frame is dropped at this port
                continue
            n.mac_table[(int(vlan), mac)] = models.MacEntry(
                vlan=int(vlan), mac=mac, port=port, learned_at=stamp, static=False
            )
        return LEARN_FORWARDED

    @staticmethod
    def _macs(values: Sequence[str]) -> List[str]:
        result: List[str] = []
        for value in values:
            try:
                mac = models.normalise_mac(value)
            except ValueError:
                continue
            if mac not in result:
                result.append(mac)
        return result

    def _secure_macs(self, n, i) -> Set[str]:
        """Addresses a secure port currently allows (configured + sticky + learned)."""
        allowed = set(self._macs(i.port_security_macs)) | set(self._macs(i.port_security_sticky_macs))
        for entry in n.mac_table.values():
            if entry.secure and canonical_interface(entry.port) == i.name:
                allowed.add(entry.mac)
        return allowed

    def _secure_admit(self, node: str, n, i, vlan: int, mac: str, now: float) -> str:
        """Port-security admission of one frame on secure port ``i``.

        A known secure address is forwarded; a new one is learned as a secure
        address (sticky when ``mac-address sticky`` is on) while the port is
        below its maximum.  Otherwise it is a violation: ``protect`` drops the
        frame, ``restrict`` drops and counts it, ``shutdown`` err-disables the
        port (counting it and flushing its dynamic secure addresses).
        """
        i.port_security_last_source = f"{format_mac(mac, 'cisco')}:{vlan}"
        allowed = self._secure_macs(n, i)
        sticky = mac in self._macs(i.port_security_sticky_macs)
        if mac in allowed or len(allowed) < int(i.port_security_maximum):
            if mac not in allowed and i.port_security_sticky:
                i.port_security_sticky_macs.append(format_mac(mac, "cisco"))
                sticky = True
            n.mac_table[(vlan, mac)] = models.MacEntry(
                vlan=vlan, mac=mac, port=i.name, learned_at=now, static=False,
                secure="sticky" if sticky else "dynamic",
            )
            return LEARN_FORWARDED
        mode = i.port_security_violation
        if mode == "protect":
            return LEARN_DROPPED
        message = (
            f"%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by "
            f"MAC address {format_mac(mac, 'cisco')} on port {i.name}."
        )
        if mode == "restrict":
            i.port_security_violation_count += 1
            self._event("psecure", node, message)
            return LEARN_DROPPED
        if i.err_disabled_reason:
            return LEARN_DROPPED
        i.port_security_violation_count = 1
        i.err_disabled_reason = "psecure-violation"
        # The port goes down: its dynamic (non-sticky) secure addresses go too.
        for key in [k for k, entry in n.mac_table.items()
                    if canonical_interface(entry.port) == i.name and not entry.static
                    and entry.secure != "sticky"]:
            del n.mac_table[key]
        # The port leaves the forwarding topology: drop every derived cache.
        self._errdis_cache.clear()
        self._etherchannel_cache.clear()
        self._stp_cache.clear()
        self._segment_state = None
        short = self._short_ifname(i.name)
        self._event(
            "errdisable", node,
            f"%PM-4-ERR_DISABLE: psecure-violation error detected on {short}, "
            f"putting {short} in err-disable state",
        )
        self._event("psecure", node, message)
        return LEARN_ERRDISABLED

    def _event(self, kind: str, node: str, message: str) -> None:
        sink = self.event_sink
        if sink is None:
            return
        try:
            sink(kind, node, message)
        except Exception:  # pragma: no cover - reporting must never break forwarding
            pass

    def _port_mac_count(self, node: str, port: str) -> int:
        """Secure address count of a port (configured + sticky + learned)."""
        n = self.nodes.get(node)
        i = self._iface(node, port)
        if n is None or i is None:
            return 0
        return len(self._secure_macs(n, i))

    def admits(self, path: Sequence[dict], src_mac: str) -> bool:
        """Side-effect-free: would every secure port on ``path`` pass ``src_mac``?

        A secure port passes a known secure address, or a new one while it is
        below its maximum (it would be learned); anything else is a violation,
        which drops the frame in every violation mode.
        """
        try:
            mac = models.normalise_mac(src_mac)
        except ValueError:
            return True
        for hop in path:
            n = self.nodes.get(hop.get("switch"))
            ingress = hop.get("ingress")
            if n is None or n.kind != "switch" or not ingress or self._is_svi(ingress):
                continue
            i = self._iface(n.name, canonical_interface(ingress))
            if i is None or not i.port_security_enabled:
                continue
            allowed = self._secure_macs(n, i)
            if mac not in allowed and len(allowed) >= int(i.port_security_maximum):
                return False
        return True

    def mac_table(self, node: str, now: Optional[float] = None) -> List[MacTableEntry]:
        """``show mac address-table`` entries after aging, plus router-facing MACs."""
        if now is None:
            now = self.now
        n = self.nodes.get(node)
        if n is None or n.kind != "switch":
            return []
        entries: List[MacTableEntry] = []
        seen: Set[Tuple[int, str]] = set()
        for (vlan, mac), entry in n.mac_table.items():
            secure = bool(getattr(entry, "secure", None))
            if not entry.static and not secure and now is not None and entry.learned_at is not None:
                if now - entry.learned_at > n.mac_aging_time:
                    continue
            seen.add((vlan, mac))
            entries.append(
                MacTableEntry(
                    vlan=entry.vlan,
                    mac=format_mac(entry.mac, "cisco"),
                    # Port-security addresses are installed as STATIC entries.
                    type="STATIC" if (entry.static or secure) else "DYNAMIC",
                    port=self._short_ifname(entry.port),
                )
            )

        # Configured secure addresses of an operational access port are
        # installed in its VLAN as well (sticky ones once learned are above).
        for i in n.interfaces.values():
            if not i.port_security_enabled or i.err_disabled_reason:
                continue
            if self.line_state(node, i.name) != ("up", "up"):
                continue
            if self._oper_mode(node, i.name) != "static access":
                continue
            vlan_id = self._access_vlan(node, i.name)
            for mac in self._macs(list(i.port_security_macs) + list(i.port_security_sticky_macs)):
                key = (vlan_id, mac)
                if key in seen:
                    continue
                seen.add(key)
                entries.append(
                    MacTableEntry(
                        vlan=vlan_id,
                        mac=format_mac(mac, "cisco"),
                        type="STATIC",
                        port=self._short_ifname(i.name),
                    )
                )

        # Routers source frames continuously: the facing switch port always
        # knows the router MAC in the port's untagged / native VLAN.
        for i in n.interfaces.values():
            name = i.name
            if self._is_svi(name) or self._is_loopback(name) or self._is_subinterface(name):
                continue
            logical = self._logical_port(node, name)
            if logical != canonical_interface(name):
                continue  # only the logical (Po or standalone) port
            peer = self.peer(node, name)
            if peer is None:
                continue
            peer_node = self.nodes.get(peer[0])
            if peer_node is None or peer_node.kind != "router":
                continue
            if self._is_subinterface(peer[1]):
                continue
            untagged, _ = self._port_untagged_and_tagged(node, logical)
            if untagged is None:
                continue
            rmac = peer_node.interface_mac(peer[1])
            if not rmac:
                continue
            key = (untagged, models.normalise_mac(rmac))
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                MacTableEntry(
                    vlan=untagged,
                    mac=format_mac(rmac, "cisco"),
                    type="DYNAMIC",
                    port=self._short_ifname(logical),
                )
            )

        entries.sort(key=lambda e: (e.vlan, e.mac))
        return entries

    # ------------------------------------------------------------------
    # Port security
    # ------------------------------------------------------------------
    def port_security(self, node: str, iface: str) -> Optional[PortSecurityInfo]:
        """``show port-security interface`` view, or ``None`` if not applicable."""
        n = self.nodes.get(node)
        i = self._iface(node, iface)
        if n is None or i is None or n.kind != "switch":
            return None
        canonical = canonical_interface(iface)
        if not self._is_switchport(node, canonical):
            return None
        reason = self._err_disabled(node, canonical)
        if reason == "psecure-violation":
            status = "Secure-shutdown"
        elif self.line_state(node, canonical) == ("up", "up"):
            status = "Secure-up"
        else:
            status = "Secure-down"
        last_source: Optional[str] = None
        latest = -1.0
        for (vlan, mac), entry in n.mac_table.items():
            if canonical_interface(entry.port) == canonical and entry.learned_at is not None:
                if entry.learned_at >= latest:
                    latest = entry.learned_at
                    last_source = format_mac(mac, "cisco")
        return PortSecurityInfo(
            interface=canonical,
            enabled=i.port_security_enabled,
            max_addresses=i.port_security_maximum,
            violation=i.port_security_violation,
            sticky=i.port_security_sticky,
            total_addresses=self._port_mac_count(node, canonical),
            status=status,
            last_source=last_source,
        )

    def as_network_callbacks(self):
        """Return ``(segment_of, line_protocol_up)`` for ``adapters.NetworkCallbacks``."""
        def segment_of(node_name: str, interface_name: str) -> Optional[Segment]:
            return self.segment_of(node_name, interface_name)

        def line_protocol_up(node_name: str, interface_name: str) -> bool:
            return self.line_state(node_name, interface_name) == ("up", "up")

        return segment_of, line_protocol_up
