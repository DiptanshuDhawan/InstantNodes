"""Engine-neutral callback bundle shared by the protocol engines.

The L3, OSPF, DHCP, discovery and services engines are written against these
four callables instead of importing each other, so they can be developed and
tested independently.  :func:`simulator.engines.build_bundle` wires them from
``l2.L2Fabric`` (segment_of / line_protocol_up) and ``l3.L3Engine`` (find_ip /
reachable); ``legacy_callbacks`` returns that bundle for callers without a
runtime.

Semantics every implementation must honour:

* ``segment_of(node, iface)`` returns a hashable broadcast-domain id for an L3
  attachment point (router port or subinterface, SVI, routed switch port, host
  NIC), or ``None`` when the node or interface does not exist.  It does not
  consider the attachment's own line state; check ``line_protocol_up`` too.
* ``line_protocol_up(node, iface)`` is True when the interface would print
  "up/up" in ``show ip interface brief``.
* ``find_ip(address)`` returns ``(node, iface)`` owning that IPv4 address on an
  up interface, or ``None``.
* ``reachable(src_node, dst_ip)`` is a side-effect-free round-trip check.

A bundle reflects the layer-2 state at creation time.  Build a new one after
changing VLANs, links, switchports or interface admin state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Hashable, Iterable, Optional, Tuple

from .models import NodeState

Link = Tuple[str, str, str, str]
SegmentOf = Callable[[str, str], Optional[Hashable]]
LineProtocolUp = Callable[[str, str], bool]
FindIp = Callable[[str], Optional[Tuple[str, str]]]
Reachable = Callable[[str, str], bool]


@dataclass(frozen=True)
class NetworkCallbacks:
    segment_of: SegmentOf
    line_protocol_up: LineProtocolUp
    find_ip: FindIp
    reachable: Reachable


def legacy_callbacks(nodes: Dict[str, NodeState], links: Iterable[Link]) -> NetworkCallbacks:
    """Build the callback bundle for ``nodes``/``links`` without a runtime.

    Kept under its historical name for callers that have no engine provider
    (e.g. a shell used outside a runtime).  Since Phase 3 it is the fully wired
    bundle from :func:`simulator.engines.build_bundle` -- the same callbacks the
    services engine uses in a live runtime.
    """
    import time

    from .engines import build_bundle  # local import avoids an import cycle

    return build_bundle(nodes, list(links), time.time()).callbacks
