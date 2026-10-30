"""Composition of the protocol engines into a single :class:`EngineBundle`.

The Phase 1 engines (:mod:`simulator.l2`, :mod:`simulator.l3`,
:mod:`simulator.ospf`, :mod:`simulator.services`) are written against the shared
:class:`simulator.adapters.NetworkCallbacks` bundle so they can be developed
independently.  This module performs the one correct wiring of those callbacks
(validated by the Phase 1 integration smoke) and hands the CLI command layer a
single object to read live network state from.

Build order (order matters -- L3 supplies ``find_ip``/``reachable`` that the
services engine needs, while L2 supplies ``segment_of``/``line_protocol_up``
that everyone needs)::

    L2Fabric.as_network_callbacks() -> (segment_of, line_protocol_up)
      -> partial NetworkCallbacks(seg, lp, <stub find_ip>, <stub reachable>)
      -> OspfEngine(partial) ; L3Engine(partial, ospf=that)
      -> full NetworkCallbacks(seg, lp, L3.find_ip adapter, L3.reachable)
      -> ServicesEngine(full)

L3's ``find_ip`` returns an :class:`~simulator.l3.IPEndpoint`; the callback
contract is ``find_ip(addr) -> (node, iface) | None``, so it is adapted here.

Freshness
---------
Engines are stateless *views* over the mutable :class:`~simulator.models.NodeState`
objects; the dynamic state they produce (DHCP leases, ARP entries, counters,
clock offset, log buffer) is written back into those NodeState objects, so it
survives a rebuild.  A bundle only needs rebuilding when the *configuration* or
topology changes (addresses, shutdown, switchport/VLAN, OSPF, links).
:class:`EngineProvider` caches a bundle and rebuilds it when a caller-supplied
version token changes, so ``ctx.engines`` is always current without rebuilding
on every keystroke.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, Optional, Tuple

from .adapters import Link, NetworkCallbacks
from .l2 import L2Fabric
from .l3 import L3Engine
from .models import NodeState
from .ospf import OspfEngine
from .services import ServicesEngine

__all__ = ["EngineBundle", "build_bundle", "EngineProvider"]


class EngineBundle:
    """The four protocol engines, wired together over one callback bundle.

    Attributes
    ----------
    l2, ospf, l3, services
        The composed engine instances (see their modules for the public API).
    callbacks
        The fully-wired :class:`NetworkCallbacks` (segment_of, line_protocol_up,
        find_ip, reachable) used by the services engine and available to any
        command handler that needs raw reachability.
    nodes, links, now
        The inputs the bundle was built from.
    """

    __slots__ = ("l2", "ospf", "l3", "services", "callbacks", "nodes", "links", "now")

    def __init__(
        self,
        l2: L2Fabric,
        ospf: OspfEngine,
        l3: L3Engine,
        services: ServicesEngine,
        callbacks: NetworkCallbacks,
        nodes: Dict[str, NodeState],
        links: Iterable[Link],
        now: float,
    ) -> None:
        self.l2 = l2
        self.ospf = ospf
        self.l3 = l3
        self.services = services
        self.callbacks = callbacks
        self.nodes = nodes
        self.links = links
        self.now = now


def build_bundle(
    nodes: Dict[str, NodeState], links: Iterable[Link], now: float
) -> EngineBundle:
    """Compose L2/OSPF/L3/services for ``nodes``/``links`` at time ``now``."""
    link_list = list(links)
    l2 = L2Fabric(nodes, link_list, now)
    seg_of, lp_up = l2.as_network_callbacks()

    # L3/OSPF only consult segment_of + line_protocol_up; stub the rest so the
    # partial bundle is valid while L3 (which supplies them) is constructed.
    partial = NetworkCallbacks(seg_of, lp_up, lambda _addr: None, lambda _s, _d: False)
    ospf = OspfEngine(nodes, link_list, partial, now)
    l3 = L3Engine(nodes, link_list, partial, now, ospf=ospf)

    def find_ip(address: str) -> Optional[Tuple[str, str]]:
        endpoint = l3.find_ip(address)
        if endpoint is None:
            return None
        return endpoint.node, endpoint.interface

    full = NetworkCallbacks(seg_of, lp_up, find_ip, l3.reachable)
    services = ServicesEngine(nodes, link_list, full, now)

    def learn_macs(legs, when: float) -> str:
        """L3 -> L2 coupling: a live ping teaches each switch on its path the
        sender's MAC, in both directions (echo request and reply).  Returns an
        :meth:`L2Fabric.learn` outcome: "" forwarded, "dropped" or "errdisabled"
        (port security; the worst outcome over all legs)."""
        worst = ""
        for leg in legs:
            for source, target in ((leg.src, leg.dst), (leg.dst, leg.src)):
                owner = nodes.get(source[0])
                mac = owner.interface_mac(source[1]) if owner is not None else None
                if not mac:
                    continue
                path = l2.l2_path(source, target)
                if not path:
                    continue
                outcome = l2.learn(path, mac, when)
                if outcome == "errdisabled" or (outcome and not worst):
                    worst = outcome
        if worst == "errdisabled":
            # OSPF adjacencies may ride on the port that just went down.
            ospf.invalidate()
        return worst

    l3.mac_learner = learn_macs

    def mac_admits(legs) -> bool:
        """Side-effect-free twin of ``learn_macs`` for reachability checks."""
        for leg in legs:
            for source, target in ((leg.src, leg.dst), (leg.dst, leg.src)):
                owner = nodes.get(source[0])
                mac = owner.interface_mac(source[1]) if owner is not None else None
                if not mac:
                    continue
                path = l2.l2_path(source, target)
                if path and not l2.admits(path, mac):
                    return False
        return True

    l3.mac_filter = mac_admits
    return EngineBundle(l2, ospf, l3, services, full, nodes, link_list, now)


class EngineProvider:
    """Returns an :class:`EngineBundle` reflecting current state, with caching.

    The runtime installs ``shell.engine_provider = provider.get`` so that
    ``ctx.engines`` transparently yields a current bundle.

    Parameters
    ----------
    nodes, links
        The runtime's live state containers (passed by reference).
    now_fn
        Zero-arg callable returning the current epoch time (``runtime.now``).
    version_fn
        Optional zero-arg callable returning a hashable token that changes
        whenever configuration/topology changes (e.g. a counter the runtime
        bumps on every config-mode command and on reset).  When ``None`` the
        provider rebuilds on every call -- correct but not cached (used by unit
        tests).
    """

    def __init__(
        self,
        nodes: Dict[str, NodeState],
        links: Iterable[Link],
        now_fn: Callable[[], float],
        version_fn: Optional[Callable[[], object]] = None,
        on_build: Optional[Callable[[EngineBundle], None]] = None,
    ) -> None:
        self._nodes = nodes
        self._links = list(links)
        self._now_fn = now_fn
        self._version_fn = version_fn
        #: Called with every newly built bundle (the runtime wires event sinks).
        self._on_build = on_build
        self._cache: Optional[EngineBundle] = None
        self._cache_key: object = object()  # sentinel that never equals a token

    def _build(self) -> EngineBundle:
        bundle = build_bundle(self._nodes, self._links, self._now_fn())
        if self._on_build is not None:
            self._on_build(bundle)
        return bundle

    def get(self) -> EngineBundle:
        if self._version_fn is None:
            return self._build()
        token = self._version_fn()
        if self._cache is None or token != self._cache_key:
            self._cache = self._build()
            self._cache_key = token
        return self._cache

    def invalidate(self) -> None:
        """Force the next :meth:`get` to rebuild."""
        self._cache = None
        self._cache_key = object()
