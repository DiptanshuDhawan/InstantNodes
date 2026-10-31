"""Per-session simulation runtime and immutable grading snapshots.

Phase 2 (A3b) additions
-----------------------
* ``runtime.clock`` / :meth:`SimulationRuntime.now` -- the simulated wall clock
  (overridable for deterministic tests).
* ``runtime.config_version`` -- bumped by every :meth:`mark_changed` (also while
  loading), by :meth:`reset`, :meth:`reload_node` and :meth:`apply_config`; it keys
  the cached :class:`~simulator.engines.EngineBundle` returned by :meth:`engines`.
* :meth:`mark_changed` re-runs DHCP for every DHCP-enabled host through the
  services engine (automatic retry; see ``NetworkEngine.recompute_dhcp``).
* :meth:`emit_log` -- syslog for a node (timestamp, log buffer, console and
  ``terminal monitor`` delivery).
"""

from __future__ import annotations

from dataclasses import dataclass
import copy
from pathlib import Path
import re
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional, Set, Tuple

import yaml

from .config_replay import apply_authored_config
from .console import NodeConsole
from .engines import EngineBundle, EngineProvider
from .models import (
    LogEntry,
    NodeState,
    canonical_interface,
    natural_key,
)
from .network import Link, NetworkEngine

#: Maximum number of syslog entries kept in ``node.log_buffer``.
LOG_BUFFER_LIMIT = 1000


class SimulatorError(RuntimeError):
    """Base error for simulator operations."""


class RuntimeNotFound(SimulatorError):
    pass


class InvalidRuntimeState(SimulatorError):
    pass


class NodeNotFound(SimulatorError):
    pass


class TerminalNotFound(SimulatorError):
    pass


def classify_node(definition: dict) -> Tuple[str, str]:
    """Resolve canonical device kind and CLI profile from new and legacy manifests."""
    name = str(definition.get("name", ""))
    explicit_kind = str(definition.get("kind", "")).strip().lower()
    device_type = str(
        definition.get("device_type", definition.get("type", ""))
    ).strip().lower()
    explicit_profile = str(definition.get("cli_profile", "")).strip().lower()

    aliases = {
        "router": "router",
        "switch": "switch",
        "host": "host",
        "pc": "host",
        "vpcs": "host",
        "cisco_iol_l2": "switch",
    }
    kind = aliases.get(explicit_kind)
    name_says_host = bool(re.match(r"^(?:pc|host|client)", name, re.IGNORECASE))
    if kind is None:
        if device_type == "cisco_iol_l2" or "switch" in device_type:
            kind = "switch"
        elif device_type == "vpcs":
            kind = "host"
        elif device_type.startswith("cisco_ios") or device_type.startswith("cisco_iol"):
            kind = "host" if name_says_host else "router"
        elif name_says_host:
            kind = "host"
        else:
            kind = "router"

    if explicit_profile in {"ios", "vpcs"}:
        profile = explicit_profile
    elif device_type == "vpcs":
        profile = "vpcs"
    else:
        profile = "ios"
    return kind, profile


@dataclass(frozen=True)
class TerminalAttachment:
    runtime_id: str
    connection_id: str
    node_name: str
    initial_output: str


def _oper_messages(before: dict, after: dict, nodes: Dict[str, NodeState]) -> List[Tuple[str, str]]:
    """IOS syslog lines for the differences between two operational snapshots.

    Physical/loopback/SVI/port-channel interfaces log ``%LINK``/``%LINEPROTO``
    (subinterfaces do not, like IOS); OSPF logs ``%OSPF-5-ADJCHG`` when a
    neighbour reaches or leaves FULL (``log-adjacency-changes``, the default).
    A newly created interface is treated as coming from administratively down.
    """
    messages: List[Tuple[str, str]] = []
    old_links, new_links = before["links"], after["links"]
    for key in sorted(new_links, key=lambda item: (item[0], natural_key(item[1]))):
        node_name, interface = key
        if "." in interface:
            continue
        old = old_links.get(key, ("administratively down", "down"))
        new = new_links[key]
        if old == new:
            continue
        old_status, old_protocol = old
        new_status, new_protocol = new
        if old_status != new_status:
            if new_status == "administratively down":
                messages.append(
                    (node_name, f"%LINK-5-CHANGED: Interface {interface}, changed state to administratively down")
                )
            elif new_status == "up":
                messages.append((node_name, f"%LINK-3-UPDOWN: Interface {interface}, changed state to up"))
            elif old_status == "up":
                messages.append((node_name, f"%LINK-3-UPDOWN: Interface {interface}, changed state to down"))
        if (old_protocol == "up") != (new_protocol == "up"):
            state = "up" if new_protocol == "up" else "down"
            messages.append(
                (node_name, f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {interface}, changed state to {state}")
            )
    old_ospf, new_ospf = before["ospf"], after["ospf"]
    for key in sorted(set(old_ospf) | set(new_ospf)):
        node_name, interface, neighbor_id = key
        old = old_ospf.get(key)
        new = new_ospf.get(key)
        was_full = old is not None and old[0].startswith("FULL")
        is_full = new is not None and new[0].startswith("FULL")
        if was_full == is_full:
            continue
        process_id = (new or old)[1]  # type: ignore[index]
        node = nodes.get(node_name)
        process = node.ospf_processes.get(process_id) if (node and process_id is not None) else None
        if process_id is None or (process is not None and not process.log_adjacency_changes):
            continue
        if is_full:
            text = (
                f"%OSPF-5-ADJCHG: Process {process_id}, Nbr {neighbor_id} on {interface} "
                "from LOADING to FULL, Loading Done"
            )
        else:
            # The router whose own OSPF interface went away (link down, now
            # passive, network removed) tears the adjacency down at once; the
            # neighbour only notices when its dead timer expires.
            local_up = new_links.get((node_name, interface)) == ("up", "up")
            local_hellos = (node_name, interface) in after.get("ospf_active", set())
            reason = (
                "Dead timer expired" if (local_up and local_hellos)
                else "Interface down or detached"
            )
            text = (
                f"%OSPF-5-ADJCHG: Process {process_id}, Nbr {neighbor_id} on {interface} "
                f"from FULL to DOWN, Neighbor Down: {reason}"
            )
        messages.append((node_name, text))
    return messages


def _boot_text(node: NodeState, restored: bool) -> str:
    """Console text of a simulated reload (no vendor legal text)."""
    ethernet = sum(1 for name in node.interfaces if name.startswith("Ethernet"))
    image = "IOL L2 switch" if node.kind == "switch" else "IOL router"
    if node.cli_profile == "vpcs":
        image = "VPCS"
    lines = [
        "",
        "",
        f"Reloading {node.name} ...",
        "",
        f"InstantNodes: booting simulated {image} image ... [OK]",
        f"{ethernet} Ethernet interface{'s' if ethernet != 1 else ''} initialized",
        (
            "Restoring startup-config from nvram ... [OK]"
            if restored
            else "No startup-config found in nvram; using factory defaults"
        ),
        "",
        "",
        "Press RETURN to get started.",
        "",
    ]
    return "\r\n".join(lines)


@dataclass
class SimulationSnapshot:
    runtime_id: str
    slug: str
    yaml_path: str
    generation: int
    status: str
    lab: dict
    nodes: Dict[str, NodeState]
    links: List[Link]
    #: Simulated time the snapshot was taken (graded answers use this clock).
    taken_at: float = 0.0

    def network(self) -> NetworkEngine:
        return NetworkEngine(self.nodes, self.links, now=self.taken_at or None)

    def running_config(self, node_name: str) -> str:
        if node_name not in self.nodes:
            raise NodeNotFound(f"Node '{node_name}' not found")
        return self.nodes[node_name].render_running_config()

    def can_reach(self, node_name: str, target: str) -> bool:
        return self.network().can_reach(node_name, target)

    def as_dict(self) -> dict:
        engine = self.network()
        return {
            "runtime_id": self.runtime_id,
            "slug": self.slug,
            "generation": self.generation,
            "status": self.status,
            "lab": copy.deepcopy(self.lab),
            "nodes": {name: node.as_dict() for name, node in self.nodes.items()},
            "links": [
                {
                    "node_a": a,
                    "interface_a": ai,
                    "node_b": b,
                    "interface_b": bi,
                    "status": engine.link_status((a, ai, b, bi)),
                }
                for a, ai, b, bi in self.links
            ],
        }


class SimulationRuntime:
    """An isolated lab instance shared only by one database session."""

    def __init__(
        self,
        runtime_id: str,
        slug: str,
        yaml_path: str,
        definition: Optional[dict] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.runtime_id = runtime_id
        self.slug = slug
        self.yaml_path = str(Path(yaml_path).resolve())
        self.lock = threading.RLock()
        self.status = "running"
        self.generation = 1
        #: Simulated wall clock (epoch seconds); replace for deterministic runs.
        self.clock: Callable[[], float] = clock if clock is not None else time.time
        #: Bumped on every configuration/topology change (keys the engine cache).
        self.config_version = 0
        #: Bumped when traffic changes the topology (a port-security err-disable
        #: during a ping); keys the engine cache and the link/OSPF syslog diff.
        self.oper_version = 0
        #: connection id -> node name of every attached terminal viewer.
        self.terminals: Dict[str, str] = {}
        #: node name -> persistent console (created on first attach).
        self.consoles: Dict[str, NodeConsole] = {}
        #: Work that must wait until the running console command has finished.
        self._deferred: List[Callable[[], None]] = []
        self._pending_reloads: Set[str] = set()
        #: Operational-state baseline for link/OSPF syslog (see oper_report).
        self._oper_state: Optional[dict] = None
        self._oper_version: object = None
        self._loading = True

        if definition is None:
            with open(self.yaml_path, "r", encoding="utf-8") as handle:
                definition = yaml.safe_load(handle)
        if not isinstance(definition, dict) or not isinstance(definition.get("lab"), dict):
            raise SimulatorError("Lab YAML must contain a 'lab' mapping")
        self.definition = copy.deepcopy(definition)
        self.lab = self.definition["lab"]

        node_definitions = self.lab.get("nodes")
        if not isinstance(node_definitions, list) or not node_definitions:
            raise SimulatorError("Lab YAML must define at least one node")
        self.nodes: Dict[str, NodeState] = {}
        for item in node_definitions:
            if not isinstance(item, dict) or not item.get("name"):
                raise SimulatorError("Every lab node must have a name")
            name = str(item["name"])
            if name in self.nodes:
                raise SimulatorError(f"Duplicate node name '{name}'")
            kind, profile = classify_node(item)
            node = NodeState(
                name=name,
                hostname=name,
                kind=kind,
                cli_profile=profile,
                device_type=str(item.get("device_type", "")),
                node_index=len(self.nodes) + 1,
                boot_time=self.now(),
            )
            node.ensure_default_interfaces()
            node.ensure_default_lines()
            self.nodes[name] = node

        self.links: List[Link] = []
        for raw_link in self.lab.get("links", []) or []:
            if not isinstance(raw_link, (list, tuple)) or len(raw_link) != 4:
                raise SimulatorError(f"Invalid link definition: {raw_link!r}")
            left_name, left_interface, right_name, right_interface = map(str, raw_link)
            if left_name not in self.nodes or right_name not in self.nodes:
                raise SimulatorError(f"Link references an unknown node: {raw_link!r}")
            left_interface = canonical_interface(left_interface)
            right_interface = canonical_interface(right_interface)
            self.nodes[left_name].ensure_interface(left_interface)
            self.nodes[right_name].ensure_interface(right_interface)
            self.links.append(
                (left_name, left_interface, right_name, right_interface)
            )

        # One cached engine bundle per (config_version, whole second): every
        # ctx.engines read inside one command shares a bundle, while time-based
        # output (CDP holdtime, NTP "last update") stays fresh.  The provider
        # holds ``self.nodes`` by reference; reset() updates that dict in place.
        self._engine_provider = EngineProvider(
            self.nodes,
            self.links,
            self.now,
            version_fn=lambda: (self.config_version, self.oper_version, int(self.now())),
            on_build=self._wire_bundle,
        )

        lab_directory = Path(self.yaml_path).parent
        errors: List[str] = []
        for node_name, node in self.nodes.items():
            config_path = lab_directory / "configs" / f"{node_name}-startup.cfg"
            config_text = ""
            if config_path.is_file():
                config_text = config_path.read_text(encoding="utf-8")
                errors.extend(apply_authored_config(self, node_name, config_text))
            node.authored_startup_config = config_text

        self._loading = False
        self.config_version += 1
        self._recompute_dhcp()
        for node in self.nodes.values():
            if node.cli_profile == "ios":
                node.saved_startup_config = node.render_running_config()
            node.config_dirty = False
        if errors:
            raise SimulatorError("Unsupported authored startup command(s): " + "; ".join(errors))
        self._baseline = copy.deepcopy(self.nodes)

    # ------------------------------------------------------------------ #
    # Clock, engines, change tracking                                    #
    # ------------------------------------------------------------------ #
    def now(self) -> float:
        """Current simulated epoch time (``runtime.clock()``)."""
        return float(self.clock())

    def network(self) -> NetworkEngine:
        return NetworkEngine(self.nodes, self.links, now=self.now())

    def engines(self) -> EngineBundle:
        """The current :class:`EngineBundle` (cached per config version + second)."""
        return self._engine_provider.get()

    def _wire_bundle(self, bundle: EngineBundle) -> None:
        """Called for every bundle the runtime builds: report traffic events."""
        bundle.l2.event_sink = self._on_engine_event

    def _on_engine_event(self, kind: str, node_name: str, message: str) -> None:
        """A switch changed state because of traffic (port security)."""
        if kind == "errdisable":
            # Topology changed outside configuration: refresh cached engines and
            # let oper_report log the resulting %LINK/%LINEPROTO changes.
            self.oper_version += 1
        if node_name in self.nodes:
            self.emit_log(node_name, message)

    def mark_changed(self) -> None:
        """Record a configuration change.

        Always bumps :attr:`config_version`; outside authored-config loading it
        also re-runs DHCP for every DHCP-enabled host (automatic retry, see
        :meth:`NetworkEngine.recompute_dhcp`).
        """
        self.config_version += 1
        if not self._loading:
            with self.lock:
                self._recompute_dhcp()

    def _recompute_dhcp(self) -> None:
        self.network().recompute_dhcp()

    # ------------------------------------------------------------------ #
    # Syslog                                                             #
    # ------------------------------------------------------------------ #
    def syslog_line(self, node_name: str, message: str) -> Tuple[str, str]:
        """Return ``(timestamp, rendered_line)`` for ``message`` on a node."""
        node = self.nodes[node_name]
        timestamp = ""
        if node.service_timestamps_log:
            try:
                timestamp = self.engines().services.syslog_timestamp(node, now=self.now())
            except Exception:  # pragma: no cover - defensive (engine bug)
                timestamp = ""
        line = f"{timestamp}: {message}" if timestamp else message
        return timestamp, line

    def emit_log(self, node_name: str, message: str) -> None:
        """Emit a syslog message on ``node_name``.

        The message is timestamped (``service timestamps log``), appended to the
        node's log buffer and delivered to the node's console (``logging
        console``) and to every VTY session open on the node with ``terminal
        monitor``.  Delivery during a running command is deferred by the console
        until that command has finished.
        """
        node = self.nodes.get(node_name)
        if node is None:
            return
        with self.lock:
            timestamp, line = self.syslog_line(node_name, message)
            node.log_buffer.append(
                LogEntry(timestamp=timestamp, message=message, created=self.now())
            )
            if len(node.log_buffer) > LOG_BUFFER_LIMIT:
                del node.log_buffer[: len(node.log_buffer) - LOG_BUFFER_LIMIT]
            self._deliver_log(node_name, line)

    def _deliver_log(self, node_name: str, line: str) -> None:
        node = self.nodes.get(node_name)
        console = self.consoles.get(node_name)
        if node is not None and node.logging_console and console is not None:
            console.deliver_log(line)
        for other in list(self.consoles.values()):
            for frame in other.monitor_frames(node_name):
                other.deliver_log(line, frame)

    # ------------------------------------------------------------------ #
    # Operational-state syslog (M7): link, line protocol, OSPF adjacency  #
    # ------------------------------------------------------------------ #
    def _oper_snapshot(self) -> dict:
        """Interface ``line_state`` and OSPF neighbour state of every IOS node."""
        bundle = self.engines()
        links: Dict[Tuple[str, str], Tuple[str, str]] = {}
        ospf: Dict[Tuple[str, str, str], Tuple[str, Optional[int]]] = {}
        #: (node, interface) running OSPF hellos (enabled and not passive).
        active: Set[Tuple[str, str]] = set()
        for node_name, node in self.nodes.items():
            if node.cli_profile == "vpcs":
                continue
            for interface_name in node.interfaces:
                links[(node_name, interface_name)] = tuple(  # type: ignore[assignment]
                    bundle.l2.line_state(node_name, interface_name)
                )
            if node.ospf_processes:
                processes = {}
                for detail in bundle.ospf.interfaces(node_name):
                    processes[detail.name] = detail.process_id
                    if not detail.passive:
                        active.add((node_name, detail.name))
                for neighbor in bundle.ospf.neighbors(node_name):
                    key = (node_name, neighbor.local_interface, neighbor.neighbor_id)
                    ospf[key] = (neighbor.state, processes.get(neighbor.local_interface))
        return {"links": links, "ospf": ospf, "ospf_active": active}

    def _oper_token(self) -> Tuple[int, int]:
        return (self.config_version, self.oper_version)

    def oper_checkpoint(self) -> None:
        """Before a console command: (silently) refresh the operational baseline
        when something outside a console command changed the configuration."""
        try:
            if self._oper_version != self._oper_token() or self._oper_state is None:
                self._oper_state = self._oper_snapshot()
                self._oper_version = self._oper_token()
        except Exception:  # pragma: no cover - cosmetic feature must never break a command
            self._oper_state = None

    def oper_report(self) -> None:
        """After a console command: log link / line-protocol / OSPF adjacency
        changes it caused (``%LINK``/``%LINEPROTO``/``%OSPF-5-ADJCHG``), whether
        by configuration or by traffic (a port-security err-disable)."""
        try:
            if self._oper_version == self._oper_token():
                return
            before = self._oper_state
            after = self._oper_snapshot()
            self._oper_state = after
            self._oper_version = self._oper_token()
            if before is None:
                return
            for node_name, message in _oper_messages(before, after, self.nodes):
                self.emit_log(node_name, message)
        except Exception:  # pragma: no cover - cosmetic feature must never break a command
            self._oper_state = None

    # ------------------------------------------------------------------ #
    # Deferred work (must not run inside a console's command generator)  #
    # ------------------------------------------------------------------ #
    def _console_busy(self) -> bool:
        return any(console.busy for console in self.consoles.values())

    def _defer(self, action: Callable[[], None]) -> None:
        """Run ``action`` now, or right after the running console command."""
        if self._console_busy():
            self._deferred.append(action)
        else:
            action()

    def _run_deferred(self) -> None:
        while self._deferred:
            action = self._deferred.pop(0)
            action()

    def reload_pending(self, node_name: str) -> bool:
        return node_name in self._pending_reloads

    # ------------------------------------------------------------------ #
    # Startup configuration replay and reload                            #
    # ------------------------------------------------------------------ #
    def _replay_loading(self, node_name: str, config_text: str) -> List[str]:
        """Replay a config loading-style (no per-line DHCP recompute)."""
        previous = self._loading
        self._loading = True
        try:
            return apply_authored_config(self, node_name, config_text)
        finally:
            self._loading = previous

    def merge_config(self, node_name: str, config_text: str) -> List[str]:
        """Merge ``config_text`` into the running config (``copy start run``).

        Returns the rejected lines (``"<node>: <line>: <error>"``)."""
        with self.lock:
            errors = self._replay_loading(node_name, config_text)
            self.config_version += 1
            self._recompute_dhcp()
            return errors

    def request_reload(self, node_name: str) -> None:
        """``reload``: reboot the node once the running command has finished."""
        with self.lock:
            self._pending_reloads.add(node_name)
            self._defer(lambda: self.reload_node(node_name))

    def reload_node(self, node_name: str) -> NodeState:
        """Reboot ``node_name`` from its saved startup-config.

        A new :class:`NodeState` (same name/kind/profile/device type/index,
        ``boot_time`` = now, default inventory, lines and link interfaces)
        replaces the node; ``saved_startup_config`` / ``authored_startup_config``
        carry over and the saved startup-config is replayed (errors ignored).
        Without a startup-config the device boots with factory defaults
        (hostname ``Router``/``Switch``).  Nested sessions into the node are
        closed and the node's own console shows a boot sequence ending in
        ``Press RETURN to get started.``.  Not to be called from inside a
        console command (``reload`` uses :meth:`request_reload`).
        """
        with self.lock:
            self._pending_reloads.discard(node_name)
            old = self.nodes[node_name]
            node = NodeState(
                name=old.name,
                hostname=old.name,
                kind=old.kind,
                cli_profile=old.cli_profile,
                device_type=old.device_type,
                node_index=old.node_index,
                boot_time=self.now(),
            )
            node.boot_reason = "reload"
            node.ensure_default_interfaces()
            node.ensure_default_lines()
            for left_name, left_interface, right_name, right_interface in self.links:
                if left_name == node_name:
                    node.ensure_interface(left_interface)
                if right_name == node_name:
                    node.ensure_interface(right_interface)
            node.saved_startup_config = old.saved_startup_config
            node.authored_startup_config = old.authored_startup_config
            node.startup_saved_at = old.startup_saved_at
            self.nodes[node_name] = node
            startup = old.saved_startup_config or ""
            restored = bool(startup.strip())
            if restored:
                if node.cli_profile == "ios":
                    # A saved configuration loads onto IOS parser defaults, not
                    # onto factory state: the running-config prints `shutdown`
                    # only for shut interfaces and `no ip routing` only when
                    # routing is off, so an interface or routing setting without
                    # such a line comes up enabled.  (Router ports and SVIs
                    # start shut only when the device boots without a
                    # startup-config.)  Interfaces the configuration creates
                    # (SVIs, subinterfaces) are created first for the same reason.
                    for line in startup.splitlines():
                        if line.startswith("interface ") and not line.startswith("interface range"):
                            node.ensure_interface(line.split(None, 1)[1].strip())
                    for interface in node.interfaces.values():
                        interface.shutdown = False
                    if node.kind != "switch":
                        node.ip_routing = True
                self._replay_loading(node_name, startup)
            elif node.cli_profile != "vpcs":
                node.hostname = "Switch" if node.kind == "switch" else "Router"
            node.config_dirty = False
            self.config_version += 1
            self._engine_provider.invalidate()
            self._recompute_dhcp()
            for console in list(self.consoles.values()):
                if console.node_name != node_name:
                    console.close_sessions_into(node_name)
            own = self.consoles.get(node_name)
            if own is not None:
                own.show_boot(_boot_text(node, restored))
            self.emit_log(node_name, "%SYS-5-RESTART: System restarted --")
            return node

    # ------------------------------------------------------------------ #
    # Terminals (persistent consoles + viewers)                          #
    # ------------------------------------------------------------------ #
    def console(self, node_name: str) -> NodeConsole:
        """The persistent console of ``node_name`` (created on demand)."""
        console = self.consoles.get(node_name)
        if console is None:
            console = NodeConsole(self, node_name)
            self.consoles[node_name] = console
        return console

    def attach(
        self, node_name: str, sink: Optional[Callable[[str], None]] = None
    ) -> TerminalAttachment:
        """Attach a viewer to the node's console.

        ``sink`` (optional) receives every later output chunk of the console,
        including output caused by other viewers, syslog and reset notices.
        ``initial_output`` is the console start output on the first attach and
        a short redraw of the current prompt afterwards.
        """
        with self.lock:
            if self.status != "running":
                raise InvalidRuntimeState("Simulator runtime is not running")
            if node_name not in self.nodes:
                raise NodeNotFound(
                    f"Node '{node_name}' not found in simulator runtime '{self.runtime_id}'"
                )
            connection_id = "term-" + uuid.uuid4().hex
            initial_output = self.console(node_name).attach(connection_id, sink)
            self.terminals[connection_id] = node_name
            return TerminalAttachment(
                runtime_id=self.runtime_id,
                connection_id=connection_id,
                node_name=node_name,
                initial_output=initial_output,
            )

    def execute(self, connection_id: str, data: str) -> str:
        with self.lock:
            if self.status != "running":
                raise InvalidRuntimeState("Simulator runtime is not running")
            node_name = self.terminals.get(connection_id)
            console = self.consoles.get(node_name) if node_name is not None else None
            if console is None:
                raise TerminalNotFound(f"Terminal '{connection_id}' is not attached")
            return console.feed(data)

    def detach(self, connection_id: str) -> None:
        with self.lock:
            node_name = self.terminals.pop(connection_id, None)
            console = self.consoles.get(node_name) if node_name is not None else None
            if console is not None:
                console.detach(connection_id)

    def reset(self) -> int:
        with self.lock:
            if self.status != "running":
                raise InvalidRuntimeState("Only a running simulator can be reset")
            restored = copy.deepcopy(self._baseline)
            # Update in place: the engine provider (and anything else holding
            # the dict) keeps seeing the live node set.
            self.nodes.clear()
            self.nodes.update(restored)
            self.generation += 1
            self.config_version += 1
            self._deferred.clear()
            self._pending_reloads.clear()
            self._engine_provider.invalidate()
            self._recompute_dhcp()
            notice = (
                f"\r\n% Simulator reset to authored baseline (generation {self.generation})\r\n"
            )
            for console in list(self.consoles.values()):
                console.rebuild(notice)
            return self.generation

    def stop(self) -> None:
        with self.lock:
            already_stopped = self.status == "stopped"
            self.status = "stopped"
            if not already_stopped:
                for console in list(self.consoles.values()):
                    console.notify_stopped()

    def snapshot(self) -> SimulationSnapshot:
        with self.lock:
            return SimulationSnapshot(
                runtime_id=self.runtime_id,
                slug=self.slug,
                yaml_path=self.yaml_path,
                generation=self.generation,
                status=self.status,
                lab=copy.deepcopy(self.lab),
                nodes=copy.deepcopy(self.nodes),
                links=copy.deepcopy(self.links),
                taken_at=self.now(),
            )

    def status_report(self) -> dict:
        with self.lock:
            if self.status != "running":
                return {
                    "runtime_id": self.runtime_id,
                    "engine": "native",
                    "status": "stopped",
                    "generation": self.generation,
                    "nodes": [],
                    "links": [],
                }
            engine = self.network()
            return {
                "runtime_id": self.runtime_id,
                "gns3_project_id": self.runtime_id,
                "engine": "native",
                "status": "running",
                "generation": self.generation,
                "nodes": [
                    {
                        "name": node.name,
                        "status": "started",
                        "kind": node.kind,
                        "cli_profile": node.cli_profile,
                    }
                    for node in self.nodes.values()
                ],
                "links": [
                    {
                        "node_a": left_name,
                        "interface_a": left_interface,
                        "node_b": right_name,
                        "interface_b": right_interface,
                        "status": engine.link_status(link),
                    }
                    for link in self.links
                    for left_name, left_interface, right_name, right_interface in [link]
                ],
            }

    def apply_config(self, node_name: str, config_text: str) -> None:
        """Apply a config fragment without changing the authored reset baseline.

        The fragment is replayed through the live CLI shells (config_replay)
        without per-line DHCP recomputation; leases are recomputed and mirrored
        once at the end.  Rejected lines raise :class:`SimulatorError` after all
        lines were applied.
        """
        with self.lock:
            if self.status != "running":
                raise InvalidRuntimeState("Simulator runtime is not running")
            if node_name not in self.nodes:
                raise NodeNotFound(f"Node '{node_name}' not found")
            errors = self._replay_loading(node_name, config_text)
            self.config_version += 1
            self._recompute_dhcp()
            if errors:
                raise SimulatorError("Unsupported config command(s): " + "; ".join(errors))
