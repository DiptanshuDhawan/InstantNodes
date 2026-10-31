"""VPCS-compatible command shell (Phase 2, A3).

:class:`VpcsShell` implements :class:`simulator.ios.protocol.ShellProtocol`, so the
same :class:`~simulator.ios.terminal.TerminalSession` line discipline (echo,
editing, history, ``?``/Tab) drives VPCS hosts and IOS devices alike.

Commands follow VPCS syntax: ``ip`` (static forms and ``dhcp [-r|-x]``), ``show
[ip|arp|history|version]``, ``ping HOST [-c N]``, ``trace HOST [-m N]``, ``arp``,
``clear ip|arp|hist``, ``save``/``load``, ``set pcname``, ``history``,
``version`` and ``?``.  Unique prefixes are accepted.

State rules
-----------
* Address changes write the host's first interface and call
  ``runtime.mark_changed()``.
* ``ip dhcp`` clears the address, resets the host's DHCP client state and calls
  ``runtime.mark_changed()``, which re-leases every DHCP-enabled host through
  ``ServicesEngine.dhcp_request`` (the simulator's automatic DHCP retry, see
  ``NetworkEngine.recompute_dhcp``); the shell then reads the interface back.
  Leases are sticky: a host keeps its address, and the reset client state makes
  the server restart this host's lease from now.  New clients start at the
  pool's tenth host address (``test_slash_zero_dhcp_allocation_is_lazy_and_bounded``).
* ``ping``/``trace``/``arp`` read the Phase 1 engines through
  ``engine_provider`` (installed by the runtime) or, failing that, a bundle
  built from ``runtime.nodes``/``runtime.links``.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Callable, Dict, List, Optional, Tuple

from ..ios.protocol import Sleep
from ..models import DHCPClientState, NodeState, format_mac, normalise_mac

__all__ = ["VpcsShell", "WELCOME_TEXT"]

#: Printed once when a console first starts on a VPCS host.
WELCOME_TEXT = (
    "\n"
    "VPCS-compatible virtual PC (InstantNodes native simulator)\n"
    "Press '?' to get help.\n"
)

_VERSION_TEXT = (
    "InstantNodes VPCS-compatible virtual PC\n"
    "Command syntax follows VPCS 0.8 (ip, ping, trace, arp, save, load, show)."
)

_HELP_ROWS = (
    ("?", "Print help"),
    ("arp", "Show the ARP table (same as: show arp)"),
    ("clear ip|arp|hist", "Clear the IP settings, ARP table or command history"),
    ("history", "List the command history (same as: show history)"),
    ("ip ARG ... [OPTION]", "Configure IP settings; enter 'ip ?' for details"),
    ("load [FILENAME]", "Run the saved startup script"),
    ("ping HOST [-c COUNT]", "Send ICMP echo requests to HOST"),
    ("save [FILENAME]", "Save the current settings as the startup script"),
    ("set pcname NAME", "Set the host name shown in the prompt"),
    ("show [ip|arp|history|version]", "Display host information"),
    ("trace HOST [-m TTL]", "Print the route packets take to HOST"),
    ("version", "Show the simulator version (same as: show version)"),
)

_IP_USAGE = (
    "ip ARG ... [OPTION]\n"
    "  Configure the IP settings of this host\n"
    "  ARG:\n"
    "    ADDRESS[/LEN] [GATEWAY]   static address, e.g. ip 10.1.1.70/24 10.1.1.65\n"
    "    ADDRESS MASK [GATEWAY]    static address, e.g. ip 10.1.1.70 255.255.255.0 10.1.1.65\n"
    "    ADDRESS GATEWAY LEN       static address, e.g. ip 10.1.1.70 10.1.1.65 24\n"
    "    dhcp [-r|-x]              get an address by DHCP; -r renew, -x release\n"
    "    dns ADDRESS               set the DNS server\n"
)

_SHOW_USAGE = "show [arp|ip|history|version]\n  Display host information\n"
_PING_USAGE = "ping HOST [-c COUNT]\n  Send ICMP echo requests to HOST (default 5)\n"
_TRACE_USAGE = "trace HOST [-m TTL]\n  Print the route packets take to HOST (default 8 hops)\n"
_CLEAR_USAGE = "clear ip|arp|hist\n  Clear the IP settings, ARP table or command history\n"
_SET_USAGE = "set pcname NAME\n  Set the host name shown in the prompt\n"

#: VPCS keeps learned ARP entries for two minutes.
_ARP_LIFETIME = 120
_DEFAULT_TRACE_TTL = 8
_STARTUP_FILE = "startup.vpc"


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _mask_from_length(length: int) -> Optional[str]:
    if not 0 <= length <= 32:
        return None
    return str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)


def _is_netmask(value: str) -> bool:
    """True only for a contiguous dotted netmask (``0.0.0.255`` is rejected)."""
    if not _is_ipv4(value):
        return False
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{value}").netmask) == value
    except ValueError:
        return False


def _prefix_length(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


class VpcsShell:
    """A VPCS command interpreter bound to one host :class:`NodeState`."""

    def __init__(self, node: NodeState, runtime: object = None, terminal: object = None) -> None:
        self.node = node
        self.runtime = runtime
        #: Set by :class:`~simulator.ios.terminal.TerminalSession`.
        self.terminal = terminal
        #: Zero-arg callable returning an :class:`~simulator.engines.EngineBundle`.
        self.engine_provider: Optional[Callable[[], object]] = None
        self._commands: Dict[str, Callable] = {
            "?": self._cmd_help,
            "help": self._cmd_help,
            "arp": self._cmd_arp,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "ip": self._cmd_ip,
            "load": self._cmd_load,
            "ping": self._cmd_ping,
            "save": self._cmd_save,
            "set": self._cmd_set,
            "show": self._cmd_show,
            "trace": self._cmd_trace,
            "version": self._cmd_version,
        }

    # ------------------------------------------------------------------ #
    # ShellProtocol                                                      #
    # ------------------------------------------------------------------ #
    def prompt(self) -> str:
        return f"{self.node.hostname}> "

    @staticmethod
    def welcome_text() -> str:
        return WELCOME_TEXT

    @property
    def terminal_length(self) -> int:
        return 0

    @property
    def history_size(self) -> int:
        return 20

    @property
    def logging_synchronous(self) -> bool:
        return False

    @property
    def closed(self) -> bool:
        return False

    def run(self, line: str):
        text = line.strip()
        if not text or text.startswith("#"):
            return
        words = text.split()
        handler = self._resolve(words[0])
        if handler is None:
            yield f'Bad command: "{text}". Use ? for help.'
            return
        result = handler(words[1:])
        if result is None:
            return
        if isinstance(result, str):
            if result:
                yield result
            return
        yield from result

    def interrupt(self, key: str):
        return
        yield  # pragma: no cover - makes this a generator

    def help_text(self, buffer: str) -> str:
        words = buffer.split()
        if words:
            name = self._resolve_name(words[0])
            usage = {
                "ip": _IP_USAGE,
                "show": _SHOW_USAGE,
                "ping": _PING_USAGE,
                "trace": _TRACE_USAGE,
                "clear": _CLEAR_USAGE,
                "set": _SET_USAGE,
            }.get(name or "")
            if usage:
                return usage
        width = max(len(name) for name, _ in _HELP_ROWS) + 2
        return "\n".join(f"{name:<{width}}{text}" for name, text in _HELP_ROWS) + "\n"

    def complete(self, buffer: str) -> Optional[str]:
        if " " not in buffer:
            matches = [name for name in self._commands if name != "?" and name.startswith(buffer.lower())]
            if len(matches) == 1:
                return matches[0] + " "
            return None
        head, _, rest = buffer.partition(" ")
        if self._resolve_name(head) == "show" and " " not in rest.strip():
            options = [opt for opt in ("arp", "history", "ip", "version") if opt.startswith(rest.strip().lower())]
            if len(options) == 1:
                return f"{head} {options[0]} "
        return None

    # ------------------------------------------------------------------ #
    # Helpers                                                            #
    # ------------------------------------------------------------------ #
    def _resolve_name(self, word: str) -> Optional[str]:
        word = word.lower()
        if word in self._commands:
            return word
        matches = [name for name in self._commands if name.startswith(word) and name not in ("?", "help")]
        return matches[0] if len(matches) == 1 else None

    def _resolve(self, word: str) -> Optional[Callable]:
        name = self._resolve_name(word)
        return self._commands.get(name) if name else None

    def _now(self) -> float:
        runtime = self.runtime
        if runtime is not None and hasattr(runtime, "now"):
            try:
                return float(runtime.now())
            except Exception:
                pass
        return time.time()

    def _changed(self) -> None:
        self.node.config_dirty = True
        runtime = self.runtime
        if runtime is not None and hasattr(runtime, "mark_changed"):
            runtime.mark_changed()

    def _engines(self):
        if self.engine_provider is not None:
            try:
                return self.engine_provider()
            except Exception:
                return None
        runtime = self.runtime
        if runtime is None:
            return None
        provider = getattr(runtime, "engines", None)
        if callable(provider):
            return provider()
        nodes = getattr(runtime, "nodes", None)
        links = getattr(runtime, "links", None)
        if nodes is None or links is None:
            return None
        from ..engines import build_bundle

        return build_bundle(nodes, links, self._now())

    def _interface(self):
        return self.node.first_host_interface()

    # ------------------------------------------------------------------ #
    # ip                                                                 #
    # ------------------------------------------------------------------ #
    def _cmd_ip(self, args: List[str]):
        if not args or args[0] == "?":
            return _IP_USAGE.rstrip("\n")
        sub = args[0].lower()
        if sub == "dhcp":
            return self._ip_dhcp([arg.lower() for arg in args[1:]])
        if sub == "dns":
            if len(args) < 2 or not _is_ipv4(args[1]):
                return "Invalid address"
            self.node.name_servers = [args[1]]
            self._changed()
            return None
        if sub == "static":  # accepted for compatibility with older lab scripts
            args = args[1:]
            if not args:
                return _IP_USAGE.rstrip("\n")
        return self._ip_static(args)

    def _parse_static(self, args: List[str]) -> Tuple[Optional[Tuple[str, str, Optional[str]]], str]:
        first, rest = args[0], args[1:]
        gateway: Optional[str] = None
        if "/" in first:
            address, _, length = first.partition("/")
            if not length.isdigit() or _mask_from_length(int(length)) is None:
                return None, "Invalid netmask"
            mask = _mask_from_length(int(length))
            if rest:
                gateway = rest[0]
        else:
            address = first
            mask = _mask_from_length(24)
            if len(rest) == 1:
                token = rest[0]
                if token.isdigit():
                    mask = _mask_from_length(int(token))
                    if mask is None:
                        return None, "Invalid netmask"
                elif _is_netmask(token):
                    mask = token
                elif _is_ipv4(token):
                    gateway = token
                else:
                    return None, "Invalid netmask"
            elif len(rest) >= 2:
                left, right = rest[0], rest[1]
                if _is_netmask(left):
                    mask, gateway = left, right
                elif _is_ipv4(left) and right.isdigit() and _mask_from_length(int(right)):
                    gateway, mask = left, _mask_from_length(int(right))
                else:
                    return None, "Invalid netmask"
        if not _is_ipv4(address) or address in ("0.0.0.0", "255.255.255.255"):
            return None, "Invalid address"
        if ipaddress.IPv4Address(address).is_multicast:
            return None, "Invalid address"
        if gateway is not None and not _is_ipv4(gateway):
            return None, "Invalid gateway"
        return (address, mask, gateway), ""

    def _ip_static(self, args: List[str]) -> str:
        parsed, error = self._parse_static(args)
        if parsed is None:
            return error
        address, mask, gateway = parsed
        node = self.node
        interface = self._interface()
        interface.ip_address = address
        interface.netmask = mask
        interface.address_source = "static"
        interface.shutdown = False
        interface.configured = True
        node.default_gateway = gateway
        node.dhcp_enabled = False
        self._changed()
        suffix = f" gateway {gateway}" if gateway else ""
        return f"{node.hostname} : {address} {mask}{suffix}"

    def _ip_dhcp(self, options: List[str]) -> str:
        node = self.node
        interface = self._interface()
        if "-x" in options:
            had = (interface.ip_address, interface.netmask) if interface.address_source == "dhcp" else None
            gateway = node.default_gateway
            node.dhcp_enabled = False
            node.dhcp_client = DHCPClientState()
            if had is not None:
                interface.ip_address = None
                interface.netmask = None
                interface.address_source = None
                node.default_gateway = None
            self._changed()
            if had is None or not had[0]:
                return "No DHCP lease to release"
            suffix = f" GW {gateway}" if gateway else ""
            return f"IP {had[0]}/{had[1]}{suffix} released"
        # Request / renew: the runtime re-leases every DHCP host (automatic retry).
        # A fresh client state marks a new DORA, so the server renews this
        # host's lease from now (``NetworkEngine.recompute_dhcp``).
        node.dhcp_enabled = True
        node.dhcp_client = DHCPClientState()
        interface.ip_address = None
        interface.netmask = None
        interface.address_source = None
        interface.configured = True
        self._changed()
        if interface.ip_address:
            gateway = node.default_gateway
            suffix = f" GW {gateway}" if gateway else ""
            return f"DDORA IP {interface.ip_address}/{interface.netmask}{suffix}"
        return "DHCP request sent; no offer yet (automatic retry enabled)."

    # ------------------------------------------------------------------ #
    # show / arp / history / version / help                              #
    # ------------------------------------------------------------------ #
    def _cmd_show(self, args: List[str]):
        if not args:
            return self._show_ip()
        option = args[0].lower()
        for name, handler in (
            ("ip", self._show_ip),
            ("arp", self._show_arp),
            ("history", self._show_history),
            ("version", lambda: _VERSION_TEXT),
        ):
            if name.startswith(option):
                return handler()
        return _SHOW_USAGE.rstrip("\n")

    def _show_ip(self) -> str:
        node = self.node
        interface = self._interface()
        if interface.ip_address and interface.netmask:
            ip_mask = f"{interface.ip_address}/{_prefix_length(interface.netmask)}"
        else:
            ip_mask = "0.0.0.0/0"
        mac = node.interface_mac(interface.name)
        dhcp = interface.address_source == "dhcp"
        client = node.dhcp_client if dhcp else None
        dns = list(node.name_servers)
        if client is not None and client.dns_servers:
            dns = list(client.dns_servers)  # option 6 from the DHCP server
        rows = [
            ("NAME", f"{node.hostname}[1]"),
            ("IP/MASK", ip_mask),
            ("GATEWAY", node.default_gateway or "0.0.0.0"),
            ("DNS", " ".join(dns)),
        ]
        if dhcp:
            server = (client.server if client is not None else None) or node.default_gateway
            if server:
                rows.append(("DHCP SERVER", server))
            lease = client.lease_seconds if client is not None else None
            if lease and client.leased_at is not None:
                remaining = max(0, int(lease - (self._now() - client.leased_at)))
                rows.append(("DHCP LEASE", f"{remaining}, {lease}/{lease // 2}/{lease * 7 // 8}"))
        rows.append(("MAC", format_mac(normalise_mac(mac), "colon") if mac else ""))
        rows.append(("MTU", str(interface.mtu or 1500)))
        return "\n".join(f"{label:<12}: {value}".rstrip() if not value else f"{label:<12}: {value}" for label, value in rows)

    def _show_arp(self) -> str:
        now = self._now()
        rows = []
        for entry in sorted(self.node.arp_cache.values(), key=lambda item: ipaddress.IPv4Address(item.address)):
            remaining = _ARP_LIFETIME - int(now - entry.learned_at)
            if remaining <= 0 and not entry.static:
                continue
            mac = format_mac(normalise_mac(entry.mac), "colon")
            rows.append(f"{mac}  {entry.address} expires in {max(remaining, 1)} seconds")
        return "\n".join(rows) if rows else "arp table is empty"

    def _cmd_arp(self, args: List[str]) -> str:
        return self._show_arp()

    def _show_history(self) -> Optional[str]:
        terminal = self.terminal
        items = list(getattr(terminal, "history", []) or [])
        return "\n".join(items) if items else None

    def _cmd_history(self, args: List[str]):
        return self._show_history()

    def _cmd_version(self, args: List[str]) -> str:
        return _VERSION_TEXT

    def _cmd_help(self, args: List[str]) -> str:
        return self.help_text(" ".join(args)).rstrip("\n")

    # ------------------------------------------------------------------ #
    # clear / set / save / load                                          #
    # ------------------------------------------------------------------ #
    def _cmd_clear(self, args: List[str]):
        target = args[0].lower() if args else "ip"
        node = self.node
        if "ip".startswith(target):
            interface = self._interface()
            interface.ip_address = None
            interface.netmask = None
            interface.address_source = None
            node.default_gateway = None
            node.dhcp_enabled = False
            self._changed()
            return None
        if "arp".startswith(target):
            node.arp_cache.clear()
            return None
        if "hist".startswith(target) or "history".startswith(target):
            terminal = self.terminal
            if terminal is not None and hasattr(terminal, "set_history_size"):
                size = self.history_size
                terminal.set_history_size(0)
                terminal.set_history_size(size)
            return None
        return _CLEAR_USAGE.rstrip("\n")

    def _cmd_set(self, args: List[str]) -> Optional[str]:
        if len(args) >= 2 and "pcname".startswith(args[0].lower()):
            self.node.hostname = args[1]
            self._changed()
            return None
        return _SET_USAGE.rstrip("\n")

    def _cmd_save(self, args: List[str]) -> str:
        from ..ios.render import render_vpcs_config

        filename = args[0] if args else _STARTUP_FILE
        self.node.saved_startup_config = render_vpcs_config(self.node)
        return f"Saving startup configuration to {filename}\n.  done"

    def _cmd_load(self, args: List[str]):
        filename = args[0] if args else _STARTUP_FILE
        script = self.node.saved_startup_config or ""
        if not script.strip():
            yield f"Can't open file {filename}"
            return
        yield f'Executing the file "{filename}"\n'
        for raw in script.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            for item in self.run(line):
                if isinstance(item, str):
                    yield item if item.endswith("\n") else item + "\n"

    # ------------------------------------------------------------------ #
    # ping / trace                                                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _option(args: List[str], flag: str, default: int, low: int, high: int) -> Optional[int]:
        if flag not in args:
            return default
        index = args.index(flag)
        if index + 1 >= len(args) or not args[index + 1].isdigit():
            return None
        value = int(args[index + 1])
        return value if low <= value <= high else None

    def _cmd_ping(self, args: List[str]):
        if not args or args[0] == "?":
            yield _PING_USAGE.rstrip("\n")
            return
        host = args[0]
        count = self._option(args[1:], "-c", 5, 1, 1000)
        if count is None:
            yield _PING_USAGE.rstrip("\n")
            return
        if not _is_ipv4(host):
            yield f"Cannot resolve {host}"
            return
        interface = self._interface()
        bundle = self._engines()
        if bundle is None or not interface.ip_address:
            yield f"host ({host}) not reachable"
            return
        now = self._now()
        result = bundle.l3.ping(self.node.name, host, repeat=count, now=now)
        forward = bundle.l3.forward(self.node.name, host)
        responder = bundle.nodes.get(forward.responder) if forward.responder else None
        base_ttl = 64 if responder is not None and responder.cli_profile == "vpcs" else 255
        ttl = max(1, base_ttl - max(0, len(forward.path) - 1))
        for sequence, probe in enumerate(result.probes, 1):
            if probe == "U":
                yield f"host ({host}) not reachable"
                return
            if probe == "!":
                yield f"84 bytes from {host} icmp_seq={sequence} ttl={ttl} time={result.rtt_avg:.3f} ms\n"
            else:
                yield f"{host} icmp_seq={sequence} timeout\n"
            if sequence < len(result.probes):
                yield Sleep(1.0)

    def _cmd_trace(self, args: List[str]):
        if not args or args[0] == "?":
            yield _TRACE_USAGE.rstrip("\n")
            return
        host = args[0]
        max_ttl = self._option(args[1:], "-m", _DEFAULT_TRACE_TTL, 1, 64)
        if max_ttl is None:
            yield _TRACE_USAGE.rstrip("\n")
            return
        if not _is_ipv4(host):
            yield f"Cannot resolve {host}"
            return
        bundle = self._engines()
        if bundle is None or not self._interface().ip_address:
            yield f"host ({host}) not reachable"
            return
        result = bundle.l3.traceroute(self.node.name, host, max_ttl=max_ttl, probes=3, now=self._now())
        yield f"trace to {host}, {max_ttl} hops max, press Ctrl+C to stop\n"
        for hop in result.hops:
            answered = [probe for probe in hop.probes if probe.address]
            if not answered:
                yield f"{hop.ttl:>2}   *  *  *\n"
                continue
            address = answered[0].address
            rtts = [probe.rtt for probe in answered if probe.rtt is not None]
            if hop.done and (result.reached or hop.status in ("host-unreachable", "unreachable")):
                reason = {
                    "host-unreachable": "ICMP type:3, code:1, Destination host unreachable",
                    "unreachable": "ICMP type:3, code:0, Destination network unreachable",
                }.get(hop.status, "ICMP type:3, code:3, Destination port unreachable")
                first = f"{rtts[0]:.3f} ms " if rtts else ""
                yield f"{hop.ttl:>2}   *{address}   {first}({reason})\n"
                return
            times = "  ".join(f"{rtt:.3f} ms" for rtt in rtts)
            yield f"{hop.ttl:>2}   {address}   {times}\n"
            yield Sleep(0.5)
