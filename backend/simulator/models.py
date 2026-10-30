"""Canonical state objects used by the native network simulator."""

from __future__ import annotations

from dataclasses import dataclass, field
import copy
import hashlib
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

from .crypto import verify_credential


CREDENTIAL_DIGEST_TYPE = "8"
LINE_PASSWORD_DIGEST_TYPE = "7"

# Platform identifiers. Routers and IOS-based hosts emulate an IOL L3 image,
# switches an IOL L2 (Catalyst 3560-like) image, and VPCS hosts a VPCS PC.
PLATFORM_ROUTER = "iol-l3"
PLATFORM_SWITCH = "iol-l2"
PLATFORM_VPCS = "vpcs"

ROUTER_ETHERNET_SLOTS = 2
SWITCH_ETHERNET_SLOTS = 4
PORTS_PER_SLOT = 4

PHYSICAL_INTERFACE_PREFIXES = (
    "Ethernet",
    "FastEthernet",
    "GigabitEthernet",
    "Serial",
)


def platform_for(kind: str, cli_profile: str) -> str:
    if cli_profile == "vpcs":
        return PLATFORM_VPCS
    if kind == "switch":
        return PLATFORM_SWITCH
    return PLATFORM_ROUTER


def default_interface_names(platform: str) -> List[str]:
    """Return the fixed interface inventory a freshly booted device owns."""
    if platform == PLATFORM_VPCS:
        return ["Ethernet0/0"]
    slots = SWITCH_ETHERNET_SLOTS if platform == PLATFORM_SWITCH else ROUTER_ETHERNET_SLOTS
    names = [
        f"Ethernet{slot}/{port}"
        for slot in range(slots)
        for port in range(PORTS_PER_SLOT)
    ]
    if platform == PLATFORM_SWITCH:
        names.append("Vlan1")
    return names


def is_physical_interface(name: str) -> bool:
    canonical = canonical_interface(name)
    return canonical.startswith(PHYSICAL_INTERFACE_PREFIXES) and "." not in canonical


def normalise_mac(value: str) -> str:
    """Return a MAC as 12 lowercase hex digits, accepting any common format."""
    digits = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {value!r}")
    return digits.lower()


def format_mac(value: str, style: str = "cisco") -> str:
    """Format a MAC as ``aabb.cc00.0100`` (cisco), colon or dash notation."""
    digits = normalise_mac(value)
    if style == "colon":
        return ":".join(digits[index : index + 2] for index in range(0, 12, 2))
    if style == "dash":
        return "-".join(digits[index : index + 2] for index in range(0, 12, 2))
    return ".".join(digits[index : index + 4] for index in range(0, 12, 4))


def _slot_port(name: str) -> Optional[Tuple[int, int]]:
    match = re.match(r"^[A-Za-z-]+(\d+)/(\d+)$", canonical_interface(name))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def credential_digest(value: str) -> str:
    """Return a deterministic, one-way representation used in public configs."""
    payload = b"NetSimX credential\0" + value.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def canonical_interface(name: str) -> str:
    """Return an IOS-style canonical interface name."""
    value = re.sub(r"\s+", "", str(name).strip())
    lower = value.lower()

    patterns = (
        (r"^(?:e|et|eth|ethernet)(\d+(?:/\d+)*(?:\.\d+)?)$", "Ethernet"),
        (r"^(?:f|fa|fastethernet)(\d+(?:/\d+)*(?:\.\d+)?)$", "FastEthernet"),
        (r"^(?:g|gi|gig|gigabitethernet)(\d+(?:/\d+)*(?:\.\d+)?)$", "GigabitEthernet"),
        (r"^(?:s|se|ser|serial)(\d+(?:/\d+)*(?:\.\d+)?)$", "Serial"),
        (r"^(?:lo|loop|loopback)(\d+)$", "Loopback"),
        (r"^(?:vl|vlan)(\d+)$", "Vlan"),
        (r"^(?:po|port-channel)(\d+)$", "Port-channel"),
        (r"^(?:tu|tunnel)(\d+)$", "Tunnel"),
    )
    for pattern, prefix in patterns:
        match = re.match(pattern, lower)
        if match:
            return prefix + match.group(1)
    return value


def natural_key(value: str) -> Tuple[object, ...]:
    return tuple(int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value))


def interface_parent(name: str) -> Optional[str]:
    canonical = canonical_interface(name)
    if "." not in canonical:
        return None
    return canonical.rsplit(".", 1)[0]


def interface_vlan(name: str) -> Optional[int]:
    canonical = canonical_interface(name)
    match = re.match(r"^Vlan(\d+)$", canonical, re.IGNORECASE)
    return int(match.group(1)) if match else None


@dataclass
class InterfaceCounters:
    """Traffic counters shown by ``show interfaces`` (dynamic state)."""

    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    broadcasts_in: int = 0
    multicasts_in: int = 0
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    collisions: int = 0
    interface_resets: int = 0
    cleared_at: Optional[float] = None


@dataclass
class InterfaceState:
    name: str
    shutdown: bool = True
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    address_source: Optional[str] = None
    encapsulation_vlan: Optional[int] = None
    # Switchport administrative mode: access | trunk | dynamic auto |
    # dynamic desirable. ``None`` means "not a switchport" on routers.
    switchport_mode: Optional[str] = None
    access_vlan: int = 1
    # None = negotiate (default on ISL-capable IOL L2), else dot1q | isl.
    trunk_encapsulation: Optional[str] = None
    channel_group: Optional[int] = None
    # active | passive | on | desirable | auto (non-silent PAgP is implied).
    channel_mode: Optional[str] = None
    configured: bool = False

    # ---- Generic interface configuration ---------------------------------
    description: Optional[str] = None
    # Burned-in address assigned by the runtime (12 lowercase hex digits).
    mac_address: Optional[str] = None
    secondary_addresses: List[Tuple[str, str]] = field(default_factory=list)
    helper_addresses: List[str] = field(default_factory=list)
    bandwidth_kbps: Optional[int] = None
    delay_tens_usec: Optional[int] = None
    mtu: Optional[int] = None
    duplex: str = "auto"
    speed: str = "auto"
    keepalive: Optional[int] = 10
    access_group_in: Optional[str] = None
    access_group_out: Optional[str] = None

    # ---- Interface-level OSPF -------------------------------------------
    ospf_process: Optional[int] = None
    ospf_area: Optional[int] = None
    ospf_cost: Optional[int] = None
    ospf_priority: Optional[int] = None
    ospf_hello_interval: Optional[int] = None
    ospf_dead_interval: Optional[int] = None
    # None = platform default (broadcast on Ethernet), else point-to-point.
    ospf_network_type: Optional[str] = None

    # ---- Switching --------------------------------------------------------
    routed_port: bool = False  # ``no switchport`` on an L2 platform
    trunk_allowed_vlans: Optional[Set[int]] = None  # None = all VLANs
    trunk_native_vlan: int = 1
    nonegotiate: bool = False
    voice_vlan: Optional[int] = None
    encapsulation_native: bool = False  # ``encapsulation dot1Q N native``
    channel_protocol: Optional[str] = None  # lacp | pagp
    stp_portfast: Optional[bool] = None  # None = follow global default
    stp_bpduguard: Optional[bool] = None
    stp_cost: Optional[int] = None
    stp_port_priority: Optional[int] = None
    port_security_enabled: bool = False
    port_security_maximum: int = 1
    port_security_violation: str = "shutdown"
    port_security_sticky: bool = False
    port_security_macs: List[str] = field(default_factory=list)
    #: Addresses learned while ``mac-address sticky`` is on; part of the
    #: running-config (``switchport port-security mac-address sticky H.H.H``).
    port_security_sticky_macs: List[str] = field(default_factory=list)
    #: Port-security frames dropped by restrict/shutdown (protect never counts).
    port_security_violation_count: int = 0
    #: "<mac>:<vlan>" of the last frame source seen on the secure port.
    port_security_last_source: Optional[str] = None
    cdp_enabled: bool = True
    lldp_transmit: bool = True
    lldp_receive: bool = True

    # ---- Dynamic operational state ----------------------------------------
    err_disabled_reason: Optional[str] = None
    counters: InterfaceCounters = field(default_factory=InterfaceCounters)
    last_change: Optional[float] = None
    last_input: Optional[float] = None
    last_output: Optional[float] = None

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        if not self.ip_address or not self.netmask:
            return None
        try:
            return ipaddress.ip_network(f"{self.ip_address}/{self.netmask}", strict=False)
        except ValueError:
            return None


@dataclass
class DHCPBinding:
    """Server-side DHCP binding (dynamic state)."""

    address: str
    client_id: str
    client_node: Optional[str] = None
    leased_at: float = 0.0
    expires_at: Optional[float] = None  # None = infinite lease
    binding_type: str = "Automatic"
    interface: Optional[str] = None


@dataclass
class DHCPClientState:
    """Host-side DHCP client state (dynamic state)."""

    server: Optional[str] = None
    leased_at: Optional[float] = None
    lease_seconds: Optional[int] = None
    dns_servers: List[str] = field(default_factory=list)
    domain_name: Optional[str] = None


@dataclass
class DHCPPool:
    name: str
    network_address: Optional[str] = None
    netmask: Optional[str] = None
    default_router: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    # Legacy view kept for compatibility: client node name -> leased address.
    leases: Dict[str, str] = field(default_factory=dict)
    domain_name: Optional[str] = None
    lease_days: int = 1
    lease_hours: int = 0
    lease_minutes: int = 0
    lease_infinite: bool = False
    # Address -> binding.
    bindings: Dict[str, DHCPBinding] = field(default_factory=dict)
    # Address -> detection time.
    conflicts: Dict[str, float] = field(default_factory=dict)

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        if not self.network_address or not self.netmask:
            return None
        try:
            return ipaddress.ip_network(
                f"{self.network_address}/{self.netmask}", strict=False
            )
        except ValueError:
            return None


@dataclass
class OSPFProcess:
    process_id: int
    networks: List[Tuple[str, str, int]] = field(default_factory=list)
    router_id: Optional[str] = None
    passive_interfaces: Set[str] = field(default_factory=set)
    passive_default: bool = False
    # Interfaces exempted by ``no passive-interface X`` under passive default.
    non_passive_interfaces: Set[str] = field(default_factory=set)
    default_information_originate: bool = False
    default_information_always: bool = False
    reference_bandwidth_mbps: int = 100
    maximum_paths: int = 4
    log_adjacency_changes: bool = True
    log_adjacency_detail: bool = False
    shutdown: bool = False
    distance: int = 110
    # Dynamic: time of the last ``clear ip ospf process``.
    cleared_at: Optional[float] = None


@dataclass
class StaticRoute:
    prefix: str
    mask: str
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    distance: int = 1
    name: Optional[str] = None
    permanent: bool = False
    tag: Optional[int] = None


@dataclass
class ArpEntry:
    address: str
    mac: str
    interface: str
    learned_at: float
    static: bool = False


@dataclass
class MacEntry:
    vlan: int
    mac: str
    port: str
    learned_at: float
    static: bool = False
    #: Port-security address kind: None (ordinary), "dynamic" or "sticky".
    #: Secure addresses show as STATIC and never age (IOS default aging 0).
    secure: Optional[str] = None


@dataclass
class LogEntry:
    """A syslog message retained in the logging buffer."""

    timestamp: str
    message: str
    created: float = 0.0


@dataclass
class NTPServer:
    address: str
    key_id: Optional[int] = None


@dataclass
class LineConfig:
    name: str
    password: Optional[str] = None
    login: bool = False
    login_local: bool = False
    exec_timeout: Optional[Tuple[int, int]] = None
    transport_input: Set[str] = field(default_factory=lambda: {"ssh", "telnet"})
    configured: bool = False
    privilege_level: Optional[int] = None
    logging_synchronous: bool = False
    history_size: int = 10
    transport_output: Optional[Set[str]] = None
    access_class_in: Optional[str] = None
    length: Optional[int] = None
    exec_enabled: bool = True


@dataclass
class NodeState:
    name: str
    kind: str
    cli_profile: str
    device_type: str = ""
    hostname: str = ""
    interfaces: Dict[str, InterfaceState] = field(default_factory=dict)
    vlans: Dict[int, str] = field(default_factory=lambda: {1: "default"})
    dhcp_pools: Dict[str, DHCPPool] = field(default_factory=dict)
    ospf_processes: Dict[int, OSPFProcess] = field(default_factory=dict)
    ntp_master: Optional[int] = None
    ntp_authenticate: bool = False
    ntp_keys: Dict[int, str] = field(default_factory=dict)
    ntp_trusted_keys: Set[int] = field(default_factory=set)
    ntp_servers: Dict[str, NTPServer] = field(default_factory=dict)
    users: Dict[str, str] = field(default_factory=dict)
    lines: Dict[str, LineConfig] = field(default_factory=dict)
    enable_secret: Optional[str] = None
    password_encryption: bool = False
    banner_motd: Optional[str] = None
    domain_name: Optional[str] = None
    rsa_bits: Optional[int] = None
    ssh_version: Optional[int] = None
    default_gateway: Optional[str] = None
    ip_routing: bool = True
    ip_routing_configured: bool = False
    clock_value: str = "00:00:00 1 January 2024"
    timezone_name: str = "UTC"
    timezone_offset: int = 0
    #: Minutes part of ``clock timezone NAME H M`` (takes the sign of the hours).
    timezone_offset_minutes: int = 0
    summer_time_name: Optional[str] = None
    summer_time_recurring: bool = False
    dhcp_enabled: bool = False
    saved_startup_config: str = ""
    authored_startup_config: str = ""

    # ---- Platform / identity ---------------------------------------------
    platform: str = ""
    node_index: int = 0  # 1-based, assigned by the runtime; drives MACs
    boot_time: float = 0.0  # wall-clock epoch of the last (re)boot
    boot_reason: str = "power-on"
    config_register: str = "0x2102"

    # ---- Management / services -------------------------------------------
    static_routes: List[StaticRoute] = field(default_factory=list)
    ip_domain_lookup: bool = True
    name_servers: List[str] = field(default_factory=list)
    ip_hosts: Dict[str, str] = field(default_factory=dict)
    banner_login: Optional[str] = None
    banner_exec: Optional[str] = None
    enable_password: Optional[str] = None
    # Encoded secret loaded from configuration text, e.g. "5 $1$ab$...".
    enable_secret_hash: Optional[str] = None
    user_privilege: Dict[str, int] = field(default_factory=dict)
    user_credential_type: Dict[str, str] = field(default_factory=dict)
    # Encoded user secrets loaded from configuration text (name -> "5 $1$...").
    user_secret_hashes: Dict[str, str] = field(default_factory=dict)
    ip_ssh_timeout: int = 120
    ip_ssh_retries: int = 3
    rsa_generated_at: Optional[float] = None
    cdp_enabled: bool = True
    cdp_timer: int = 60
    cdp_holdtime: int = 180
    lldp_enabled: bool = False
    stp_mode: str = "pvst"
    stp_priorities: Dict[int, int] = field(default_factory=dict)
    stp_portfast_default: bool = False
    stp_bpduguard_default: bool = False
    vtp_mode: str = "server"
    vtp_domain: str = ""
    vtp_version: int = 1
    dhcp_excluded: List[Tuple[str, str]] = field(default_factory=list)
    dhcp_service_enabled: bool = True
    dhcp_client: DHCPClientState = field(default_factory=DHCPClientState)
    host_dns_servers: List[str] = field(default_factory=list)
    logging_console: bool = True
    logging_buffered: Optional[int] = None
    service_timestamps_log: bool = True
    #: ``service timestamps log|debug`` formats: ``uptime`` or ``datetime``
    #: followed by any of ``msec localtime show-timezone year`` in IOS order.
    #: ``datetime`` without ``localtime`` stamps UTC; the IOL default is
    #: ``datetime msec`` for both.
    service_timestamps_log_format: str = "datetime msec"
    service_timestamps_debug: bool = True
    service_timestamps_debug_format: str = "datetime msec"
    #: ``ip http server`` / ``ip http secure-server`` (stored and rendered; no
    #: HTTP service is simulated).
    ip_http_server: bool = False
    ip_http_secure_server: bool = False

    # ---- Clock (see services.py for semantics) ----------------------------
    # Simulated UTC epoch = boot_calendar_epoch + elapsed + clock_offset.
    clock_offset: float = 0.0
    clock_set_at: Optional[float] = None
    clock_source: str = "none"  # none | user | ntp

    # ---- Dynamic tables -----------------------------------------------------
    arp_cache: Dict[str, ArpEntry] = field(default_factory=dict)
    arp_timeout: int = 14400
    mac_table: Dict[Tuple[int, str], MacEntry] = field(default_factory=dict)
    mac_aging_time: int = 300
    log_buffer: List[LogEntry] = field(default_factory=list)
    config_dirty: bool = False
    last_config_change: Optional[float] = None
    last_config_by: str = "console"
    startup_saved_at: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.hostname:
            self.hostname = self.name
        if self.kind != "router":
            self.ip_routing = False
        if not self.platform:
            self.platform = platform_for(self.kind, self.cli_profile)

    def clone(self) -> "NodeState":
        return copy.deepcopy(self)

    # ---- Inventory and addressing -------------------------------------------
    def ensure_default_interfaces(self) -> None:
        """Create the platform's fixed interface inventory."""
        for name in default_interface_names(self.platform):
            self.ensure_interface(name)

    def has_interface(self, name: str) -> bool:
        return canonical_interface(name) in self.interfaces

    def base_mac(self) -> str:
        """Device base MAC (STP bridge address and SVI MAC on switches)."""
        if self.platform == PLATFORM_VPCS:
            return self._vpcs_mac()
        return f"aabbcc80{self.node_index & 0xFF:02x}00"

    def _vpcs_mac(self) -> str:
        return f"0050796668{(max(self.node_index, 1) - 1) & 0xFF:02x}"

    def interface_mac(self, name: str) -> Optional[str]:
        """Burned-in MAC for an interface, or ``None`` when it has none."""
        canonical = canonical_interface(name)
        interface = self.interfaces.get(canonical)
        if interface is not None and interface.mac_address:
            return interface.mac_address
        parent = interface_parent(canonical)
        if parent:
            return self.interface_mac(parent)
        if canonical.startswith(("Loopback", "Tunnel")):
            return None
        if self.platform == PLATFORM_VPCS:
            return self._vpcs_mac()
        if canonical.startswith(("Vlan", "Port-channel")):
            return self.base_mac()
        slot_port = _slot_port(canonical)
        if slot_port is None:
            return self.base_mac()
        slot, port = slot_port
        return f"aabbcc00{self.node_index & 0xFF:02x}{((port & 0xF) << 4) | (slot & 0xF):02x}"

    # ---- Credentials ----------------------------------------------------------
    def has_enable_password(self) -> bool:
        return bool(
            self.enable_secret is not None
            or self.enable_secret_hash
            or self.enable_password is not None
        )

    def verify_enable(self, password: str) -> bool:
        """Check ``password`` against enable secret (preferred) or password."""
        if self.enable_secret is not None or self.enable_secret_hash:
            return verify_credential(
                password, plaintext=self.enable_secret, encoded=self.enable_secret_hash
            )
        if self.enable_password is not None:
            return password == self.enable_password
        return False

    def user_exists(self, username: str) -> bool:
        return username in self.users or username in self.user_secret_hashes

    def verify_user(self, username: str, password: str) -> bool:
        if username in self.users and self.users[username] is not None:
            return self.users[username] == password
        encoded = self.user_secret_hashes.get(username)
        return bool(encoded) and verify_credential(password, encoded=encoded)

    def set_user(
        self,
        username: str,
        credential: Optional[str],
        kind: str = "secret",
        privilege: Optional[int] = None,
        encoded: Optional[str] = None,
    ) -> None:
        """Create/replace a local user from plaintext or an encoded secret."""
        self.users.pop(username, None)
        self.user_secret_hashes.pop(username, None)
        if encoded:
            self.user_secret_hashes[username] = encoded
        else:
            self.users[username] = credential if credential is not None else ""
        self.user_credential_type[username] = kind
        if privilege is not None:
            self.user_privilege[username] = privilege
        else:
            self.user_privilege.pop(username, None)

    def remove_user(self, username: str) -> None:
        for table in (
            self.users,
            self.user_secret_hashes,
            self.user_credential_type,
            self.user_privilege,
        ):
            table.pop(username, None)

    def ensure_interface(self, name: str) -> InterfaceState:
        canonical = canonical_interface(name)
        interface = self.interfaces.get(canonical)
        if interface is not None:
            return interface

        is_switch_port = self.kind == "switch" and not canonical.startswith(("Vlan", "Loopback"))
        # VPCS NICs are always enabled; IOS-based hosts behave like routers.
        is_host_port = self.platform == PLATFORM_VPCS
        shutdown = not (is_switch_port or is_host_port or canonical.startswith("Port-channel"))
        if interface_parent(canonical):
            shutdown = False
        if canonical.startswith("Loopback"):
            # IOS brings a newly created loopback up immediately.
            shutdown = False
        if canonical.startswith("Vlan") and self.kind == "switch":
            # IOS switched virtual interfaces require an explicit ``no shutdown``.
            shutdown = True

        interface = InterfaceState(
            name=canonical,
            shutdown=shutdown,
            switchport_mode="access" if is_switch_port or canonical.startswith("Port-channel") else None,
        )
        self.interfaces[canonical] = interface
        return interface

    def default_interface(self, name: str) -> None:
        canonical = canonical_interface(name)
        self.interfaces.pop(canonical, None)
        self.ensure_interface(canonical)

    def remove_interface(self, name: str) -> None:
        canonical = canonical_interface(name)
        self.interfaces.pop(canonical, None)

    def line(self, name: str) -> LineConfig:
        canonical = re.sub(r"\s+", " ", name.strip().lower())
        canonical = canonical.replace("console", "con")
        line = self.lines.get(canonical)
        if line is None:
            line = LineConfig(canonical)
            if canonical.startswith("vty"):
                # IOS 15.x defaults: VTY lines require a login and accept no
                # inbound transport until one is configured.
                line.login = True
                line.transport_input = set()
            self.lines[canonical] = line
        return line

    def ensure_default_lines(self) -> None:
        """Create the console, aux and VTY lines present on IOS devices."""
        if self.platform == PLATFORM_VPCS:
            return
        console = self.line("con 0")
        console.logging_synchronous = True
        self.line("aux 0")
        self.line("vty 0 4")

    def first_host_interface(self) -> InterfaceState:
        physical = [
            iface
            for iface in self.interfaces.values()
            if not iface.name.startswith(("Vlan", "Loopback", "Port-channel"))
            and interface_parent(iface.name) is None
        ]
        if physical:
            return sorted(physical, key=lambda item: natural_key(item.name))[0]
        return self.ensure_interface("Ethernet0/0")

    def render_running_config(self) -> str:
        # Delegated to the native IOS renderer (agent E).  The renderer produces
        # realistic IOL 15.x output for every node field; see ios/render.py.
        from .ios.render import render_running_config

        return render_running_config(self)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "hostname": self.hostname,
            "kind": self.kind,
            "cli_profile": self.cli_profile,
            "device_type": self.device_type,
            "interfaces": {
                name: {
                    "ip_address": iface.ip_address,
                    "netmask": iface.netmask,
                    "shutdown": iface.shutdown,
                    "encapsulation_vlan": iface.encapsulation_vlan,
                    "switchport_mode": iface.switchport_mode,
                    "access_vlan": iface.access_vlan,
                    "channel_group": iface.channel_group,
                    "channel_mode": iface.channel_mode,
                }
                for name, iface in self.interfaces.items()
            },
            "vlans": dict(self.vlans),
            "dhcp_pools": {
                name: {
                    "network": pool.network_address,
                    "netmask": pool.netmask,
                    "default_router": pool.default_router,
                    "dns_servers": list(pool.dns_servers),
                    "leases": dict(pool.leases),
                }
                for name, pool in self.dhcp_pools.items()
            },
            "ospf_processes": {
                process_id: list(process.networks)
                for process_id, process in self.ospf_processes.items()
            },
            "ntp": {
                "master": self.ntp_master,
                "authenticate": self.ntp_authenticate,
                "keys": dict(self.ntp_keys),
                "trusted_keys": sorted(self.ntp_trusted_keys),
                "servers": {
                    address: server.key_id for address, server in self.ntp_servers.items()
                },
            },
            "users": sorted(self.users),
            "domain_name": self.domain_name,
            "rsa_bits": self.rsa_bits,
            "ssh_version": self.ssh_version,
            "default_gateway": self.default_gateway,
            "ip_routing": self.ip_routing,
            "running_config": self.render_running_config(),
            "startup_config": self.saved_startup_config,
        }
