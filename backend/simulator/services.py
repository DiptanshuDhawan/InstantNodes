"""Stateful device services for the native simulator (Agent D, Phase 1).

``ServicesEngine`` computes clock / NTP / DHCP / CDP-LLDP / remote-access
behaviour from canonical :class:`~simulator.models.NodeState` objects.  It is a
pure, deterministic engine: it never prints, never sleeps and never reads the
wall clock.  Every time-dependent method takes ``now`` (epoch seconds); callers
pass ``runtime.now()``.  For tests, use ``now = node.boot_time + uptime``.

The engine is decoupled from the other protocol engines through the shared
:class:`~simulator.adapters.NetworkCallbacks` bundle (``segment_of``,
``line_protocol_up``, ``find_ip``, ``reachable``).  Build one for tests with
``simulator.adapters.legacy_callbacks(nodes, links)``.

Results are returned as small dataclasses (defined below); rendering to IOS/VPCS
text is the job of the Phase 2 command modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import ipaddress
import re
from typing import Dict, Hashable, Iterable, List, Optional, Tuple, Union

from .adapters import NetworkCallbacks, Link
from .models import (
    DHCPBinding,
    DHCPClientState,
    DHCPPool,
    NodeState,
    canonical_interface,
    format_mac,
    interface_vlan,
    natural_key,
    normalise_mac,
)

__all__ = [
    "ServicesEngine",
    "NodeClock",
    "NtpStatus",
    "NtpAssociation",
    "DhcpResult",
    "DhcpBindingRow",
    "DhcpPoolStats",
    "DhcpConflictRow",
    "CdpNeighbor",
    "CdpGlobals",
    "LldpNeighbor",
    "VtyDecision",
    "SshServerInfo",
]


# ---------------------------------------------------------------------------
# Calendar constants and helpers
# ---------------------------------------------------------------------------

#: Naive Unix epoch used as the arithmetic base for all datetime<->epoch maths.
_UNIX_EPOCH = datetime(1970, 1, 1)
#: IOS boots with its calendar at 1993-03-01 00:00:00 UTC (no hardware calendar).
_BOOT_CALENDAR = datetime(1993, 3, 1, 0, 0, 0)
_BOOT_CALENDAR_EPOCH = (_BOOT_CALENDAR - _UNIX_EPOCH).total_seconds()
#: Seconds between the NTP era (1900) and the Unix era (1970).
_NTP_UNIX_DELTA = 2208988800

_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]  # datetime.weekday(): Mon=0
_MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_MONTH_FULL = ["", "January", "February", "March", "April", "May", "June",
               "July", "August", "September", "October", "November", "December"]

_NOMINAL_FREQ = 250.0000
_SECONDS_PER_MINUTE = 60


def _to_epoch(moment: datetime) -> float:
    return (moment - _UNIX_EPOCH).total_seconds()


def _from_epoch(seconds: float) -> datetime:
    return _UNIX_EPOCH + timedelta(seconds=seconds)


def _month_number(name: str) -> int:
    """Resolve a full or abbreviated month name (case-insensitive) to 1..12."""
    token = str(name).strip().lower()[:3]
    for index in range(1, 13):
        if _MONTHS[index].lower() == token:
            return index
    raise ValueError(f"Invalid month name: {name!r}")


def _ip_sort_key(address: str) -> Tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(address).split("."))
    except ValueError:
        return (0,)


def _nth_weekday_day(year: int, month: int, weekday: int, occurrence: int) -> int:
    """Day-of-month of the ``occurrence``-th ``weekday`` (Mon=0..Sun=6)."""
    first = datetime(year, month, 1)
    shift = (weekday - first.weekday()) % 7
    return 1 + shift + (occurrence - 1) * 7


_SUNDAY = 6


def _dst_bounds_utc(year: int, std_offset_seconds: int) -> Tuple[datetime, datetime]:
    """US DST window expressed as absolute UTC instants.

    Starts 2nd Sunday of March 02:00 local *standard* time, ends 1st Sunday of
    November 02:00 local *daylight* time (== 01:00 standard).
    """
    spring_local = datetime(year, 3, _nth_weekday_day(year, 3, _SUNDAY, 2), 2, 0, 0)
    spring_utc = spring_local - timedelta(seconds=std_offset_seconds)
    fall_local = datetime(year, 11, _nth_weekday_day(year, 11, _SUNDAY, 1), 2, 0, 0)
    fall_utc = fall_local - timedelta(seconds=std_offset_seconds + 3600)
    return spring_utc, fall_utc


_IFSHORT = (
    ("GigabitEthernet", "Gig"),
    ("FastEthernet", "Fas"),
    ("Ethernet", "Eth"),
    ("Serial", "Ser"),
    ("Loopback", "Lo"),
    ("Port-channel", "Po"),
    ("Tunnel", "Tu"),
    ("Vlan", "Vl"),
)


def _short_ifname(name: str) -> str:
    """``Ethernet0/0`` -> ``Eth 0/0`` (CDP/LLDP local-interface style)."""
    canonical = canonical_interface(name)
    for prefix, short in _IFSHORT:
        if canonical.startswith(prefix):
            return f"{short} {canonical[len(prefix):]}"
    return canonical


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class NodeClock:
    """Resolved simulated clock for a node."""

    utc: datetime
    local: datetime
    zone_name: str
    offset_seconds: int
    dst_active: bool
    authoritative: bool
    marker: str            # "" | "." | "*"
    source: str            # "ntp" | "user" | "none"
    synchronized: bool
    stratum: int
    reference: Optional[str]


@dataclass
class NtpStatus:
    synchronized: bool
    stratum: int
    reference: str
    nominal_freq: float = _NOMINAL_FREQ
    actual_freq: float = _NOMINAL_FREQ
    precision: str = "2**10"
    reference_time_hex: str = "00000000.00000000"
    reference_time_text: str = ""
    clock_offset_ms: float = 0.0
    root_delay_ms: float = 0.0
    root_dispersion_ms: float = 0.0
    peer_dispersion_ms: float = 0.0
    loopfilter_state: str = "'FREERUN'"
    system_poll_interval: int = 64
    last_update: str = "never"
    ntp_uptime_cs: int = 0
    resolution: int = 4000
    drift_ppm: float = 0.0


@dataclass
class NtpAssociation:
    marker: str            # "*" sys.peer, "+" candidate, "~" configured, " "
    address: str
    ref_clock: str
    stratum: int
    when: int
    poll: int
    reach: int
    delay_ms: float
    offset_ms: float
    dispersion_ms: float
    configured: bool = True
    authenticated: bool = False
    sane: bool = True
    valid: bool = True
    ref_id: str = ""


@dataclass
class DhcpResult:
    success: bool
    steps: str
    code: str = "ok"
    reason: str = ""
    address: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    server: Optional[str] = None
    domain: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    lease_seconds: Optional[int] = None
    client_id: Optional[str] = None
    pool_name: Optional[str] = None
    server_node: Optional[str] = None
    relay: bool = False
    giaddr: Optional[str] = None
    interface: Optional[str] = None


@dataclass
class DhcpBindingRow:
    ip: str
    client_id: str
    lease_expiration: str
    type: str
    state: str
    interface: str


@dataclass
class DhcpPoolStats:
    pool_name: str
    network: str
    netmask: str
    subnet_size: int
    total: int
    leased: int
    excluded: int
    available: int
    pending: int
    utilization: int
    current_index: Optional[str]
    first_address: Optional[str]
    last_address: Optional[str]


@dataclass
class DhcpConflictRow:
    address: str
    detection_time: str
    detection_method: str


@dataclass
class CdpNeighbor:
    device_id: str
    local_interface: str
    local_interface_short: str
    holdtime: int
    capabilities: str
    platform: str
    port_id: str
    port_id_short: str
    mgmt_addresses: List[str] = field(default_factory=list)
    interface_addresses: List[str] = field(default_factory=list)
    version: str = ""
    native_vlan: Optional[int] = None
    duplex: str = "full"
    advertisement_version: int = 2


@dataclass
class CdpGlobals:
    enabled: bool
    timer: int
    holdtime: int
    advertise_v2: bool = True


@dataclass
class LldpNeighbor:
    system_name: str
    local_interface: str
    local_interface_short: str
    hold_time: int
    capabilities: str
    port_id: str
    port_description: str = ""
    mgmt_addresses: List[str] = field(default_factory=list)


@dataclass
class VtyDecision:
    allowed: bool
    message: str
    code: str              # ok | timeout | refused | no_password | no_server
    transport: str
    target_node: Optional[str] = None
    target_address: Optional[str] = None
    target_line: Optional[str] = None
    login_mode: str = "none"   # none | line | local
    requires_username: bool = False
    requires_password: bool = False


@dataclass
class SshServerInfo:
    enabled: bool
    version_text: str
    version: str
    auth_timeout: int
    retries: int
    modulus: Optional[int]


# Internal NTP resolution record.
@dataclass
class _NtpSync:
    synchronized: bool
    stratum: int
    reference: str
    root: Optional[str]
    via: Optional[str] = None
    server_address: Optional[str] = None
    reason: str = ""


NodeRef = Union[NodeState, str]


class ServicesEngine:
    """Deterministic clock / NTP / DHCP / discovery / remote-access engine."""

    DHCP_CANDIDATE_PROBE_LIMIT = 4096

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

    # -- small helpers ------------------------------------------------------
    def _node(self, ref: NodeRef) -> NodeState:
        if isinstance(ref, NodeState):
            return ref
        return self.nodes[ref]

    @staticmethod
    def _name(ref: NodeRef) -> str:
        return ref.name if isinstance(ref, NodeState) else ref

    def _resolve_now(self, now: Optional[float]) -> float:
        return self.now if now is None else float(now)

    # ======================================================================
    # 1. CLOCK
    # ======================================================================
    def _uptime_seconds(self, node: NodeState, now: float) -> float:
        return max(0.0, now - (node.boot_time or 0.0))

    def _free_running_epoch(self, node: NodeState, now: float) -> float:
        """Node's own free-running UTC epoch (boot calendar + uptime + offset)."""
        return _BOOT_CALENDAR_EPOCH + self._uptime_seconds(node, now) + node.clock_offset

    def _std_offset_seconds(self, node: NodeState) -> int:
        """Standard-time UTC offset; ``clock timezone NST -3 30`` is -3:30."""
        hours = int(node.timezone_offset)
        minutes = int(getattr(node, "timezone_offset_minutes", 0) or 0)
        sign = -1 if hours < 0 else 1
        return hours * 3600 + sign * minutes * 60

    def _dst_active(self, node: NodeState, utc: datetime) -> bool:
        if not node.summer_time_recurring and not node.summer_time_name:
            return False
        if not node.summer_time_recurring:
            # Only the recurring US rule is modelled; fixed dates are ignored.
            return False
        std_offset = self._std_offset_seconds(node)
        spring, fall = _dst_bounds_utc(utc.year, std_offset)
        return spring <= utc < fall

    def _apply_timezone(self, node: NodeState, utc: datetime) -> Tuple[datetime, str, int, bool]:
        """Return (local_datetime, zone_name, total_offset_seconds, dst_active)."""
        std_offset = self._std_offset_seconds(node)
        dst = self._dst_active(node, utc)
        total = std_offset + (3600 if dst else 0)
        local = utc + timedelta(seconds=total)
        if dst and node.summer_time_name:
            zone = node.summer_time_name
        else:
            zone = node.timezone_name or "UTC"
        return local, zone, total, dst

    def set_clock(
        self,
        node: NodeRef,
        hh: int,
        mm: int,
        ss: int,
        day: int,
        month_name: str,
        year: int,
        now: Optional[float] = None,
    ) -> NodeClock:
        """Manually set the volatile clock (``clock set`` semantics).

        The supplied wall time is interpreted in the node's configured local
        timezone and summer-time; ``clock_offset`` is derived so the simulated
        UTC matches, and the clock source becomes ``user``.
        """
        node = self._node(node)
        now = self._resolve_now(now)
        month = _month_number(month_name)
        local_naive = datetime(int(year), month, int(day), int(hh), int(mm), int(ss))
        std_offset = self._std_offset_seconds(node)
        # Assume standard offset, then correct if the instant is inside DST.
        utc = local_naive - timedelta(seconds=std_offset)
        if (node.summer_time_recurring or node.summer_time_name) and self._dst_active(node, utc):
            utc = local_naive - timedelta(seconds=std_offset + 3600)
        target_epoch = _to_epoch(utc)
        node.clock_offset = target_epoch - _BOOT_CALENDAR_EPOCH - self._uptime_seconds(node, now)
        node.clock_set_at = now
        node.clock_source = "user"
        return self.node_clock(node, now)

    def node_clock(self, node: NodeRef, now: Optional[float] = None) -> NodeClock:
        """Resolve a node's simulated clock, following NTP sync when present."""
        node = self._node(node)
        now = self._resolve_now(now)
        sync = self._ntp_resolve(node.name, now)
        if sync.synchronized:
            root = self.nodes.get(sync.root) if sync.root else None
            epoch = self._free_running_epoch(root or node, now)
            source, authoritative, marker = "ntp", True, ""
            reference: Optional[str] = sync.reference
            stratum = sync.stratum
        else:
            epoch = self._free_running_epoch(node, now)
            user_set = node.clock_source == "user" or node.clock_set_at is not None
            ntp_configured = bool(node.ntp_servers) or node.ntp_master is not None
            reference = None
            stratum = 16
            if user_set:
                source, authoritative, marker = "user", True, ""
            elif ntp_configured:
                source, authoritative, marker = "none", True, "."
            else:
                source, authoritative, marker = "none", False, "*"
        utc = _from_epoch(epoch)
        local, zone, total_offset, dst = self._apply_timezone(node, utc)
        return NodeClock(
            utc=utc,
            local=local,
            zone_name=zone,
            offset_seconds=total_offset,
            dst_active=dst,
            authoritative=authoritative,
            marker=marker,
            source=source,
            synchronized=sync.synchronized,
            stratum=stratum,
            reference=reference,
        )

    def format_clock(self, node: NodeRef, now: Optional[float] = None, detail: bool = False) -> str:
        """Render ``show clock`` / ``show clock detail`` text."""
        node = self._node(node)
        now = self._resolve_now(now)
        clock = self.node_clock(node, now)
        local = clock.local
        ms = local.microsecond // 1000
        line = (
            f"{clock.marker}{local.hour:02d}:{local.minute:02d}:{local.second:02d}.{ms:03d} "
            f"{clock.zone_name} {_WEEKDAYS[local.weekday()]} {_MONTHS[local.month]} "
            f"{local.day} {local.year}"
        )
        if not detail:
            return line
        if clock.source == "ntp":
            source_line = "Time source is NTP"
        elif clock.source == "user":
            source_line = "Time source is user configuration"
        else:
            source_line = "No time source"
        lines = [line, source_line]
        lines.extend(self._summer_time_lines(node, local.year))
        return "\n".join(lines)

    def _summer_time_lines(self, node: NodeState, year: int) -> List[str]:
        if not node.summer_time_recurring:
            return []
        std_zone = node.timezone_name or "UTC"
        dst_zone = node.summer_time_name or std_zone
        start_day = _nth_weekday_day(year, 3, _SUNDAY, 2)
        end_day = _nth_weekday_day(year, 11, _SUNDAY, 1)
        start = datetime(year, 3, start_day)
        end = datetime(year, 11, end_day)
        return [
            f"Summer time starts 02:00:00 {std_zone} {_WEEKDAYS[start.weekday()]} "
            f"{_MONTHS[3]} {start_day} {year}",
            f"Summer time ends 02:00:00 {dst_zone} {_WEEKDAYS[end.weekday()]} "
            f"{_MONTHS[11]} {end_day} {year}",
        ]

    def syslog_timestamp(self, node: NodeRef, now: Optional[float] = None) -> str:
        """Log-message timestamp for ``service timestamps log <format>``.

        ``uptime`` gives ``00:05:23`` / ``1d02h`` / ``2w3d`` / ``1y27w``.
        ``datetime`` gives ``*Mar  1 00:05:23`` in UTC; ``msec`` adds
        ``.123``, ``year`` inserts the year after the day, ``localtime`` uses
        the configured timezone/summer-time and ``show-timezone`` appends the
        zone name (``UTC`` without ``localtime``).  The ``*``/``.`` marker is
        the same as ``show clock``'s.
        """
        node = self._node(node)
        now = self._resolve_now(now)
        words = (getattr(node, "service_timestamps_log_format", "") or "datetime msec").split()
        if "datetime" not in words:
            return self._uptime_stamp(self._uptime_seconds(node, now))
        clock = self.node_clock(node, now)
        stamp = clock.local if "localtime" in words else clock.utc
        text = f"{clock.marker}{_MONTHS[stamp.month]} {stamp.day:2d} "
        if "year" in words:
            text += f"{stamp.year} "
        text += f"{stamp.hour:02d}:{stamp.minute:02d}:{stamp.second:02d}"
        if "msec" in words:
            text += f".{stamp.microsecond // 1000:03d}"
        if "show-timezone" in words:
            text += " " + (clock.zone_name if "localtime" in words else "UTC")
        return text

    @staticmethod
    def _uptime_stamp(seconds: float) -> str:
        """IOS uptime timestamp: ``hh:mm:ss`` under a day, then ``1d02h``, ``2w3d``, ``1y27w``."""
        total = int(max(0.0, seconds))
        days, rest = divmod(total, 86400)
        if days == 0:
            hours, rest = divmod(rest, 3600)
            minutes, secs = divmod(rest, 60)
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        if days < 7:
            return f"{days}d{rest // 3600:02d}h"
        years, days = divmod(days, 365)
        weeks, days = divmod(days, 7)
        if years == 0:
            return f"{weeks}w{days}d"
        return f"{years}y{weeks}w"

    @staticmethod
    def uptime_text(seconds: float) -> str:
        """IOS-style uptime, e.g. ``1 hour, 5 minutes`` / ``2 weeks, 3 days``."""
        minutes_total = int(max(0.0, seconds) // 60)
        years, rem = divmod(minutes_total, 525600)   # 365-day years
        weeks, rem = divmod(rem, 10080)
        days, rem = divmod(rem, 1440)
        hours, minutes = divmod(rem, 60)
        parts: List[Tuple[int, str]] = [
            (years, "year"),
            (weeks, "week"),
            (days, "day"),
            (hours, "hour"),
            (minutes, "minute"),
        ]
        chosen = [(value, label) for value, label in parts if value]
        if not chosen:
            return "0 minutes"
        return ", ".join(
            f"{value} {label}" + ("s" if value != 1 else "")
            for value, label in chosen
        )

    # ======================================================================
    # 2. NTP
    # ======================================================================
    def _ntp_resolve(
        self, node_name: str, now: float, visiting: Optional[set] = None
    ) -> _NtpSync:
        node = self.nodes.get(node_name)
        if node is None:
            return _NtpSync(False, 16, "", None, reason="missing node")
        if node.ntp_master is not None:
            return _NtpSync(
                True, int(node.ntp_master), "127.127.1.1", node_name,
                reason="local master",
            )
        visiting = set(visiting or set())
        if node_name in visiting:
            return _NtpSync(False, 16, "", None, reason="loop")
        visiting.add(node_name)
        for address in sorted(node.ntp_servers, key=_ip_sort_key):
            server_cfg = node.ntp_servers[address]
            endpoint = self.callbacks.find_ip(address)
            if endpoint is None or not self.callbacks.reachable(node_name, address):
                continue
            upstream_name = endpoint[0]
            upstream = self.nodes.get(upstream_name)
            if upstream is None:
                continue
            if node.ntp_authenticate:
                key_id = server_cfg.key_id
                if key_id is None:
                    continue
                if key_id not in node.ntp_trusted_keys or key_id not in upstream.ntp_trusted_keys:
                    continue
                if key_id not in node.ntp_keys or node.ntp_keys.get(key_id) != upstream.ntp_keys.get(key_id):
                    continue
            upstream_sync = self._ntp_resolve(upstream_name, now, visiting)
            if not upstream_sync.synchronized:
                continue
            stratum = upstream_sync.stratum + 1
            if stratum >= 16:
                continue
            return _NtpSync(
                True, stratum, address, upstream_sync.root,
                via=upstream_name, server_address=address,
                reason="upstream synchronized",
            )
        return _NtpSync(False, 16, "", None, reason="no valid server")

    def _ntp_reference_time(self, node: NodeState, now: float) -> Tuple[str, str]:
        utc = self.node_clock(node, now).utc
        unix = _to_epoch(utc)
        ntp_value = unix + _NTP_UNIX_DELTA
        secs = int(ntp_value)
        frac = int((ntp_value - secs) * (1 << 32)) & 0xFFFFFFFF
        hex_text = f"{secs & 0xFFFFFFFF:08X}.{frac:08X}"
        ms = utc.microsecond // 1000
        human = (
            f"{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}.{ms:03d} UTC "
            f"{_WEEKDAYS[utc.weekday()]} {_MONTHS[utc.month]} {utc.day} {utc.year}"
        )
        return hex_text, human

    def ntp_status(self, node: NodeRef, now: Optional[float] = None) -> NtpStatus:
        node = self._node(node)
        now = self._resolve_now(now)
        sync = self._ntp_resolve(node.name, now)
        hex_time, human_time = self._ntp_reference_time(node, now)
        uptime_cs = int(self._uptime_seconds(node, now) * 100)
        if sync.synchronized:
            return NtpStatus(
                synchronized=True,
                stratum=sync.stratum,
                reference=sync.reference,
                reference_time_hex=hex_time,
                reference_time_text=human_time,
                loopfilter_state="'CTRL' (Normal Controlled Loop)",
                last_update=f"{int(self._uptime_seconds(node, now)) % 64} sec ago",
                ntp_uptime_cs=uptime_cs,
                root_dispersion_ms=1.0 if sync.root != node.name else 0.0,
                peer_dispersion_ms=0.5 if sync.root != node.name else 0.0,
            )
        return NtpStatus(
            synchronized=False,
            stratum=16,
            reference="",
            reference_time_hex=hex_time,
            reference_time_text=human_time,
            loopfilter_state="'FREERUN'",
            last_update="never",
            ntp_uptime_cs=uptime_cs,
            root_dispersion_ms=0.0,
            peer_dispersion_ms=0.0,
        )

    def ntp_associations(
        self, node: NodeRef, now: Optional[float] = None, detail: bool = False
    ) -> List[NtpAssociation]:
        node = self._node(node)
        now = self._resolve_now(now)
        sync = self._ntp_resolve(node.name, now)
        selected = sync.server_address if sync.synchronized else None
        rows: List[NtpAssociation] = []
        for address in sorted(node.ntp_servers, key=_ip_sort_key):
            server_cfg = node.ntp_servers[address]
            endpoint = self.callbacks.find_ip(address)
            reachable = endpoint is not None and self.callbacks.reachable(node.name, address)
            upstream_name = endpoint[0] if endpoint else None
            upstream_sync = (
                self._ntp_resolve(upstream_name, now) if upstream_name else None
            )
            peer_stratum = upstream_sync.stratum if (upstream_sync and upstream_sync.synchronized) else 16
            ref_clock = (
                upstream_sync.reference if (upstream_sync and upstream_sync.synchronized) else ".INIT."
            )
            is_selected = selected == address
            usable = bool(upstream_sync and upstream_sync.synchronized and reachable)
            if is_selected:
                marker = "*"
            elif usable:
                marker = "+"
            else:
                marker = "~"
            authenticated = server_cfg.key_id is not None and node.ntp_authenticate
            rows.append(
                NtpAssociation(
                    marker=marker,
                    address=address,
                    ref_clock=ref_clock,
                    stratum=peer_stratum,
                    when=int(now) % 64,
                    poll=64,
                    reach=377 if (reachable and usable) else 0,
                    delay_ms=0.0,
                    offset_ms=0.0,
                    dispersion_ms=0.0 if usable else 15.937,
                    configured=True,
                    authenticated=authenticated,
                    sane=usable,
                    valid=usable,
                    ref_id=ref_clock,
                )
            )
        return rows

    # ======================================================================
    # 3. DHCP (stateful)
    # ======================================================================
    @staticmethod
    def _client_id(mac: str) -> str:
        digits = "01" + normalise_mac(mac)
        groups = [digits[i:i + 4] for i in range(0, len(digits), 4)]
        return ".".join(groups)

    def _client_interface(self, node: NodeState, interface: Optional[str]):
        if interface is not None:
            return node.ensure_interface(interface)
        return node.first_host_interface()

    def _pool_for_address(self, server: NodeState, address: str):
        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            return None
        for pool_name in sorted(server.dhcp_pools):
            pool = server.dhcp_pools[pool_name]
            network = pool.network
            if network is not None and target in network:
                return pool
        return None

    def _server_interface_in(self, server: NodeState, network: ipaddress.IPv4Network) -> Optional[str]:
        for iface in sorted(server.interfaces.values(), key=lambda i: natural_key(i.name)):
            if iface.ip_address:
                try:
                    if ipaddress.ip_address(iface.ip_address) in network:
                        return iface.name
                except ValueError:
                    continue
        return None

    def _used_addresses(self) -> set:
        used = set()
        for node in self.nodes.values():
            for iface in node.interfaces.values():
                if iface.ip_address:
                    used.add(iface.ip_address)
                for secondary, _mask in iface.secondary_addresses:
                    used.add(secondary)
            for pool in node.dhcp_pools.values():
                used.update(pool.bindings.keys())
        return used

    @staticmethod
    def _excluded_predicate(node: NodeState):
        ranges: List[Tuple[int, int]] = []
        for start, end in node.dhcp_excluded:
            try:
                low = int(ipaddress.ip_address(start))
                high = int(ipaddress.ip_address(end))
            except ValueError:
                continue
            if high < low:
                low, high = high, low
            ranges.append((low, high))

        def excluded(value: int) -> bool:
            return any(low <= value <= high for low, high in ranges)

        return excluded

    def _candidate_addresses(self, network: ipaddress.IPv4Network) -> Iterable[ipaddress.IPv4Address]:
        """Pool addresses in allocation order, probing at most the probe limit.

        NetSimX convention (kept from the pre-Phase-3 engine and pinned by
        ``test_slash_zero_dhcp_allocation_is_lazy_and_bounded``): when a pool
        has more than nine host addresses, allocation starts at the tenth
        (``.10`` in a /24, leaving ``.1``-``.9`` for statically addressed
        infrastructure) and wraps round to the start of the pool.
        """
        if network.prefixlen < 31:
            first = int(network.network_address) + 1
            count = network.num_addresses - 2
        else:
            first = int(network.network_address)
            count = network.num_addresses
        count = max(0, count)
        if count <= 0:
            return
        start = 9 if count > 9 else 0
        limit = min(count, self.DHCP_CANDIDATE_PROBE_LIMIT)
        for offset in range(limit):
            index = start + offset
            if index >= count:
                index -= count
            yield ipaddress.IPv4Address(first + index)

    def _lease_seconds(self, pool: DHCPPool) -> Optional[int]:
        if pool.lease_infinite:
            return None
        total = pool.lease_days * 86400 + pool.lease_hours * 3600 + pool.lease_minutes * 60
        return total if total > 0 else 86400

    def _select_server(self, client: NodeState, iface) -> Tuple[Optional[dict], str, str]:
        """Find the serving router for ``client``'s segment.

        Returns ``(selection, code, reason)`` where ``selection`` is a dict with
        keys server(NodeState), server_name, pool, giaddr, relay(bool),
        server_address, server_interface — or ``None`` on failure.
        """
        client_seg = self.callbacks.segment_of(client.name, iface.name)
        if client_seg is None:
            return None, "no_segment", "no DHCP server reachable (interface down or unlinked)"

        gateways: List[Tuple[str, object]] = []
        for rname in sorted(self.nodes):
            rnode = self.nodes[rname]
            if rnode.kind != "router":
                continue
            for rif in sorted(rnode.interfaces.values(), key=lambda i: natural_key(i.name)):
                if not rif.ip_address:
                    continue
                if not self.callbacks.line_protocol_up(rname, rif.name):
                    continue
                if self.callbacks.segment_of(rname, rif.name) == client_seg:
                    gateways.append((rname, rif))

        if not gateways:
            return None, "no_server", "no DHCP server reachable on this segment"

        for rname, rif in gateways:
            rnode = self.nodes[rname]
            giaddr = rif.ip_address
            # Direct: this router serves a pool whose network contains giaddr.
            if rnode.dhcp_service_enabled:
                pool = self._pool_for_address(rnode, giaddr)
                if pool is not None:
                    return (
                        {
                            "server": rnode,
                            "server_name": rname,
                            "pool": pool,
                            "giaddr": giaddr,
                            "relay": False,
                            "server_address": rif.ip_address,
                            "server_interface": rif.name,
                        },
                        "ok",
                        "",
                    )
            # Relay: giaddr = this router interface; forward to each helper.
            for helper in rif.helper_addresses:
                if not self.callbacks.reachable(rname, helper):
                    continue
                endpoint = self.callbacks.find_ip(helper)
                if endpoint is None:
                    continue
                snode = self.nodes.get(endpoint[0])
                if snode is None or not snode.dhcp_service_enabled:
                    continue
                pool = self._pool_for_address(snode, giaddr)
                if pool is not None:
                    return (
                        {
                            "server": snode,
                            "server_name": endpoint[0],
                            "pool": pool,
                            "giaddr": giaddr,
                            "relay": True,
                            "server_address": helper,
                            "server_interface": self._server_interface_in(snode, pool.network)
                            or rif.name,
                        },
                        "ok",
                        "",
                    )
        return None, "no_server", "no matching DHCP pool for this subnet"

    def dhcp_request(
        self,
        client_node: NodeRef,
        now: Optional[float] = None,
        interface: Optional[str] = None,
    ) -> DhcpResult:
        """Perform a full DORA exchange for a host and commit the lease."""
        client = self._node(client_node)
        now = self._resolve_now(now)
        iface = self._client_interface(client, interface)
        mac = client.interface_mac(iface.name) or client.base_mac()
        client_id = self._client_id(mac)

        if not self.callbacks.line_protocol_up(client.name, iface.name):
            return DhcpResult(False, "D", code="no_segment",
                              reason="interface is down", client_id=client_id,
                              interface=iface.name)

        selection, code, reason = self._select_server(client, iface)
        if selection is None:
            return DhcpResult(False, "DDDD", code=code, reason=reason,
                              client_id=client_id, interface=iface.name)

        server: NodeState = selection["server"]
        pool: DHCPPool = selection["pool"]
        network = pool.network
        if network is None:
            return DhcpResult(False, "DDDD", code="no_server",
                              reason="DHCP pool has no network", client_id=client_id,
                              interface=iface.name)

        # Reuse an existing binding for this client if present.
        existing_addr = next(
            (addr for addr, b in pool.bindings.items() if b.client_id == client_id),
            None,
        )
        excluded = self._excluded_predicate(server)
        used = self._used_addresses()
        gateway = pool.default_router

        chosen: Optional[str] = existing_addr
        if chosen is None:
            for candidate in self._candidate_addresses(network):
                text = str(candidate)
                value = int(candidate)
                if text == gateway:
                    continue
                if text in pool.conflicts:
                    continue
                if excluded(value):
                    continue
                if text in used:
                    continue
                chosen = text
                break

        if chosen is None:
            return DhcpResult(False, "DDORA", code="pool_exhausted",
                              reason="DHCP pool exhausted", client_id=client_id,
                              pool_name=pool.name, server_node=selection["server_name"],
                              relay=selection["relay"], giaddr=selection["giaddr"],
                              interface=iface.name)

        lease_seconds = self._lease_seconds(pool)
        expires_at = None if lease_seconds is None else now + lease_seconds
        binding = DHCPBinding(
            address=chosen,
            client_id=client_id,
            client_node=client.name,
            leased_at=now,
            expires_at=expires_at,
            binding_type="Automatic",
            interface=selection["server_interface"],
        )
        pool.bindings[chosen] = binding
        pool.leases[client.name] = chosen

        netmask = str(network.netmask)
        iface.ip_address = chosen
        iface.netmask = netmask
        iface.address_source = "dhcp"
        iface.configured = True
        client.default_gateway = gateway
        client.dhcp_client = DHCPClientState(
            server=selection["server_address"],
            leased_at=now,
            lease_seconds=lease_seconds,
            dns_servers=list(pool.dns_servers),
            domain_name=pool.domain_name,
        )

        return DhcpResult(
            success=True,
            steps="DORA",
            code="ok",
            address=chosen,
            mask=netmask,
            gateway=gateway,
            server=selection["server_address"],
            domain=pool.domain_name,
            dns_servers=list(pool.dns_servers),
            lease_seconds=lease_seconds,
            client_id=client_id,
            pool_name=pool.name,
            server_node=selection["server_name"],
            relay=selection["relay"],
            giaddr=selection["giaddr"],
            interface=iface.name,
        )

    def _find_client_binding(self, client_name: str) -> Optional[Tuple[NodeState, DHCPPool, str]]:
        for server in self.nodes.values():
            for pool in server.dhcp_pools.values():
                for addr, binding in pool.bindings.items():
                    if binding.client_node == client_name:
                        return server, pool, addr
        return None

    def dhcp_release(self, client_node: NodeRef, now: Optional[float] = None) -> DhcpResult:
        """Release a host's lease and clear its DHCP-sourced address."""
        client = self._node(client_node)
        now = self._resolve_now(now)
        found = self._find_client_binding(client.name)
        if found is None:
            return DhcpResult(False, "", code="no_lease", reason="no active DHCP lease")
        _server, pool, address = found
        pool.bindings.pop(address, None)
        pool.leases.pop(client.name, None)
        for iface in client.interfaces.values():
            if iface.address_source == "dhcp" and iface.ip_address == address:
                iface.ip_address = None
                iface.netmask = None
                iface.address_source = None
        client.default_gateway = None
        client.dhcp_client = DHCPClientState()
        return DhcpResult(True, "release", code="ok", address=address, pool_name=pool.name)

    def dhcp_renew(self, client_node: NodeRef, now: Optional[float] = None) -> DhcpResult:
        """Extend an existing lease from ``now``."""
        client = self._node(client_node)
        now = self._resolve_now(now)
        found = self._find_client_binding(client.name)
        if found is None:
            return DhcpResult(False, "", code="no_lease", reason="no active DHCP lease")
        _server, pool, address = found
        binding = pool.bindings[address]
        lease_seconds = self._lease_seconds(pool)
        binding.leased_at = now
        binding.expires_at = None if lease_seconds is None else now + lease_seconds
        if client.dhcp_client is not None:
            client.dhcp_client.leased_at = now
            client.dhcp_client.lease_seconds = lease_seconds
        return DhcpResult(True, "renew", code="ok", address=address,
                          lease_seconds=lease_seconds, pool_name=pool.name)

    def expire_bindings(self, now: Optional[float] = None) -> int:
        """Remove every expired (non-infinite) binding; return the count removed."""
        now = self._resolve_now(now)
        removed = 0
        for server in self.nodes.values():
            for pool in server.dhcp_pools.values():
                stale = [
                    addr for addr, b in pool.bindings.items()
                    if b.expires_at is not None and b.expires_at <= now
                ]
                for addr in stale:
                    binding = pool.bindings.pop(addr)
                    pool.leases.pop(binding.client_node or "", None)
                    removed += 1
        return removed

    def _local_from_epoch(self, node: NodeState, epoch: float) -> datetime:
        utc = _from_epoch(epoch)
        local, _zone, _offset, _dst = self._apply_timezone(node, utc)
        return local

    def _format_lease_expiration(self, node: NodeState, epoch: Optional[float]) -> str:
        if epoch is None:
            return "Infinite"
        local = self._local_from_epoch(node, epoch)
        hour12 = local.hour % 12 or 12
        ampm = "AM" if local.hour < 12 else "PM"
        return (
            f"{_MONTHS[local.month]} {local.day:02d} {local.year} "
            f"{hour12:02d}:{local.minute:02d} {ampm}"
        )

    def dhcp_bindings(self, server_node: NodeRef, now: Optional[float] = None) -> List[DhcpBindingRow]:
        """Rows for ``show ip dhcp binding``."""
        server = self._node(server_node)
        rows: List[DhcpBindingRow] = []
        for pool_name in sorted(server.dhcp_pools):
            pool = server.dhcp_pools[pool_name]
            for address in sorted(pool.bindings, key=_ip_sort_key):
                binding = pool.bindings[address]
                rows.append(
                    DhcpBindingRow(
                        ip=address,
                        client_id=binding.client_id,
                        lease_expiration=self._format_lease_expiration(server, binding.expires_at),
                        type=binding.binding_type,
                        state="Active",
                        interface=binding.interface or "",
                    )
                )
        return rows

    def dhcp_pool_stats(self, server_node: NodeRef, pool: Union[str, DHCPPool]) -> Optional[DhcpPoolStats]:
        """Stats for ``show ip dhcp pool``."""
        server = self._node(server_node)
        if isinstance(pool, str):
            pool_obj = server.dhcp_pools.get(pool)
        else:
            pool_obj = pool
        if pool_obj is None:
            return None
        network = pool_obj.network
        if network is None:
            return DhcpPoolStats(pool_obj.name, "", "", 0, 0, len(pool_obj.bindings),
                                 0, 0, 0, 0, None, None, None)
        if network.prefixlen < 31:
            total = network.num_addresses - 2
            first = network.network_address + 1
            last = network.broadcast_address - 1
        else:
            total = network.num_addresses
            first = network.network_address
            last = network.broadcast_address
        total = max(0, total)
        leased = len(pool_obj.bindings)
        excluded_pred = self._excluded_predicate(server)
        excluded = 0
        for candidate in self._candidate_addresses(network):
            if excluded_pred(int(candidate)):
                excluded += 1
        available = max(0, total - leased - excluded)
        utilization = int(round((leased / total) * 100)) if total else 0
        current = next(
            (str(c) for c in self._candidate_addresses(network)
             if str(c) not in pool_obj.bindings and not excluded_pred(int(c))),
            None,
        )
        return DhcpPoolStats(
            pool_name=pool_obj.name,
            network=str(network.network_address),
            netmask=str(network.netmask),
            subnet_size=network.num_addresses,
            total=total,
            leased=leased,
            excluded=excluded,
            available=available,
            pending=0,
            utilization=utilization,
            current_index=current,
            first_address=str(first),
            last_address=str(last),
        )

    def dhcp_conflicts(self, server_node: NodeRef) -> List[DhcpConflictRow]:
        """Rows for ``show ip dhcp conflict``."""
        server = self._node(server_node)
        rows: List[DhcpConflictRow] = []
        for pool_name in sorted(server.dhcp_pools):
            pool = server.dhcp_pools[pool_name]
            for address in sorted(pool.conflicts, key=_ip_sort_key):
                rows.append(
                    DhcpConflictRow(
                        address=address,
                        detection_time=self._format_lease_expiration(server, pool.conflicts[address]),
                        detection_method="Ping",
                    )
                )
        return rows

    # ======================================================================
    # 4. CDP / LLDP
    # ======================================================================
    def _neighbor_links(self, node_name: str):
        """Yield ``(local_iface, far_name, far_iface)`` for every link touching node."""
        for a, ai, b, bi in self.links:
            if a == node_name:
                yield ai, b, bi
            elif b == node_name:
                yield bi, a, ai

    @staticmethod
    def _speaks_cdp(node: NodeState) -> bool:
        return node.platform != "vpcs"

    @staticmethod
    def _capabilities_for(node: NodeState) -> str:
        if node.platform == "iol-l2":
            return "R S I"
        if node.platform == "iol-l3":
            return "R B"
        return "R"

    @staticmethod
    def _lldp_capabilities_for(node: NodeState) -> str:
        if node.platform == "iol-l2":
            return "B"
        if node.platform == "iol-l3":
            return "R"
        return ""

    @staticmethod
    def _ios_version(node: NodeState) -> str:
        if node.platform == "iol-l2":
            return ("Cisco IOS Software, Linux Software (I86BI_LINUXL2-"
                    "ADVENTERPRISEK9-M), Version 15.2(4)E, RELEASE SOFTWARE (fc1)")
        return ("Cisco IOS Software, Linux Software (I86BI_LINUX-"
                "ADVENTERPRISEK9-M), Version 15.7(3)M3, RELEASE SOFTWARE (fc2)")

    def _holdtime(self, node: NodeState, now: float) -> int:
        timer = node.cdp_timer or 60
        phase = int(now) % timer
        hold = node.cdp_holdtime - phase
        if hold < 1:
            hold = node.cdp_holdtime
        return hold

    def cdp_neighbors(self, node: NodeRef, now: Optional[float] = None) -> List[CdpNeighbor]:
        """CDP neighbours visible on ``node`` (``show cdp neighbors [detail]``)."""
        node = self._node(node)
        now = self._resolve_now(now)
        if not node.cdp_enabled or not self._speaks_cdp(node):
            return []
        neighbors: List[CdpNeighbor] = []
        for local_if, far_name, far_if in self._neighbor_links(node.name):
            far = self.nodes.get(far_name)
            if far is None or not self._speaks_cdp(far) or not far.cdp_enabled:
                continue
            local_iface = node.interfaces.get(canonical_interface(local_if))
            far_iface = far.interfaces.get(canonical_interface(far_if))
            if local_iface is not None and not local_iface.cdp_enabled:
                continue
            if far_iface is not None and not far_iface.cdp_enabled:
                continue
            if not self.callbacks.line_protocol_up(node.name, local_if):
                continue
            if not self.callbacks.line_protocol_up(far_name, far_if):
                continue
            device_id = far.hostname + (f".{far.domain_name}" if far.domain_name else "")
            addresses = [far_iface.ip_address] if (far_iface and far_iface.ip_address) else []
            mgmt = list(addresses)
            if not mgmt:
                svi = far.interfaces.get("Vlan1")
                if svi and svi.ip_address:
                    mgmt = [svi.ip_address]
            native_vlan = None
            if far_iface is not None:
                if far_iface.switchport_mode == "trunk":
                    native_vlan = far_iface.trunk_native_vlan
                elif far_iface.switchport_mode == "access":
                    native_vlan = far_iface.access_vlan
            neighbors.append(
                CdpNeighbor(
                    device_id=device_id,
                    local_interface=canonical_interface(local_if),
                    local_interface_short=_short_ifname(local_if),
                    holdtime=self._holdtime(far, now),
                    capabilities=self._capabilities_for(far),
                    platform="Linux Unix",
                    port_id=canonical_interface(far_if),
                    port_id_short=_short_ifname(far_if),
                    mgmt_addresses=mgmt,
                    interface_addresses=addresses,
                    version=self._ios_version(far),
                    native_vlan=native_vlan,
                    duplex="full",
                    advertisement_version=2,
                )
            )
        neighbors.sort(key=lambda n: (natural_key(n.local_interface), n.device_id))
        return neighbors

    def cdp_globals(self, node: NodeRef) -> CdpGlobals:
        """Globals for ``show cdp``."""
        node = self._node(node)
        return CdpGlobals(
            enabled=node.cdp_enabled and self._speaks_cdp(node),
            timer=node.cdp_timer,
            holdtime=node.cdp_holdtime,
            advertise_v2=True,
        )

    def lldp_neighbors(self, node: NodeRef, now: Optional[float] = None) -> List[LldpNeighbor]:
        """LLDP neighbours visible on ``node`` (``show lldp neighbors``)."""
        node = self._node(node)
        now = self._resolve_now(now)
        if not node.lldp_enabled or node.platform == "vpcs":
            return []
        neighbors: List[LldpNeighbor] = []
        for local_if, far_name, far_if in self._neighbor_links(node.name):
            far = self.nodes.get(far_name)
            if far is None or not far.lldp_enabled or far.platform == "vpcs":
                continue
            local_iface = node.interfaces.get(canonical_interface(local_if))
            far_iface = far.interfaces.get(canonical_interface(far_if))
            if local_iface is not None and not local_iface.lldp_transmit:
                continue
            if far_iface is not None and not far_iface.lldp_receive:
                continue
            if not self.callbacks.line_protocol_up(node.name, local_if):
                continue
            if not self.callbacks.line_protocol_up(far_name, far_if):
                continue
            addresses = [far_iface.ip_address] if (far_iface and far_iface.ip_address) else []
            neighbors.append(
                LldpNeighbor(
                    system_name=far.hostname,
                    local_interface=canonical_interface(local_if),
                    local_interface_short=_short_ifname(local_if),
                    hold_time=120,
                    capabilities=self._lldp_capabilities_for(far),
                    port_id=canonical_interface(far_if),
                    port_description="",
                    mgmt_addresses=addresses,
                )
            )
        neighbors.sort(key=lambda n: (natural_key(n.local_interface), n.system_name))
        return neighbors

    # ======================================================================
    # 5. Remote access policy (VTY / SSH / Telnet)
    # ======================================================================
    @staticmethod
    def _vty_lines(node: NodeState):
        lines = [(name, cfg) for name, cfg in node.lines.items() if name.startswith("vty")]

        def start_index(name: str) -> int:
            match = re.search(r"vty\s+(\d+)", name)
            return int(match.group(1)) if match else 0

        return sorted(lines, key=lambda item: start_index(item[0]))

    def ssh_server_info(self, node: NodeRef) -> SshServerInfo:
        """Data for ``show ip ssh``."""
        node = self._node(node)
        enabled = node.rsa_bits is not None
        if node.ssh_version == 2:
            version = "2.0"
        elif node.ssh_version == 1:
            version = "1.5"
        else:
            version = "1.99"
        state = "Enabled" if enabled else "Disabled"
        return SshServerInfo(
            enabled=enabled,
            version_text=f"SSH {state} - version {version}",
            version=version,
            auth_timeout=node.ip_ssh_timeout,
            retries=node.ip_ssh_retries,
            modulus=node.rsa_bits,
        )

    def vty_access(
        self,
        src_node: NodeRef,
        target_address: str,
        transport: str,
        now: Optional[float] = None,
    ) -> VtyDecision:
        """Decide whether ``src_node`` can open a ``transport`` session.

        Models reachability, VTY transport policy, SSH key/version requirements
        and the login mode, returning IOS-faithful failure messages.
        """
        now = self._resolve_now(now)
        src_name = self._name(src_node)
        transport = transport.lower()

        if not self.callbacks.reachable(src_name, target_address):
            return VtyDecision(False, "% Connection timed out; remote host not responding",
                               "timeout", transport, target_address=target_address)
        endpoint = self.callbacks.find_ip(target_address)
        if endpoint is None:
            return VtyDecision(False, "% Connection timed out; remote host not responding",
                               "timeout", transport, target_address=target_address)
        target = self.nodes.get(endpoint[0])
        if target is None:
            return VtyDecision(False, "% Connection timed out; remote host not responding",
                               "timeout", transport, target_address=target_address)

        vty_lines = self._vty_lines(target)
        permitting = [
            (name, cfg) for name, cfg in vty_lines if transport in cfg.transport_input
        ]
        if not permitting:
            return VtyDecision(False, "% Connection refused by remote host", "refused",
                               transport, target_node=target.name, target_address=target_address)

        if transport == "ssh" and target.rsa_bits is None:
            return VtyDecision(False, "% Connection refused by remote host", "refused",
                               transport, target_node=target.name, target_address=target_address)

        line_name, line_cfg = permitting[0]
        if line_cfg.login_local:
            mode = "local"
            requires_username = True
            requires_password = True
        elif line_cfg.login:
            mode = "line"
            requires_username = transport == "ssh"
            requires_password = True
            if line_cfg.password is None:
                return VtyDecision(False, "Password required, but none set", "no_password",
                                   transport, target_node=target.name,
                                   target_address=target_address, target_line=line_name,
                                   login_mode="line")
        else:
            mode = "none"
            requires_username = transport == "ssh"
            requires_password = False

        return VtyDecision(
            allowed=True,
            message="",
            code="ok",
            transport=transport,
            target_node=target.name,
            target_address=target_address,
            target_line=line_name,
            login_mode=mode,
            requires_username=requires_username,
            requires_password=requires_password,
        )

    def vty_authenticate(
        self,
        target_node: NodeRef,
        mode: str,
        username: Optional[str],
        password: Optional[str],
        line: Optional[str] = None,
    ) -> bool:
        """Validate a login against the local user DB or the line password (exact)."""
        target = self._node(target_node)
        if mode == "none":
            return True
        if mode == "local":
            if not username:
                return False
            return target.verify_user(username, password or "")
        if mode == "line":
            if line is not None:
                cfg = target.lines.get(line)
                line_password = cfg.password if cfg else None
            else:
                vty = self._vty_lines(target)
                line_password = vty[0][1].password if vty else None
            return line_password is not None and password == line_password
        return False
