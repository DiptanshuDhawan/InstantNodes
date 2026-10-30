"""Realistic IOL 15.x ``running-config`` / ``startup-config`` rendering.

This module turns an immutable :class:`~simulator.models.NodeState` into the
exact text a Cisco IOL image would print for ``show running-config`` and
``show startup-config``.  Three device families are supported:

* ``iol-l3`` -- routers and IOS-based hosts (``version 15.7``)
* ``iol-l2`` -- switches (``version 15.2``, ``service compress-config``, the
  ``logging discriminator`` pair, ``spanning-tree`` and
  ``vlan internal allocation policy`` boilerplate)
* ``vpcs``  -- VPCS PCs, rendered as a VPCS startup script, never a fake IOS
  config (:func:`render_vpcs_config`).

The output is meant to be re-parseable as genuine IOS/VPCS syntax: every line
is either a documented boilerplate no-op (see ``PLAN.md``) or a command the IOS
command engine accepts.  Credentials are encoded exactly as IOS renders them --
``enable secret``/``username ... secret`` as type 5 (MD5-crypt), line passwords,
``enable password`` and NTP keys as type 7 when ``service password-encryption``
/ NTP authentication applies.

``crypto`` is imported lazily and the layer-2/3, OSPF and services engines are
never imported here: rendering is a pure function of a single node's state.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import List, Optional, Tuple

from ..models import (
    NodeState,
    PLATFORM_SWITCH,
    PLATFORM_VPCS,
    InterfaceState,
    LineConfig,
    canonical_interface,
    interface_parent,
    natural_key,
    vty_name,
    vty_span,
)

__all__ = [
    "render_running_config",
    "render_show_running",
    "render_startup_config",
    "render_vpcs_config",
]

NVRAM_SIZE = 262144


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def render_running_config(node: NodeState, now: Optional[float] = None) -> str:
    """Return the running-config body (starts with ``!``, ends with ``end``)."""
    if _is_vpcs(node):
        return render_vpcs_config(node)
    return _render_ios_running(node, now=now)


def render_show_running(
    node: NodeState, now: Optional[float] = None, interface: Optional[str] = None
) -> str:
    """Return ``show running-config`` output including the IOS header."""
    if _is_vpcs(node):
        return render_vpcs_config(node)
    if interface is not None:
        block = _render_interface_only(node, interface)
        size = len(block.encode("utf-8"))
        return (
            "Building configuration...\n\n"
            f"Current configuration : {size} bytes\n"
            "!\n" + block
        )
    body = _render_ios_running(node, now=now)
    size = len(body.encode("utf-8"))
    header = ["Building configuration...", "", f"Current configuration : {size} bytes"]
    if node.last_config_change:
        stamp = _format_config_time(node, node.last_config_change)
        by = node.last_config_by or "console"
        header.append(f"! Last configuration change at {stamp} by {by}")
    return "\n".join(header) + "\n" + body


def render_startup_config(node: NodeState) -> str:
    """Return ``show startup-config`` output (NVRAM header or 'not present')."""
    saved = node.saved_startup_config or ""
    if not saved.strip():
        return "startup-config is not present"
    body = saved.rstrip("\n")
    used = len(body.encode("utf-8"))
    return f"Using {used} out of {NVRAM_SIZE} bytes\n!\n{body}\n"


def render_vpcs_config(node: NodeState) -> str:
    """Return the VPCS startup script for ``node`` (never a fake IOS config)."""
    lines = [f"set pcname {node.hostname or node.name}"]
    interface = node.first_host_interface()
    if node.dhcp_enabled or interface.address_source == "dhcp":
        lines.append("ip dhcp")
    elif interface.ip_address and interface.netmask:
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{interface.netmask}").prefixlen
            suffix = f" {node.default_gateway}" if node.default_gateway else ""
            lines.append(f"ip {interface.ip_address}/{prefix}{suffix}")
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            pass
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_vpcs(node: NodeState) -> bool:
    return node.platform == PLATFORM_VPCS or node.cli_profile == "vpcs"


def _is_switch(node: NodeState) -> bool:
    return node.platform == PLATFORM_SWITCH or node.kind == "switch"


def _version(node: NodeState) -> str:
    return "15.2" if _is_switch(node) else "15.7"


class _Builder:
    """Accumulates config lines, collapsing duplicate ``!`` separators."""

    def __init__(self) -> None:
        self.lines: List[str] = ["!"]

    def add(self, line: str) -> None:
        self.lines.append(line)

    def extend(self, values: List[str]) -> None:
        self.lines.extend(values)

    def sep(self) -> None:
        if self.lines and self.lines[-1] != "!":
            self.lines.append("!")

    def render(self) -> str:
        if self.lines[-1] != "!":
            self.sep()
        self.lines.append("end")
        return "\n".join(self.lines) + "\n"


def _render_ios_running(node: NodeState, now: Optional[float] = None) -> str:
    builder = _Builder()
    switch = _is_switch(node)

    # --- version + services ------------------------------------------------
    builder.add(f"version {_version(node)}")
    if switch:
        builder.add("service compress-config")
    for kind in ("debug", "log"):
        if getattr(node, f"service_timestamps_{kind}", True):
            fmt = getattr(node, f"service_timestamps_{kind}_format", "") or "datetime msec"
            builder.add(f"service timestamps {kind} {fmt}")
        else:
            builder.add(f"no service timestamps {kind} uptime")
    if node.password_encryption:
        builder.add("service password-encryption")
    builder.sep()

    # --- hostname ----------------------------------------------------------
    builder.add(f"hostname {node.hostname}")
    builder.sep()

    # --- boot markers ------------------------------------------------------
    builder.add("boot-start-marker")
    builder.add("boot-end-marker")
    builder.sep()

    # --- enable credentials ------------------------------------------------
    enable_secret = _enable_secret_line(node)
    if enable_secret:
        builder.add(enable_secret)
    enable_password = _enable_password_line(node)
    if enable_password:
        builder.add(enable_password)
    if enable_secret or enable_password:
        builder.sep()

    # --- aaa + clock -------------------------------------------------------
    builder.add("no aaa new-model")
    for line in _clock_lines(node):
        builder.add(line)
    builder.sep()

    # --- spanning-tree / switch globals (early block) ----------------------
    if switch:
        builder.add(f"spanning-tree mode {node.stp_mode}")
        if node.stp_portfast_default:
            builder.add("spanning-tree portfast default")
        if node.stp_bpduguard_default:
            builder.add("spanning-tree portfast bpduguard default")
        for vlan_id in sorted(node.stp_priorities):
            builder.add(
                f"spanning-tree vlan {vlan_id} priority {node.stp_priorities[vlan_id]}"
            )
        builder.add("spanning-tree extend system-id")
        builder.sep()

    # --- domain / name resolution ------------------------------------------
    domain_block: List[str] = []
    if not node.ip_domain_lookup:
        domain_block.append("no ip domain lookup")
    if node.domain_name:
        domain_block.append(f"ip domain name {node.domain_name}")
    for server in node.name_servers:
        domain_block.append(f"ip name-server {server}")
    for host in sorted(node.ip_hosts):
        domain_block.append(f"ip host {host} {node.ip_hosts[host]}")
    if domain_block:
        builder.extend(domain_block)
        builder.sep()

    # --- VTP / VLAN definitions (transparent mode shows VLANs) -------------
    if switch:
        if node.vtp_mode != "server":
            builder.add(f"vtp mode {node.vtp_mode}")
        if node.vtp_domain:
            builder.add(f"vtp domain {node.vtp_domain}")
        if node.vtp_mode != "server" or node.vtp_domain:
            builder.sep()
        if node.vtp_mode == "transparent":
            vlan_block = _vlan_lines(node)
            if vlan_block:
                builder.extend(vlan_block)
                builder.sep()

    # --- CEF (routers) -----------------------------------------------------
    if not switch:
        builder.add("ip cef")
        builder.add("no ipv6 cef")
        builder.sep()

    # --- ip routing (only when it deviates from the platform default) ------
    if not switch and not node.ip_routing:
        builder.add("no ip routing")
        builder.sep()
    elif switch and node.ip_routing:
        builder.add("ip routing")
        builder.sep()

    # --- DHCP --------------------------------------------------------------
    dhcp_block = _dhcp_lines(node)
    if dhcp_block:
        builder.extend(dhcp_block)
        builder.sep()

    # --- local users (one ordering, whichever way each credential is stored) --
    user_block = [
        _username_line(node, name)
        for name in sorted(set(node.users) | set(node.user_secret_hashes))
    ]
    user_block = [line for line in user_block if line]
    if user_block:
        builder.extend(user_block)
        builder.sep()

    # --- SSH + CDP/LLDP management -----------------------------------------
    ssh_block = _ssh_lines(node)
    if ssh_block:
        builder.extend(ssh_block)
        builder.sep()
    management: List[str] = []
    if node.cdp_timer != 60:
        management.append(f"cdp timer {node.cdp_timer}")
    if node.cdp_holdtime != 180:
        management.append(f"cdp holdtime {node.cdp_holdtime}")
    if not node.cdp_enabled:
        management.append("no cdp run")
    if node.lldp_enabled:
        management.append("lldp run")
    if management:
        builder.extend(management)
        builder.sep()

    # --- platform filler ---------------------------------------------------
    if not switch:
        builder.add("multilink bundle-name authenticated")
        builder.sep()
    else:
        builder.add("vlan internal allocation policy ascending")
        builder.sep()
    builder.add("redundancy")
    builder.sep()
    if switch:
        builder.add(
            "logging discriminator EXCESS severity drops 6 msg-body drops EXCESSCOLL"
        )
        builder.add("logging console discriminator EXCESS")
        if node.logging_buffered is not None:
            builder.add(f"logging buffered {node.logging_buffered}")
        builder.sep()
    elif node.logging_buffered is not None:
        builder.add(f"logging buffered {node.logging_buffered}")
        builder.sep()

    # --- interfaces --------------------------------------------------------
    for interface in sorted(node.interfaces.values(), key=lambda item: natural_key(item.name)):
        builder.extend(_interface_block(node, interface))
        builder.sep()

    # --- routing -----------------------------------------------------------
    for process_id in sorted(node.ospf_processes):
        builder.extend(_ospf_block(node, process_id))
        builder.sep()

    if not switch:
        builder.add("ip forward-protocol nd")
        builder.sep()

    builder.add("ip http server" if getattr(node, "ip_http_server", False) else "no ip http server")
    builder.add(
        "ip http secure-server" if getattr(node, "ip_http_secure_server", False)
        else "no ip http secure-server"
    )
    for route in _static_route_lines(node):
        builder.add(route)
    builder.sep()

    if node.default_gateway and (switch or not node.ip_routing):
        builder.add(f"ip default-gateway {node.default_gateway}")
        builder.sep()

    # --- NTP ---------------------------------------------------------------
    ntp_block = _ntp_lines(node)
    if ntp_block:
        builder.extend(ntp_block)
        builder.sep()

    # --- control-plane -----------------------------------------------------
    builder.add("control-plane")
    builder.sep()

    # --- banners -----------------------------------------------------------
    for banner in _banner_lines(node):
        builder.add(banner)
        builder.sep()

    # --- lines -------------------------------------------------------------
    for line in _rendered_lines(node):
        builder.extend(_line_block(node, line))
        builder.sep()

    return builder.render()


# ---- credential encodings -------------------------------------------------
def _enable_secret_line(node: NodeState) -> Optional[str]:
    if node.enable_secret_hash:
        return f"enable secret {node.enable_secret_hash}"
    if node.enable_secret is not None:
        from ..crypto import type5_secret

        return f"enable secret 5 {type5_secret(node.enable_secret, node.name, 'enable')}"
    return None


def _enable_password_line(node: NodeState) -> Optional[str]:
    if node.enable_password is None:
        return None
    if node.password_encryption:
        from ..crypto import type7_encode, type7_seed

        encoded = type7_encode(node.enable_password, type7_seed(node.name, "enable-pw"))
        return f"enable password 7 {encoded}"
    return f"enable password {node.enable_password}"


def _username_line(node: NodeState, username: str) -> Optional[str]:
    privilege = node.user_privilege.get(username)
    privilege_part = f" privilege {privilege}" if privilege is not None else ""
    encoded = node.user_secret_hashes.get(username)
    if encoded:
        return f"username {username}{privilege_part} secret {encoded}"
    if username not in node.users:
        return None
    secret = node.users.get(username, "") or ""
    kind = node.user_credential_type.get(username, "secret")
    if kind == "password":
        if node.password_encryption:
            from ..crypto import type7_encode, type7_seed

            encoded = type7_encode(secret, type7_seed(node.name, "user", username))
            return f"username {username}{privilege_part} password 7 {encoded}"
        return f"username {username}{privilege_part} password 0 {secret}"
    from ..crypto import type5_secret

    hashed = type5_secret(secret, node.name, "user", username)
    return f"username {username}{privilege_part} secret 5 {hashed}"


def _line_password_line(node: NodeState, line: LineConfig) -> Optional[str]:
    if line.password is None:
        return None
    if node.password_encryption:
        from ..crypto import type7_encode, type7_seed

        encoded = type7_encode(line.password, type7_seed(node.name, "line", line.name))
        return f" password 7 {encoded}"
    return f" password {line.password}"


# ---- clock ----------------------------------------------------------------
def _clock_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    minutes = int(getattr(node, "timezone_offset_minutes", 0) or 0)
    if node.timezone_name != "UTC" or node.timezone_offset or minutes:
        # IOS 15 always prints the minutes field.
        lines.append(f"clock timezone {node.timezone_name} {node.timezone_offset} {minutes}")
    if node.summer_time_name:
        suffix = " recurring" if node.summer_time_recurring else ""
        lines.append(f"clock summer-time {node.summer_time_name}{suffix}")
    return lines


def _ssh_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    if node.ssh_version is not None:
        lines.append(f"ip ssh version {node.ssh_version}")
    if node.ip_ssh_timeout != 120:
        lines.append(f"ip ssh time-out {node.ip_ssh_timeout}")
    if node.ip_ssh_retries != 3:
        lines.append(f"ip ssh authentication-retries {node.ip_ssh_retries}")
    return lines


# ---- VLAN / VTP -----------------------------------------------------------
def _vlan_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    for vlan_id in sorted(vlan for vlan in node.vlans if vlan != 1):
        lines.append(f"vlan {vlan_id}")
        name = node.vlans[vlan_id]
        if name and name.lower() not in (f"vlan{vlan_id:04d}", f"vlan{vlan_id}"):
            lines.append(f" name {name}")
    return lines


# ---- DHCP -----------------------------------------------------------------
def _dhcp_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    for start, end in node.dhcp_excluded:
        if end and end != start:
            lines.append(f"ip dhcp excluded-address {start} {end}")
        else:
            lines.append(f"ip dhcp excluded-address {start}")
    for pool_name in sorted(node.dhcp_pools):
        pool = node.dhcp_pools[pool_name]
        lines.append(f"ip dhcp pool {pool.name}")
        if pool.network_address and pool.netmask:
            lines.append(f" network {pool.network_address} {pool.netmask}")
        if pool.default_router:
            lines.append(f" default-router {pool.default_router}")
        if pool.dns_servers:
            lines.append(" dns-server " + " ".join(pool.dns_servers))
        if pool.domain_name:
            lines.append(f" domain-name {pool.domain_name}")
        if not pool.lease_infinite and (
            pool.lease_days != 1 or pool.lease_hours or pool.lease_minutes
        ):
            lines.append(
                f" lease {pool.lease_days} {pool.lease_hours} {pool.lease_minutes}"
            )
        elif pool.lease_infinite:
            lines.append(" lease infinite")
    return lines


# ---- NTP ------------------------------------------------------------------
def _ntp_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    for key_id in sorted(node.ntp_keys):
        from ..crypto import type7_encode, type7_seed

        encoded = type7_encode(node.ntp_keys[key_id], type7_seed(node.name, "ntp", str(key_id)))
        lines.append(f"ntp authentication-key {key_id} md5 {encoded} 7")
    if node.ntp_authenticate:
        lines.append("ntp authenticate")
    for key_id in sorted(node.ntp_trusted_keys):
        lines.append(f"ntp trusted-key {key_id}")
    if node.ntp_master is not None:
        lines.append(f"ntp master {node.ntp_master}")
    for address in sorted(node.ntp_servers, key=_ip_sort_key):
        server = node.ntp_servers[address]
        suffix = f" key {server.key_id}" if server.key_id is not None else ""
        lines.append(f"ntp server {address}{suffix}")
    return lines


# ---- banners --------------------------------------------------------------
def _banner_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    for keyword, text in (
        ("motd", node.banner_motd),
        ("login", node.banner_login),
        ("exec", node.banner_exec),
    ):
        if text is not None:
            lines.append(f"banner {keyword} ^C{text}^C")
    return lines


# ---- static routes --------------------------------------------------------
def _static_route_lines(node: NodeState) -> List[str]:
    lines: List[str] = []
    for route in node.static_routes:
        parts = ["ip route", route.prefix, route.mask]
        if route.interface:
            parts.append(route.interface)
        if route.next_hop:
            parts.append(route.next_hop)
        if route.distance and route.distance != 1:
            parts.append(str(route.distance))
        if route.name:
            parts.extend(["name", route.name])
        if route.permanent:
            parts.append("permanent")
        lines.append(" ".join(parts))
    return lines


# ---- OSPF -----------------------------------------------------------------
def _ospf_block(node: NodeState, process_id: int) -> List[str]:
    process = node.ospf_processes[process_id]
    block = [f"router ospf {process_id}"]
    if process.shutdown:
        block.append(" shutdown")
    if process.router_id:
        block.append(f" router-id {process.router_id}")
    if process.log_adjacency_detail:
        block.append(" log-adjacency-changes detail")
    if process.reference_bandwidth_mbps != 100:
        block.append(f" auto-cost reference-bandwidth {process.reference_bandwidth_mbps}")
    if process.passive_default:
        block.append(" passive-interface default")
        for interface in sorted(process.non_passive_interfaces, key=natural_key):
            block.append(f" no passive-interface {interface}")
    else:
        for interface in sorted(process.passive_interfaces, key=natural_key):
            block.append(f" passive-interface {interface}")
    for network, wildcard, area in process.networks:
        block.append(f" network {network} {wildcard} area {area}")
    if process.default_information_originate:
        suffix = " always" if process.default_information_always else ""
        block.append(f" default-information originate{suffix}")
    if process.maximum_paths != 4:
        block.append(f" maximum-paths {process.maximum_paths}")
    return block


# ---- interfaces -----------------------------------------------------------
def _interface_block(node: NodeState, interface: InterfaceState) -> List[str]:
    block = [f"interface {interface.name}"]
    block.extend(_interface_body(node, interface))
    return block


def _interface_body(node: NodeState, interface: InterfaceState) -> List[str]:
    body: List[str] = []
    name = interface.name
    switch = _is_switch(node)
    is_vlan = name.startswith("Vlan")
    is_loopback = name.startswith("Loopback")
    l2_port = switch and not is_vlan and not interface.routed_port and not is_loopback

    if interface.description:
        body.append(f" description {interface.description}")

    if l2_port:
        body.extend(_switchport_body(node, interface))
        # speed / duplex / bandwidth / delay / mtu are valid on switchports too.
        body.extend(_interface_tuning(interface))
    else:
        if interface.routed_port:
            body.append(" no switchport")
        if interface.encapsulation_vlan is not None:
            native = " native" if interface.encapsulation_native else ""
            body.append(f" encapsulation dot1Q {interface.encapsulation_vlan}{native}")
        if interface.ip_address and interface.netmask:
            body.append(f" ip address {interface.ip_address} {interface.netmask}")
            for address, mask in interface.secondary_addresses:
                body.append(f" ip address {address} {mask} secondary")
        elif not is_loopback:
            body.append(" no ip address")
        for helper in interface.helper_addresses:
            body.append(f" ip helper-address {helper}")
        body.extend(_interface_tuning(interface))
        body.extend(_interface_ospf(interface))

    if interface.channel_protocol:
        # Shown whenever it was configured, with or without a channel-group.
        body.append(f" channel-protocol {interface.channel_protocol}")
    if interface.channel_group is not None:
        mode = interface.channel_mode or "active"
        body.append(f" channel-group {interface.channel_group} mode {mode}")

    body.extend(_interface_stp(node, interface, l2_port))

    if interface.shutdown:
        body.append(" shutdown")
    if not interface.cdp_enabled:
        body.append(" no cdp enable")
    return body


def _switchport_body(node: NodeState, interface: InterfaceState) -> List[str]:
    body: List[str] = []
    if interface.channel_group is not None:
        # Bundle members inherit switchport settings from the Port-channel.
        return body
    mode = interface.switchport_mode
    if interface.trunk_encapsulation:
        body.append(f" switchport trunk encapsulation {interface.trunk_encapsulation}")
    if interface.trunk_native_vlan != 1:
        body.append(f" switchport trunk native vlan {interface.trunk_native_vlan}")
    if interface.trunk_allowed_vlans is not None:
        body.append(
            f" switchport trunk allowed vlan {_compress_vlans(interface.trunk_allowed_vlans)}"
        )
    if mode == "access":
        if interface.access_vlan != 1:
            body.append(f" switchport access vlan {interface.access_vlan}")
        if interface.voice_vlan is not None:
            body.append(f" switchport voice vlan {interface.voice_vlan}")
        if interface.configured:
            body.append(" switchport mode access")
    elif mode == "trunk":
        body.append(" switchport mode trunk")
    if interface.nonegotiate:
        body.append(" switchport nonegotiate")
    body.extend(_port_security_lines(interface))
    return body


def _port_security_lines(interface: InterfaceState) -> List[str]:
    if not interface.port_security_enabled:
        return []
    lines = [" switchport port-security"]
    if interface.port_security_maximum != 1:
        lines.append(f" switchport port-security maximum {interface.port_security_maximum}")
    if interface.port_security_violation != "shutdown":
        lines.append(
            f" switchport port-security violation {interface.port_security_violation}"
        )
    if interface.port_security_sticky:
        lines.append(" switchport port-security mac-address sticky")
    for mac in getattr(interface, "port_security_sticky_macs", []) or []:
        lines.append(f" switchport port-security mac-address sticky {mac}")
    for mac in interface.port_security_macs:
        lines.append(f" switchport port-security mac-address {mac}")
    return lines


def _interface_tuning(interface: InterfaceState) -> List[str]:
    lines: List[str] = []
    if interface.bandwidth_kbps is not None:
        lines.append(f" bandwidth {interface.bandwidth_kbps}")
    if interface.delay_tens_usec is not None:
        lines.append(f" delay {interface.delay_tens_usec}")
    if interface.mtu is not None:
        lines.append(f" mtu {interface.mtu}")
    if interface.duplex and interface.duplex != "auto":
        lines.append(f" duplex {interface.duplex}")
    if interface.speed and interface.speed != "auto":
        lines.append(f" speed {interface.speed}")
    return lines


def _interface_ospf(interface: InterfaceState) -> List[str]:
    lines: List[str] = []
    pid = interface.ospf_process
    if pid is not None and interface.ospf_area is not None:
        lines.append(f" ip ospf {pid} area {interface.ospf_area}")
    if interface.ospf_cost is not None:
        lines.append(f" ip ospf cost {interface.ospf_cost}")
    if interface.ospf_priority is not None:
        lines.append(f" ip ospf priority {interface.ospf_priority}")
    if interface.ospf_hello_interval is not None:
        lines.append(f" ip ospf hello-interval {interface.ospf_hello_interval}")
    if interface.ospf_dead_interval is not None:
        lines.append(f" ip ospf dead-interval {interface.ospf_dead_interval}")
    if interface.ospf_network_type:
        lines.append(f" ip ospf network {interface.ospf_network_type}")
    return lines


def _interface_stp(node: NodeState, interface: InterfaceState, l2_port: bool) -> List[str]:
    if not l2_port:
        return []
    lines: List[str] = []
    if interface.stp_portfast is True:
        lines.append(" spanning-tree portfast")
    elif interface.stp_portfast is False:
        lines.append(" spanning-tree portfast disable")
    if interface.stp_bpduguard is True:
        lines.append(" spanning-tree bpduguard enable")
    elif interface.stp_bpduguard is False:
        lines.append(" spanning-tree bpduguard disable")
    if interface.stp_cost is not None:
        lines.append(f" spanning-tree cost {interface.stp_cost}")
    if interface.stp_port_priority is not None:
        lines.append(f" spanning-tree port-priority {interface.stp_port_priority}")
    return lines


def _render_interface_only(node: NodeState, interface: str) -> str:
    canonical = canonical_interface(interface)
    state = node.interfaces.get(canonical)
    if state is None:
        return f"interface {canonical}\n!\nend\n"
    block = _interface_block(node, state)
    return "\n".join(block + ["!", "end"]) + "\n"


# ---- lines ----------------------------------------------------------------
def _ordered_line_names(node: NodeState) -> List[str]:
    def key(name: str):
        kind = 0 if name.startswith("con") else 1 if name.startswith("aux") else 2
        numbers = [int(part) for part in name.split() if part.isdigit()]
        return (kind, numbers)

    return sorted(node.lines, key=key)


def _line_settings(line: LineConfig) -> dict:
    return {key: value for key, value in vars(line).items() if key != "name"}


def _rendered_lines(node: NodeState) -> List[LineConfig]:
    """Lines in running-config order.  Adjacent VTY blocks with the same
    settings print as one range, as IOS does (``line vty 0 1`` + ``2 4`` ->
    ``line vty 0 4``), but never across the default 0-4 block and lines 5+."""
    merged: List[Tuple[Optional[Tuple[int, int]], LineConfig]] = []
    for name in _ordered_line_names(node):
        line = node.lines[name]
        span = vty_span(name)
        if span is not None and merged and merged[-1][0] is not None:
            low, high = merged[-1][0]
            previous = merged[-1][1]
            if (
                span[0] == high + 1
                and (high < 5) == (span[0] < 5)
                and _line_settings(previous) == _line_settings(line)
            ):
                combined = copy.copy(previous)
                combined.name = vty_name(low, span[1])
                merged[-1] = ((low, span[1]), combined)
                continue
        merged.append((span, line))
    return [line for _span, line in merged]


def _line_block(node: NodeState, line: LineConfig) -> List[str]:
    block = [f"line {line.name}"]
    is_vty = line.name.startswith("vty")
    if line.exec_timeout is not None:
        block.append(f" exec-timeout {line.exec_timeout[0]} {line.exec_timeout[1]}")
    if line.access_class_in:
        block.append(f" access-class {line.access_class_in} in")
    outbound = getattr(line, "_sys_access_class_out", None)
    if outbound:
        block.append(f" access-class {outbound} out")
    password = _line_password_line(node, line)
    if password:
        block.append(password)
    if line.privilege_level is not None:
        block.append(f" privilege level {line.privilege_level}")
    if line.logging_synchronous:
        block.append(" logging synchronous")
    if line.length is not None:
        block.append(f" length {line.length}")
    if line.history_size != 10:
        block.append(f" history size {line.history_size}")
    if line.login_local:
        block.append(" login local")
    elif line.login:
        block.append(" login")
    elif is_vty:
        # VTY lines default to `login`, so IOS shows the disabled state.
        block.append(" no login")
    default_transport = set() if is_vty else {"ssh", "telnet"}
    if line.transport_input != default_transport:
        rendered = " ".join(sorted(line.transport_input)) if line.transport_input else "none"
        block.append(f" transport input {rendered}")
    elif is_vty:
        block.append(" transport input none")
    if line.transport_output is not None:
        rendered = " ".join(sorted(line.transport_output)) if line.transport_output else "none"
        block.append(f" transport output {rendered}")
    return block


# ---- misc small helpers ---------------------------------------------------
def _compress_vlans(vlans) -> str:
    numbers = sorted({int(vlan) for vlan in vlans})
    if not numbers:
        return "none"
    ranges: List[str] = []
    start = previous = numbers[0]
    for number in numbers[1:]:
        if number == previous + 1:
            previous = number
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _ip_sort_key(address: str):
    try:
        return (0, int(ipaddress.IPv4Address(address)))
    except ipaddress.AddressValueError:
        return (1, address)


def _format_config_time(node: NodeState, epoch: float) -> str:
    try:  # services.py is owned by another workstream and may be absent.
        from .. import services  # type: ignore

        formatter = getattr(services, "format_config_timestamp", None)
        if callable(formatter):
            return formatter(node, epoch)
    except Exception:  # pragma: no cover - defensive, optional dependency
        pass
    import time as _time

    return _time.strftime("%H:%M:%S UTC %a %b %d %Y", _time.gmtime(epoch))
