"""Native NetSimX grading engine.

The grader consumes an immutable simulator snapshot.  It never opens a console,
changes CLI modes, or mutates a running lab.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Dict, List, Optional, Set

import yaml

from simulator.crypto import verify_credential
from simulator.models import (
    canonical_interface,
    credential_digest,
    interface_parent,
    natural_key,
)
from simulator.runtime import SimulationSnapshot

logger = logging.getLogger("netlabx.grading")


def load_lab_definition(yaml_path: str) -> dict:
    with open(yaml_path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _normalise_banner(value: str) -> str:
    value = value.strip()
    delimiter = "^C" if value.startswith("^C") else value[:1]
    message = value[len(delimiter) :].strip()
    if delimiter and message.endswith(delimiter):
        message = message[: -len(delimiter)].strip()
    return f"banner motd {message}"


def _credential_fingerprint(value: str) -> str:
    rendered = re.match(r"^[78]\s+([0-9a-fA-F]{64})$", value)
    if rendered:
        return rendered.group(1).lower()
    return credential_digest(value)


def _normalise_credential_command(
    value: str, canonicalize: bool = True
) -> Optional[str]:
    match = re.match(r"^enable\s+secret\s+(.+)$", value, re.IGNORECASE)
    if match:
        secret = match.group(1)
        rendered = _credential_fingerprint(secret) if canonicalize else secret
        marker = "sha256 " if canonicalize else ""
        return f"enable secret {marker}{rendered}"
    match = re.match(
        r"^username\s+(\S+)\s+secret\s+(.+)$", value, re.IGNORECASE
    )
    if match:
        username, secret = match.groups()
        rendered = _credential_fingerprint(secret) if canonicalize else secret
        marker = "sha256 " if canonicalize else ""
        return f"username {username} secret {marker}{rendered}"
    match = re.match(r"^password\s+(.+)$", value, re.IGNORECASE)
    if match:
        secret = match.group(1)
        rendered = _credential_fingerprint(secret) if canonicalize else secret
        marker = "sha256 " if canonicalize else ""
        return f"password {marker}{rendered}"
    return None


def _normalise_command(
    value: str, canonicalize_credentials: bool = True
) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    match = re.match(r"^interface\s+(.+)$", value, re.IGNORECASE)
    if match:
        return "interface " + canonical_interface(match.group(1))
    match = re.match(r"^line\s+console\s+0$", value, re.IGNORECASE)
    if match:
        return "line con 0"
    match = re.match(r"^line\s+con\s+0$", value, re.IGNORECASE)
    if match:
        return "line con 0"
    match = re.match(r"^banner\s+motd\s+(.+)$", value, re.IGNORECASE)
    if match:
        return _normalise_banner(match.group(1))
    match = re.match(r"^ip\s+domain[\s-]name\s+(\S+)$", value, re.IGNORECASE)
    if match:
        # ``ip domain name`` (IOS 15 render) == ``ip domain-name`` (classic).
        return f"ip domain-name {match.group(1).lower()}"
    match = re.match(
        r"^clock\s+timezone\s+(\S+)\s+(-?\d+)(?:\s+(-?\d+))?$", value, re.IGNORECASE
    )
    if match:
        # IOS 15 always prints the minutes field; a trailing " 0" is equivalent
        # to omitting it in an authored solution.
        name, hours, minutes = match.group(1), match.group(2), match.group(3)
        if minutes is None or int(minutes) == 0:
            return f"clock timezone {name.lower()} {hours}"
        return f"clock timezone {name.lower()} {hours} {minutes}"

    credential = _normalise_credential_command(value, canonicalize_credentials)
    if credential is not None:
        return credential

    # Command keywords are case-insensitive; the listed arguments are not.
    sensitive_patterns = (
        (r"^hostname\s+(.+)$", "hostname {}"),
        (r"^name\s+(.+)$", "name {}"),
        (
            r"^ntp\s+authentication-key\s+(\d+)\s+md5\s+(.+)$",
            "ntp authentication-key {} md5 {}",
        ),
        (r"^ip\s+dhcp\s+pool\s+(.+)$", "ip dhcp pool {}"),
    )
    for pattern, template in sensitive_patterns:
        match = re.match(pattern, value, re.IGNORECASE)
        if match:
            return template.format(*match.groups())
    return value.lower()


def _is_parent(command: str) -> bool:
    return bool(
        re.match(
            r"^(?:interface\s+|vlan\s+\d+$|router\s+ospf\s+\d+$|"
            r"ip\s+dhcp\s+pool\s+|line\s+)",
            command,
            re.IGNORECASE,
        )
    )


def _is_child(parent: str, command: str) -> bool:
    lower = command.lower()
    if parent.startswith("interface "):
        return lower.startswith(
            (
                "ip address ",
                "no ip address",
                "shutdown",
                "no shutdown",
                "encapsulation ",
                "no encapsulation",
                "switchport ",
                "no switchport ",
                "channel-group ",
                "no channel-group",
            )
        )
    if parent.startswith("vlan "):
        return lower.startswith(("name ", "no name"))
    if parent.startswith("router ospf "):
        return lower.startswith(("network ", "no network "))
    if parent.startswith("ip dhcp pool "):
        return lower.startswith(("network ", "default-router ", "dns-server "))
    if parent.startswith("line "):
        return lower.startswith(
            ("password ", "login", "no login", "exec-timeout ", "transport input ")
        )
    return False


def normalise_config(
    config_text: str, canonicalize_credentials: bool = True
) -> Set[str]:
    """Convert config text into context-aware required command strings."""
    result: Set[str] = set()
    current_parent: Optional[str] = None
    skip_prefixes = (
        "building configuration",
        "current configuration",
        "last configuration change",
        "version ",
        "boot-start-marker",
        "boot-end-marker",
        "ntp clock-period",
    )
    for raw_line in config_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("!") or stripped.lower() == "end":
            continue
        if any(stripped.lower().startswith(prefix) for prefix in skip_prefixes):
            continue
        command = _normalise_command(
            stripped, canonicalize_credentials=canonicalize_credentials
        )
        if _is_parent(command):
            current_parent = command
            result.add(command)
            continue
        if (raw_line[:1].isspace() or (current_parent and _is_child(current_parent, command))) and current_parent:
            result.add(f"{current_parent} -> {command}")
            continue
        current_parent = None
        result.add(command)
    return result


def _canonicalize_display_entry(entry: str) -> str:
    """Convert a display-safe expected entry to its comparison representation."""
    parent, separator, command = entry.rpartition(" -> ")
    credential = _normalise_credential_command(command, canonicalize=True)
    if credential is None:
        return entry
    return f"{parent}{separator}{credential}" if separator else credential


def _canonical_line_name(name: str) -> str:
    """Normalise a line identifier the way :meth:`NodeState.line` stores it."""
    canonical = re.sub(r"\s+", " ", name.strip().lower())
    return canonical.replace("console", "con")


def _expected_plaintext(value: str) -> str:
    """Return the plaintext a solution expects, tolerating an explicit ``0 ``."""
    value = value.strip()
    match = re.match(r"^0\s+(.+)$", value)
    return match.group(1) if match else value


def _secret_matches(stored: Optional[str], expected: str) -> bool:
    """True when a stored credential equals, or verifies, the expected plaintext."""
    if stored is None:
        return False
    if stored == expected:
        return True
    return verify_credential(expected, encoded=stored)


def _credential_satisfied(node, parent: str, command: str) -> bool:
    """Verify a required credential line against the snapshot node directly.

    IOS renders ``enable secret``/``username ... secret`` as type 5 and line
    passwords / NTP keys as type 7, so a verbatim text match against the
    rendered config is impossible.  The authored solution carries the plaintext,
    which we verify against the stored (possibly hashed) value instead.
    """
    match = re.match(r"^enable\s+(?:secret|password)\s+(.+)$", command, re.IGNORECASE)
    if match:
        return node.verify_enable(_expected_plaintext(match.group(1)))
    match = re.match(
        r"^username\s+(\S+)\s+(?:secret|password)\s+(.+)$", command, re.IGNORECASE
    )
    if match:
        return node.verify_user(match.group(1), _expected_plaintext(match.group(2)))
    match = re.match(
        r"^ntp\s+authentication-key\s+(\d+)\s+md5\s+(.+)$", command, re.IGNORECASE
    )
    if match:
        key_id = int(match.group(1))
        expected = _expected_plaintext(re.sub(r"\s+7$", "", match.group(2)))
        return _secret_matches(node.ntp_keys.get(key_id), expected)
    if parent.lower().startswith("line "):
        match = re.match(r"^password\s+(.+)$", command, re.IGNORECASE)
        if match:
            line = node.lines.get(_canonical_line_name(parent.split(" ", 1)[1]))
            return line is not None and _secret_matches(
                line.password, _expected_plaintext(match.group(1))
            )
    return False


def _requirement_satisfied(node, token: str, display: str) -> bool:
    """True when the snapshot node satisfies a required line that the IOS
    renderer legitimately does not reproduce verbatim: credentials (type 5/7),
    ``no shutdown`` on an interface that is not administratively down, and VLANs
    that VTP server/client mode hides from the running-config."""
    head, separator, leaf = display.rpartition(" -> ")
    parent = head if separator else ""
    command = leaf.strip()

    if parent.lower().startswith("interface ") and command.lower() in (
        "no shutdown",
        "no shut",
    ):
        name = canonical_interface(parent.split(" ", 1)[1])
        interface = node.interfaces.get(name)
        return interface is not None and not interface.shutdown

    if not separator:
        match = re.match(r"^vlan\s+(\d+)$", command, re.IGNORECASE)
        if match:
            return int(match.group(1)) in node.vlans

    return _credential_satisfied(node, parent, command)


class BaseGrader:
    def __init__(
        self,
        node_name: str,
        node_config: dict,
        solution_path: str,
        snapshot: Optional[SimulationSnapshot] = None,
    ) -> None:
        self.node_name = node_name
        self.node_config = node_config
        self.solution_path = solution_path
        self.snapshot = snapshot

    def sanitize_config(self, config_text: str) -> set:
        """Compatibility name retained for callers of the previous grader."""
        return normalise_config(config_text)

    def _operational_requirements(self, expected: Set[str]) -> List[str]:
        if self.snapshot is None or self.node_name not in self.snapshot.nodes:
            return []
        missing: List[str] = []
        network = self.snapshot.network()
        interfaces = set()
        for line in expected:
            match = re.match(
                r"^(interface\s+\S+) -> (?:ip address|encapsulation dot1q)", line
            )
            if match:
                interfaces.add(match.group(1).split(" ", 1)[1])
        for interface in sorted(interfaces, key=natural_key):
            if not network.interface_oper_up(self.node_name, interface):
                status, protocol = network.line_state(self.node_name, interface)
                if status == "administratively down":
                    missing.append(
                        f"interface {interface} -> no shutdown (administratively down)"
                    )
                else:
                    # Up/down or down/down: the cause is the cable peer, the
                    # switch port or the parent interface, not this command.
                    missing.append(
                        f"interface {interface} is operationally down "
                        f"({status}, line protocol is {protocol})"
                    )

        if any(line.startswith("router ospf ") for line in expected):
            if not network.ospf_neighbors(self.node_name):
                missing.append("OSPF: no FULL neighbor adjacency")

        if any(line.startswith("ntp server ") for line in expected):
            info = network.ntp_info(self.node_name)
            if not info["synchronized"]:
                missing.append(
                    "NTP: clock is not synchronized with an authenticated server"
                )

        groups: Dict[int, Set[str]] = {}
        for line in expected:
            match = re.match(
                r"^interface\s+(\S+) -> channel-group\s+(\d+)\s+mode\s+active$",
                line,
            )
            if match:
                interface = canonical_interface(match.group(1))
                if (
                    interface_parent(interface) is None
                    and not interface.startswith(("Port-channel", "Vlan", "Loopback"))
                ):
                    groups.setdefault(int(match.group(2)), set()).add(interface)
                continue
            match = re.search(r"channel-group\s+(\d+)\s+mode\s+active$", line)
            if match:
                groups.setdefault(int(match.group(1)), set())
        for group in sorted(groups):
            status = network.channel_status(self.node_name, group)
            if not status["formed"]:
                missing.append(f"EtherChannel {group}: LACP peer is not formed")
            for interface in sorted(groups[group], key=natural_key):
                if status["members"].get(interface) is not True:
                    missing.append(
                        f"EtherChannel {group}: expected member {interface} is not bundled/up"
                    )

        ssh_markers = (
            "ip ssh version 2",
            "login local",
            "transport input ssh",
        )
        if all(any(marker in line for line in expected) for marker in ssh_markers):
            node = self.snapshot.nodes[self.node_name]
            if not node.domain_name or node.rsa_bits is None:
                missing.append("SSH: domain name and generated RSA keys are required")
            elif node.rsa_bits != 2048:
                missing.append(
                    f"SSH: RSA modulus must be exactly 2048 bits (configured {node.rsa_bits})"
                )
        return missing

    def grade(self) -> dict:
        if not os.path.exists(self.solution_path):
            kind = str(self.node_config.get("kind", "")).lower()
            if self.snapshot is not None and self.node_name in self.snapshot.nodes:
                kind = self.snapshot.nodes[self.node_name].kind
            if kind == "host" or str(self.node_config.get("device_type", "")).lower() == "vpcs":
                return {
                    "node": self.node_name,
                    "passed": True,
                    "missing_lines": [],
                    "error": "No solution file found for host. Skipping.",
                }
            return {
                "node": self.node_name,
                "passed": False,
                "missing_lines": [f"Required solution file is missing: {os.path.basename(self.solution_path)}"],
                "error": "Required solution file is missing.",
            }
        if self.snapshot is None:
            return {
                "node": self.node_name,
                "passed": False,
                "missing_lines": ["Simulator snapshot is required"],
                "error": "Simulator snapshot is required.",
            }
        if self.node_name not in self.snapshot.nodes:
            return {
                "node": self.node_name,
                "passed": False,
                "missing_lines": [f"Node {self.node_name} is absent from the simulator"],
                "error": "Simulator node missing.",
            }

        with open(self.solution_path, "r", encoding="utf-8") as handle:
            solution_text = handle.read()
        expected = self.sanitize_config(solution_text)
        expected_display = normalise_config(
            solution_text, canonicalize_credentials=False
        )
        display_by_canonical = {
            _canonicalize_display_entry(line): line for line in expected_display
        }
        actual = self.sanitize_config(self.snapshot.running_config(self.node_name))
        node = self.snapshot.nodes[self.node_name]
        missing: List[str] = []
        for token in sorted(expected):
            if token in actual:
                continue
            display = display_by_canonical.get(token, token)
            if _requirement_satisfied(node, token, display):
                continue
            missing.append(display)
        for requirement in self._operational_requirements(expected):
            if requirement not in missing:
                missing.append(requirement)
        return {
            "node": self.node_name,
            "passed": not missing,
            "missing_lines": missing,
            "error": "",
        }


class IOSGrader(BaseGrader):
    """Name retained for compatibility; canonical snapshots include VLAN state."""


def get_grader_for_device(
    node_name: str,
    node_config: dict,
    solution_path: str,
    snapshot: Optional[SimulationSnapshot] = None,
) -> BaseGrader:
    device_type = str(node_config.get("device_type", ""))
    kind = str(node_config.get("kind", ""))
    if "cisco" in device_type or kind in {"router", "switch"}:
        return IOSGrader(node_name, node_config, solution_path, snapshot=snapshot)
    return BaseGrader(node_name, node_config, solution_path, snapshot=snapshot)


class BehavioralGrader:
    def __init__(
        self,
        node_name: str,
        node_config: dict,
        checks: list,
        snapshot: Optional[SimulationSnapshot] = None,
    ) -> None:
        self.node_name = node_name
        self.node_config = node_config
        self.checks = checks
        self.snapshot = snapshot

    def _target_addresses(self, value: object) -> List[str]:
        if self.snapshot is None:
            return []
        target = str(value or "").strip()
        if not target:
            return []
        network = self.snapshot.network()
        if target in self.snapshot.nodes:
            endpoints = sorted(
                (
                    endpoint
                    for endpoint in network.ip_endpoints()
                    if endpoint.node == target
                ),
                key=lambda item: (int(item.address), natural_key(item.interface)),
            )
            return [str(endpoint.address) for endpoint in endpoints]
        try:
            address = ipaddress.IPv4Address(target)
        except ipaddress.AddressValueError:
            return []
        return [str(address)] if network.find_ip(str(address)) is not None else []

    def _check_ping(self, check: dict) -> Optional[str]:
        target = str(check.get("target", "")).strip()
        if not target:
            return "missing required target"
        try:
            target = str(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError:
            return "target is not a valid IPv4 address"
        if not self.snapshot.can_reach(self.node_name, target):
            return f"target {target} is unreachable"
        return None

    def _check_dhcp(self, check: dict) -> Optional[str]:
        node = self.snapshot.nodes[self.node_name]
        if node.kind != "host":
            return "DHCP checks require a host node"
        interfaces = sorted(
            (
                interface
                for interface in node.interfaces.values()
                if interface_parent(interface.name) is None
                and not interface.name.startswith(("Vlan", "Loopback", "Port-channel"))
            ),
            key=lambda item: natural_key(item.name),
        )
        if not interfaces:
            return "host has no interface"
        interface = interfaces[0]
        if not node.dhcp_enabled or interface.address_source != "dhcp":
            return "host interface did not learn its address through DHCP"
        if not self.snapshot.network().interface_oper_up(node.name, interface.name):
            return "DHCP host interface is not operationally up"
        try:
            lease = ipaddress.IPv4Interface(
                f"{interface.ip_address}/{interface.netmask}"
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return "DHCP lease does not contain a valid IPv4 address and mask"
        if lease.ip.is_unspecified or lease.ip.is_multicast:
            return "DHCP lease is not a valid unicast host address"
        if lease.network.prefixlen < 31 and lease.ip in {
            lease.network.network_address,
            lease.network.broadcast_address,
        }:
            return "DHCP lease is not a usable host address"
        if not node.default_gateway:
            return "DHCP did not learn a default gateway"
        try:
            learned_gateway = ipaddress.IPv4Address(node.default_gateway)
        except ipaddress.AddressValueError:
            return "DHCP learned an invalid default gateway"
        if learned_gateway.is_unspecified or learned_gateway.is_multicast:
            return "DHCP learned an invalid default gateway"
        if learned_gateway not in lease.network:
            return "DHCP default gateway is outside the learned subnet"
        if lease.network.prefixlen < 31 and learned_gateway in {
            lease.network.network_address,
            lease.network.broadcast_address,
        }:
            return "DHCP learned an invalid default gateway"

        expected_network = check.get("network")
        if expected_network:
            try:
                required_network = ipaddress.IPv4Network(
                    str(expected_network), strict=False
                )
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                return "check defines an invalid DHCP network"
            if lease.network != required_network:
                return (
                    f"DHCP lease is on {lease.network.with_prefixlen}, expected "
                    f"{required_network.with_prefixlen}"
                )
        expected_gateway = check.get("gateway")
        if expected_gateway:
            try:
                required_gateway = ipaddress.IPv4Address(str(expected_gateway))
            except ipaddress.AddressValueError:
                return "check defines an invalid DHCP gateway"
            if learned_gateway != required_gateway:
                return (
                    f"DHCP learned gateway {learned_gateway}, expected "
                    f"{required_gateway}"
                )
        return None

    def _check_ping_node(self, check: dict) -> Optional[str]:
        target_node = str(check.get("target_node", "")).strip()
        if not target_node:
            return "missing required target_node"
        if target_node not in self.snapshot.nodes:
            return f"target_node '{target_node}' does not exist"
        network = self.snapshot.network()
        addresses = self._target_addresses(target_node)
        if not addresses:
            return f"target_node '{target_node}' has no active IPv4 address"
        if not any(network.can_reach(self.node_name, address) for address in addresses):
            return f"target_node '{target_node}' is unreachable"
        return None

    def _check_ssh(self, check: dict) -> Optional[str]:
        target = str(check.get("target", "")).strip()
        username = str(check.get("username", "")).strip()
        password = check.get("password")
        if not target:
            return "missing required target"
        if not username:
            return "missing required username"
        if not isinstance(password, str) or not password:
            return "missing required password"
        addresses = self._target_addresses(target)
        if not addresses:
            return f"target '{target}' has no active IPv4 address"
        network = self.snapshot.network()
        reasons: List[str] = []
        for address in addresses:
            allowed, reason = network.ssh_authenticate(
                self.node_name, username, password, address
            )
            if allowed:
                return None
            reasons.append(reason)
        return reasons[0] if reasons else "SSH authentication failed"

    def _check_telnet_refused(self, check: dict) -> Optional[str]:
        target = str(check.get("target", "")).strip()
        if not target:
            return "missing required target"
        addresses = self._target_addresses(target)
        if not addresses:
            return f"target '{target}' has no active IPv4 address"
        network = self.snapshot.network()
        reachable = False
        for address in addresses:
            if not network.can_reach(self.node_name, address):
                continue
            reachable = True
            allowed, reason = network.telnet_allowed(self.node_name, address)
            if not allowed and reason == "Connection refused by remote host":
                return None
            if allowed:
                return "Telnet is permitted by the target VTY transport policy"
        if not reachable:
            return "target is unreachable, so Telnet refusal was not verified"
        return "Telnet was not specifically refused by VTY transport policy"

    def grade(self) -> dict:
        missing: List[str] = []
        if self.snapshot is None:
            missing.append("Behavioral grading requires a simulator snapshot")
        else:
            handlers = {
                "ping": self._check_ping,
                "dhcp": self._check_dhcp,
                "ping_node": self._check_ping_node,
                "ssh": self._check_ssh,
                "telnet_refused": self._check_telnet_refused,
            }
            for check in self.checks:
                check_type = str(check.get("type", "")).strip().lower()
                description = check.get("description") or check_type or "unnamed check"
                handler = handlers.get(check_type)
                if handler is None:
                    missing.append(
                        f"Unsupported behavioral check type '{check.get('type', '')}': {description}"
                    )
                    continue
                reason = handler(check)
                if reason:
                    missing.append(f"Behavioral check failed: {description} ({reason}).")
        return {
            "node": self.node_name,
            "passed": not missing,
            "missing_lines": missing,
            "error": "" if not missing else "Behavioral verification failed.",
        }


def grade_lab(
    yaml_path: str,
    skip_tasks: list = None,
    lab_dir: str = None,
    snapshot: Optional[SimulationSnapshot] = None,
) -> dict:
    """Grade config subsets and behavior against one immutable snapshot."""
    del skip_tasks  # Current manifests do not map checks/config to task IDs.
    lab_definition = load_lab_definition(yaml_path)
    lab_info = lab_definition["lab"]
    if not lab_dir:
        lab_dir = os.path.dirname(os.path.abspath(yaml_path))

    node_configs = {node["name"]: node for node in lab_info.get("nodes", [])}
    checks_by_node = {}
    unknown_node_checks = []
    for check in lab_info.get("checks", []) or []:
        node_name = check.get("node")
        if node_name not in node_configs:
            unknown_node_checks.append(check)
        else:
            checks_by_node.setdefault(node_name, []).append(check)

    results = []
    for node_name, node_config in node_configs.items():
        solution_path = os.path.join(lab_dir, f"solution_{node_name}.cfg")
        grader = get_grader_for_device(
            node_name, node_config, solution_path, snapshot=snapshot
        )
        result = grader.grade()
        result.setdefault("missing_lines", [])
        result.setdefault("error", "")
        if node_name in checks_by_node:
            behavioral = BehavioralGrader(
                node_name,
                node_config,
                checks_by_node[node_name],
                snapshot=snapshot,
            ).grade()
            result["missing_lines"].extend(behavioral["missing_lines"])
            result["passed"] = bool(result["passed"] and behavioral["passed"])
            if behavioral["error"]:
                result["error"] = " ".join(
                    value for value in (result.get("error", ""), behavioral["error"]) if value
                )
        results.append(result)

    for check in unknown_node_checks:
        node_name = str(check.get("node", ""))
        results.append(
            {
                "node": node_name,
                "passed": False,
                "missing_lines": [
                    f"Behavioral check references unknown node '{node_name}'"
                ],
                "error": "Invalid lab check definition.",
            }
        )

    passed = bool(results) and all(result["passed"] for result in results)
    return {
        "lab_id": lab_info["id"],
        "lab_title": lab_info["title"],
        "total_earned": 100 if passed else 0,
        "total_possible": 100,
        "percentage": 100 if passed else 0,
        "passed": passed,
        "node_results": results,
    }
