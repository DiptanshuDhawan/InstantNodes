"""Native NetSimX grading engine.

The grader reads one immutable simulator snapshot.  It never opens a console,
changes CLI modes or mutates a running lab.

How a lab is graded
-------------------
A lab becomes a list of *requirements*.  Each requirement belongs to one node
and, when the lab maps it, to one task:

* Configuration.  Every line of ``solution_<node>.cfg`` must be in the node's
  running configuration; child lines keep their parent (``interface X -> ip
  address ...``).  Lines that IOS does not show verbatim are checked against
  node state: credentials (type 5/7, and ``secret`` vs ``password``),
  ``no shutdown``, VLANs hidden by VTP server mode, ``ntp server`` (a line
  without ``key`` accepts any key) and ``line vty`` ranges (however the range
  is split into blocks).
* State implied by the solution.  Interfaces with an address or 802.1Q
  encapsulation are up/up, ``router ospf`` has a FULL neighbor, ``ntp server``
  is synchronized, ``channel-group N mode active`` members are bundled, and
  the SSH lines (``ip ssh version 2``, ``login local``, ``transport input ssh``)
  need a domain name and 2048-bit RSA keys.
* Behavior from the ``checks`` in ``lab.yaml``: ``ping``, ``ping_node``,
  ``dhcp``, ``ssh`` and ``telnet_refused``.

Tasks.  A ``! task N`` comment in a solution file assigns the following lines
to task N, up to the next marker; a check's ``task`` field assigns the check;
a state requirement follows the last solution line that implies it.  Anything
else is listed under "Other requirements".

Score.  A task passes when all of its requirements pass.  Each graded task is
worth its ``points`` (default 1).  The percentage is the share of points of the
passed tasks, rounded down, and it is 100 only when every requirement passes.

The report keeps its original shape (``node_results`` with ``missing_lines``)
and adds ``tasks`` (per-task results with student-facing findings) and
``summary``.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

import yaml

from simulator.crypto import verify_credential
from simulator.models import (
    canonical_interface,
    credential_digest,
    interface_parent,
    natural_key,
)
from simulator.ospf import normalise_network_statement
from simulator.runtime import SimulationSnapshot

logger = logging.getLogger("netlabx.grading")

OTHER_TASK_TITLE = "Other requirements"

#: ``! task 3`` / ``! Task 3 - Configure VLANs`` in a solution file.
_TASK_MARKER = re.compile(r"^!\s*task\s*[:#]?\s*([0-9]+|[A-Za-z][\w.]*)\b", re.IGNORECASE)
_BANNER = re.compile(r"^banner\s+(motd|login|exec)\b\s*(.*)$", re.IGNORECASE)
_OSPF_NETWORK = re.compile(
    r"^network\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+area\s+(\S+)$",
    re.IGNORECASE,
)
_VTY_BLOCK = re.compile(r"^line\s+vty\s+(\d+)(?:\s+(\d+))?$", re.IGNORECASE)
_SKIP_PREFIXES = (
    "building configuration",
    "current configuration",
    "last configuration change",
    "version ",
    "boot-start-marker",
    "boot-end-marker",
    "ntp clock-period",
)

#: Commands whose currently configured value is shown next to a missing line
#: ("found instead").  Matched against the start of the comparison form.
_HINT_KEYS = tuple(
    re.compile(pattern + r"(?:\s|$)")
    for pattern in (
        r"ip address",
        r"ip default-gateway",
        r"ip domain[ -]name",
        r"ip ssh version",
        r"ip route \S+ \S+",
        r"ip helper-address",
        r"ip ospf \d+ area",
        r"ip ospf (?:cost|priority|hello-interval|dead-interval|network)",
        r"switchport mode",
        r"switchport access vlan",
        r"switchport trunk encapsulation",
        r"switchport trunk allowed vlan",
        r"switchport trunk native vlan",
        r"switchport voice vlan",
        r"switchport port-security (?:maximum|violation)",
        r"encapsulation dot1q",
        r"channel-group",
        r"channel-protocol",
        r"spanning-tree mode",
        r"spanning-tree vlan \S+ priority",
        r"description",
        r"speed",
        r"duplex",
        r"exec-timeout",
        r"transport input",
        r"login",
        r"privilege level",
        r"network",
        r"default-router",
        r"dns-server",
        r"lease",
        r"domain-name",
        r"router-id",
        r"hostname",
        r"banner (?:motd|login|exec)",
        r"clock timezone",
        r"clock summer-time",
        r"ntp master",
        r"ntp server",
        r"ntp trusted-key",
        r"vtp mode",
        r"vtp domain",
        r"name",
    )
)

_MEMBER_FLAGS = {
    "s": "suspended: the other end does not negotiate a matching LACP bundle",
    "I": "stand-alone: no LACP partner answered",
    "D": "down",
    "H": "hot-standby",
    "w": "waiting to be aggregated",
}


def load_lab_definition(yaml_path: str) -> dict:
    with open(yaml_path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


# --------------------------------------------------------------------------- #
# Configuration text -> comparable lines                                      #
# --------------------------------------------------------------------------- #
def _normalise_banner(value: str) -> str:
    value = value.strip()
    delimiter = "^C" if value.startswith("^C") else value[:1]
    message = value[len(delimiter) :].strip()
    if delimiter and message.endswith(delimiter):
        message = message[: -len(delimiter)].strip()
    return f"banner motd {message}"


def _banner_message(rest: str, following: Sequence[str]) -> Tuple[str, int]:
    """Text of ``banner <kind> <rest>`` and how many following lines it spans.

    The first character (or ``^C``) of ``rest`` is the delimiter; a banner that
    does not close on its first line continues until the delimiter recurs.
    Whitespace and line breaks inside the text are compared as single spaces.
    """
    rest = rest.strip()
    if not rest:
        return "", 0
    delimiter = "^C" if rest.startswith("^C") else rest[0]
    body = rest[len(delimiter) :]
    position = body.find(delimiter)
    if position != -1:
        return " ".join(body[:position].split()), 0
    parts = [body]
    used = 0
    for line in following:
        used += 1
        position = line.find(delimiter)
        if position != -1:
            parts.append(line[:position])
            break
        parts.append(line)
    return " ".join(" ".join(parts).split()), used


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


def _normalise_area(value: str) -> str:
    try:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
            return str(int(ipaddress.IPv4Address(value)))
        if value.isdigit():
            return str(int(value))
    except (ipaddress.AddressValueError, ValueError):
        pass
    return value.lower()


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
    match = _OSPF_NETWORK.match(value)
    if match:
        # IOS clears the host bits and turns a subnet mask into wildcard bits.
        address, bits, area = match.groups()
        try:
            address, bits = normalise_network_statement(address, bits)
        except ValueError:
            pass
        return f"network {address} {bits} area {_normalise_area(area)}"

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


def _display_command(value: str) -> str:
    """The line as the student would type it: case kept, names canonical."""
    value = re.sub(r"\s+", " ", value.strip())
    match = re.match(r"^interface\s+(.+)$", value, re.IGNORECASE)
    if match:
        return "interface " + canonical_interface(match.group(1))
    if re.match(r"^line\s+con(?:sole)?\s+0$", value, re.IGNORECASE):
        return "line con 0"
    return value


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


@dataclass
class ConfigLine:
    """One configuration command with its parent context."""

    token: str  # comparison key; "parent -> command" for child lines
    command: str  # comparison form of the command itself
    text: str  # display form of the command (case kept)
    parent: Optional[str] = None  # comparison form of the parent
    parent_text: Optional[str] = None  # display form of the parent
    is_parent: bool = False
    task: Optional[str] = None
    index: int = 0

    @property
    def display(self) -> str:
        return f"{self.parent_text} -> {self.text}" if self.parent_text else self.text


def parse_config(
    config_text: str, canonicalize_credentials: bool = True, task_markers: bool = False
) -> List[ConfigLine]:
    """Parse IOS configuration text into context-aware lines.

    With ``task_markers`` a ``! task N`` comment assigns the lines after it to
    task N (an unindented marker also closes the current block).
    """
    result: List[ConfigLine] = []
    raw_lines = config_text.splitlines()
    parent: Optional[str] = None
    parent_text: Optional[str] = None
    task: Optional[str] = None
    index = 0
    while index < len(raw_lines):
        raw_line = raw_lines[index]
        position = index
        index += 1
        stripped = raw_line.strip()
        indented = raw_line[:1].isspace()
        if stripped.startswith("!"):
            marker = _TASK_MARKER.match(stripped) if task_markers else None
            if marker:
                task = marker.group(1)
                if not indented:
                    parent = parent_text = None
            continue
        if not stripped or stripped.lower() == "end":
            continue
        lowered = stripped.lower()
        if any(lowered.startswith(prefix) for prefix in _SKIP_PREFIXES):
            continue
        banner = _BANNER.match(stripped)
        if banner:
            message, used = _banner_message(banner.group(2), raw_lines[index:])
            index += used
            command = f"banner {banner.group(1).lower()} {message}".rstrip()
            parent = parent_text = None
            result.append(
                ConfigLine(token=command, command=command, text=command, task=task, index=position)
            )
            continue
        command = _normalise_command(stripped, canonicalize_credentials)
        text = _display_command(stripped)
        if _is_parent(command):
            parent, parent_text = command, text
            result.append(
                ConfigLine(
                    token=command, command=command, text=text, is_parent=True,
                    task=task, index=position,
                )
            )
            continue
        if parent and (indented or _is_child(parent, command)):
            result.append(
                ConfigLine(
                    token=f"{parent} -> {command}", command=command, text=text,
                    parent=parent, parent_text=parent_text, task=task, index=position,
                )
            )
            continue
        parent = parent_text = None
        result.append(
            ConfigLine(token=command, command=command, text=text, task=task, index=position)
        )
    return result


def normalise_config(
    config_text: str, canonicalize_credentials: bool = True
) -> Set[str]:
    """Convert config text into context-aware required command strings."""
    return {line.token for line in parse_config(config_text, canonicalize_credentials)}


def _vty_range(command: Optional[str]) -> Optional[Tuple[int, int]]:
    match = _VTY_BLOCK.match(command or "")
    if not match:
        return None
    first = int(match.group(1))
    last = int(match.group(2)) if match.group(2) is not None else first
    return (min(first, last), max(first, last))


class RunningConfig:
    """A node's running configuration, indexed for requirement checks."""

    def __init__(self, text: str) -> None:
        self.lines = parse_config(text)
        self.tokens: Set[str] = {line.token for line in self.lines}
        self.by_scope: Dict[Optional[str], List[ConfigLine]] = {}
        blocks: Dict[str, Tuple[Tuple[int, int], Set[str]]] = {}
        for line in self.lines:
            self.by_scope.setdefault(line.parent, []).append(line)
            span = _vty_range(line.command) if line.is_parent else None
            if span is not None:
                blocks[line.command] = (span, set())
            elif line.parent in blocks:
                blocks[line.parent][1].add(line.command)
        self.vty_blocks: List[Tuple[Tuple[int, int], Set[str]]] = list(blocks.values())

    def vty_covers(self, block: str, command: Optional[str] = None) -> bool:
        """True when VTY lines ``block`` exist and every block covering part of
        the range has ``command`` (IOS splits ``line vty 0 15`` into 0-4 and
        5-15, and keeps a partly changed range in separate blocks)."""
        wanted = _vty_range(block)
        if wanted is None:
            return False
        first, last = wanted
        covered: Set[int] = set()
        for (low, high), commands in self.vty_blocks:
            low, high = max(low, first), min(high, last)
            if low > high:
                continue
            if command is not None and command not in commands:
                return False
            covered.update(range(low, high + 1))
        return covered >= set(range(first, last + 1))

    def related(self, line: ConfigLine) -> List[str]:
        """Configured lines in the same scope that set what ``line`` sets
        (shown as "currently configured" next to a missing line)."""
        if line.is_parent:
            return []
        key = None
        for pattern in _HINT_KEYS:
            match = pattern.match(line.command)
            if match:
                key = match.group(0).strip()
                break
        if key is None:
            return []
        found = []
        for candidate in self.by_scope.get(line.parent, []):
            if candidate.is_parent or candidate.token == line.token:
                continue
            if candidate.command == key or candidate.command.startswith(key + " "):
                found.append(candidate.text)
        return found


# --------------------------------------------------------------------------- #
# Requirements                                                                #
# --------------------------------------------------------------------------- #
@dataclass
class Requirement:
    """One graded item; failed ones become ``missing_lines`` and findings."""

    node: str
    kind: str  # config | state | check | error
    line: str  # the ``missing_lines`` entry when it fails
    task: Optional[str] = None
    passed: bool = False
    message: str = ""
    expected: List[str] = field(default_factory=list)
    found: List[str] = field(default_factory=list)
    title: str = ""
    token: str = ""
    #: Config lines merge into one finding per block (``interface X``) or per
    #: node (global lines) unless they carry their own message.
    block: Optional[str] = None
    block_missing: bool = False
    mergeable: bool = False
    #: ``(node, solution prefix)`` whose lines this state also depends on
    #: (e.g. the cable peer's interface): the requirement moves to the latest
    #: of those tasks, so a task does not fail for work another task asks for.
    depends: List[Tuple[str, str]] = field(default_factory=list)
    #: ``(node, token)`` of config lines that explain this failure; when one of
    #: them failed too, this requirement is dropped as a duplicate.
    consequence_of: List[Tuple[str, str]] = field(default_factory=list)


class _CheckDefinitionError(ValueError):
    """A ``checks`` entry in lab.yaml is incomplete or invalid."""


def _task_key(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _sentence(text: str) -> str:
    text = text.strip()
    if not text:
        return text
    text = text[0].upper() + text[1:]
    return text if text.endswith((".", "!", "?", ":")) else text + "."


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


def _line_configs(node, parent: str) -> list:
    """LineConfig objects covering ``line ...`` (all VTY blocks in the range)."""
    name = _canonical_line_name(parent.split(" ", 1)[1]) if " " in parent else ""
    span = _vty_range(f"line {name}")
    if span is None:
        line = node.lines.get(name)
        return [line] if line is not None else []
    found = []
    for key, line in node.lines.items():
        other = _vty_range(f"line {key}")
        if other is not None and other[0] <= span[1] and span[0] <= other[1]:
            found.append(line)
    return found


def _check_credential(node, parent: str, command: str) -> Optional[Tuple[bool, str]]:
    """Verify a credential line against node state.

    IOS renders ``enable secret``/``username ... secret`` as type 5 and line
    passwords / NTP keys as type 7, so the plaintext in the solution is
    verified against the stored (possibly hashed) value.  ``secret`` and
    ``password`` are different commands: one does not satisfy the other.
    Returns ``None`` for lines that are not credentials, else
    ``(passed, message)``.
    """
    match = re.match(r"^enable\s+secret\s+(.+)$", command, re.IGNORECASE)
    if match:
        expected = _expected_plaintext(match.group(1))
        if node.enable_secret is None and not node.enable_secret_hash:
            if node.enable_password is not None:
                return False, "An enable password is set, but the task asks for an enable secret."
            return False, "No enable secret is configured."
        if verify_credential(
            expected, plaintext=node.enable_secret, encoded=node.enable_secret_hash
        ):
            return True, ""
        return False, "The enable secret is set, but not to the required password."
    match = re.match(r"^enable\s+password\s+(.+)$", command, re.IGNORECASE)
    if match:
        if node.enable_password is None:
            return False, "No enable password is configured."
        if _secret_matches(node.enable_password, _expected_plaintext(match.group(1))):
            return True, ""
        return False, "The enable password is set, but not to the required password."
    match = re.match(
        r"^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+(secret|password)\s+(.+)$",
        command,
        re.IGNORECASE,
    )
    if match:
        username, privilege, kind, value = match.groups()
        kind = kind.lower()
        if not node.user_exists(username):
            return False, f"User {username} does not exist."
        actual_kind = (
            "secret"
            if username in node.user_secret_hashes
            else node.user_credential_type.get(username, "secret")
        )
        if actual_kind != kind:
            return False, (
                f"User {username} is configured with `{actual_kind}`, "
                f"but the task asks for `{kind}`."
            )
        if not node.verify_user(username, _expected_plaintext(value)):
            return False, f"User {username} has a different {kind}."
        if privilege is not None and int(node.user_privilege.get(username, 1)) != int(privilege):
            return False, f"User {username} does not have privilege {privilege}."
        return True, ""
    match = re.match(
        r"^ntp\s+authentication-key\s+(\d+)\s+md5\s+(.+)$", command, re.IGNORECASE
    )
    if match:
        key_id = int(match.group(1))
        expected = _expected_plaintext(re.sub(r"\s+7$", "", match.group(2)))
        stored = node.ntp_keys.get(key_id)
        if stored is None:
            return False, f"NTP authentication key {key_id} is not defined."
        if _secret_matches(stored, expected):
            return True, ""
        return False, f"NTP authentication key {key_id} has a different key string."
    if parent.lower().startswith("line "):
        match = re.match(r"^password\s+(.+)$", command, re.IGNORECASE)
        if match:
            lines = _line_configs(node, parent)
            if not lines or any(line.password is None for line in lines):
                return False, f"No password is set on {parent}."
            expected = _expected_plaintext(match.group(1))
            if all(_secret_matches(line.password, expected) for line in lines):
                return True, ""
            return False, f"The {parent} password is not the required password."
    return None


def _evaluate_line(node, line: ConfigLine, actual: RunningConfig) -> Tuple[bool, str]:
    """``(passed, message)`` for one solution line; ``message`` is set only when
    the failure has a more precise explanation than "missing"."""
    if line.token in actual.tokens:
        return True, ""
    parent = line.parent or ""
    command = line.command

    if parent.startswith("interface ") and command in ("no shutdown", "no shut"):
        name = parent.split(" ", 1)[1]
        interface = node.interfaces.get(name)
        if interface is None:
            return False, ""
        if not interface.shutdown:
            return True, ""
        return False, f"{name} is administratively down."

    if line.is_parent:
        match = re.match(r"^vlan\s+(\d+)$", command)
        if match:
            # VTP server/client mode keeps VLANs out of the running-config.
            return int(match.group(1)) in node.vlans, ""
        if _vty_range(command) is not None and actual.vty_covers(command):
            return True, ""
        return False, ""

    match = re.match(r"^vlan\s+(\d+)$", parent)
    if match:
        name = re.match(r"^name\s+(\S+)$", command)
        if name and node.vlans.get(int(match.group(1))) == name.group(1):
            return True, ""

    credential = _check_credential(node, line.parent_text or "", line.text)
    if credential is not None:
        return credential

    match = re.match(r"^ntp\s+server\s+(\S+)(?:\s+key\s+(\d+))?$", command)
    if match and not parent:
        server = node.ntp_servers.get(match.group(1))
        if server is not None and (
            match.group(2) is None or server.key_id == int(match.group(2))
        ):
            return True, ""
        return False, ""

    if _vty_range(parent) is not None and actual.vty_covers(parent, command):
        return True, ""
    return False, ""


def _legacy_result(node_name: str, requirements: List[Requirement], error: str) -> dict:
    missing: List[str] = []
    for requirement in requirements:
        if not requirement.passed and requirement.line not in missing:
            missing.append(requirement.line)
    return {
        "node": node_name,
        "passed": all(requirement.passed for requirement in requirements),
        "missing_lines": missing,
        "error": error,
    }


# --------------------------------------------------------------------------- #
# Configuration + implied state, per node                                     #
# --------------------------------------------------------------------------- #
class BaseGrader:
    def __init__(
        self,
        node_name: str,
        node_config: dict,
        solution_path: str,
        snapshot: Optional[SimulationSnapshot] = None,
        network=None,
    ) -> None:
        self.node_name = node_name
        self.node_config = node_config
        self.solution_path = solution_path
        self.snapshot = snapshot
        self._network = network

    @property
    def network(self):
        if self._network is None and self.snapshot is not None:
            self._network = self.snapshot.network()
        return self._network

    def sanitize_config(self, config_text: str) -> set:
        """Compatibility name retained for callers of the previous grader."""
        return normalise_config(config_text)

    def _error(self, line: str, message: str) -> Requirement:
        return Requirement(self.node_name, "error", line, message=message)

    def evaluate(self) -> Tuple[List[Requirement], str]:
        """All requirements of this node and the legacy ``error`` text."""
        if not os.path.exists(self.solution_path):
            kind = str(self.node_config.get("kind", "")).lower()
            if self.snapshot is not None and self.node_name in self.snapshot.nodes:
                kind = self.snapshot.nodes[self.node_name].kind
            if kind == "host" or str(self.node_config.get("device_type", "")).lower() == "vpcs":
                return [], "No solution file found for host. Skipping."
            name = os.path.basename(self.solution_path)
            return [
                self._error(
                    f"Required solution file is missing: {name}",
                    f"The lab has no solution file for {self.node_name} ({name}).",
                )
            ], "Required solution file is missing."
        if self.snapshot is None:
            return [
                self._error(
                    "Simulator snapshot is required",
                    "Grading needs a running simulator.",
                )
            ], "Simulator snapshot is required."
        if self.node_name not in self.snapshot.nodes:
            return [
                self._error(
                    f"Node {self.node_name} is absent from the simulator",
                    f"{self.node_name} is not part of the running lab.",
                )
            ], "Simulator node missing."

        with open(self.solution_path, "r", encoding="utf-8") as handle:
            solution = parse_config(handle.read(), task_markers=True)
        node = self.snapshot.nodes[self.node_name]
        actual = RunningConfig(self.snapshot.running_config(self.node_name))

        requirements: List[Requirement] = []
        seen: Set[str] = set()
        for line in solution:
            if line.token in seen:
                continue
            seen.add(line.token)
            requirements.append(self._config_requirement(node, line, actual))
        requirements.extend(self._state_requirements(node, solution, requirements))
        return requirements, ""

    def grade(self) -> dict:
        requirements, error = self.evaluate()
        return _legacy_result(self.node_name, requirements, error)

    # ---- configuration lines ----------------------------------------------
    def _config_requirement(self, node, line: ConfigLine, actual: RunningConfig) -> Requirement:
        passed, message = _evaluate_line(node, line, actual)
        requirement = Requirement(
            self.node_name, "config", line.display, task=line.task,
            passed=passed, token=line.token,
        )
        if passed:
            return requirement
        if message:
            requirement.message = message
            if line.parent_text:
                requirement.expected = [line.parent_text, " " + line.text]
            else:
                requirement.expected = [line.text]
            return requirement
        requirement.mergeable = True
        if line.is_parent:
            requirement.block = line.text
            requirement.block_missing = True
        elif line.parent_text:
            requirement.block = line.parent_text
            requirement.expected = [" " + line.text]
            requirement.found = [" " + text for text in actual.related(line)]
        else:
            requirement.expected = [line.text]
            requirement.found = actual.related(line)
        return requirement

    # ---- state implied by the solution ------------------------------------
    def _cable_peer(self, interface: str) -> Optional[Tuple[str, str]]:
        physical = interface_parent(interface) or interface
        for left, left_if, right, right_if in self.snapshot.links:
            if left == self.node_name and canonical_interface(left_if) == physical:
                return right, canonical_interface(right_if)
            if right == self.node_name and canonical_interface(right_if) == physical:
                return left, canonical_interface(left_if)
        return None

    def _interface_problem(
        self, node, interface: str
    ) -> Tuple[str, str, List[str], List[Tuple[str, str]], bool]:
        """``(missing line, message, expected lines, consequence_of, own_cause)``.

        ``own_cause`` is True when this node's own configuration (the interface
        or its parent shut down) explains the failure."""
        network = self.network
        status, protocol = network.line_state(self.node_name, interface)
        generic = (
            f"interface {interface} is operationally down "
            f"({status}, line protocol is {protocol})"
        )

        def no_shutdown(owner: str, name: str) -> List[Tuple[str, str]]:
            return [
                (owner, f"interface {name} -> no shutdown"),
                (owner, f"interface {name} -> no shut"),
            ]

        state = node.interfaces.get(interface)
        if state is not None and state.shutdown:
            return (
                f"interface {interface} -> no shutdown (administratively down)",
                f"{interface} is administratively down.",
                [f"interface {interface}", " no shutdown"],
                no_shutdown(self.node_name, interface),
                True,
            )
        parent = interface_parent(interface)
        if parent:
            parent_state = node.interfaces.get(parent)
            if parent_state is not None and parent_state.shutdown:
                return (
                    f"interface {interface} is operationally down "
                    f"(parent {parent} is administratively down)",
                    f"{interface} is down because its parent interface {parent} "
                    "is administratively down.",
                    [f"interface {parent}", " no shutdown"],
                    no_shutdown(self.node_name, parent),
                    True,
                )
            if parent_state is not None and not network.interface_oper_up(self.node_name, parent):
                parent_status, parent_protocol = network.line_state(self.node_name, parent)
                return (
                    generic,
                    f"{interface} is down because its parent interface {parent} is "
                    f"{parent_status} (line protocol is {parent_protocol}).",
                    [],
                    [],
                    False,
                )
        message = f"{interface} is {status}, line protocol is {protocol}."
        consequence: List[Tuple[str, str]] = []
        if interface.startswith("Vlan") and status == "up":
            vlan = interface[4:]
            message = (
                f"{interface} is up, but its line protocol is down: no switch port "
                f"in VLAN {vlan} is up and forwarding."
            )
        elif interface.startswith("Port-channel"):
            message = f"{interface} is {status}: none of its member links is bundled."
        else:
            peer = self._cable_peer(interface)
            peer_node = self.snapshot.nodes.get(peer[0]) if peer else None
            peer_state = peer_node.interfaces.get(peer[1]) if peer_node is not None else None
            if peer_state is not None and peer_state.shutdown:
                message = (
                    f"{interface} is {status}: the other end of its cable, "
                    f"{peer[0]} {peer[1]}, is administratively down."
                )
                consequence = no_shutdown(peer[0], peer[1])
            elif peer is not None and not network.interface_oper_up(*peer):
                peer_status, peer_protocol = network.line_state(*peer)
                message = (
                    f"{interface} is {status}: the other end of its cable, {peer[0]} "
                    f"{peer[1]}, is {peer_status} (line protocol is {peer_protocol})."
                )
            elif peer is None and interface_parent(interface) is None:
                message = f"{interface} is {status}: no cable is connected to it."
        return generic, message, [], consequence, False

    def _peer_prefixes(self, interfaces, prefix: Optional[str] = None) -> List[Tuple[str, str]]:
        """``(peer node, solution prefix)`` for the cable peers of ``interfaces``:
        the peer interface's block, or ``prefix`` (e.g. ``router ospf``)."""
        depends: List[Tuple[str, str]] = []
        for interface in interfaces:
            peer = self._cable_peer(interface)
            if peer is None:
                continue
            item = (peer[0], prefix or f"interface {peer[1]}")
            if item not in depends:
                depends.append(item)
        return depends

    def _address_owner(self, address: str) -> Optional[str]:
        for node in self.snapshot.nodes.values():
            for interface in node.interfaces.values():
                if interface.ip_address == address:
                    return node.name
                if any(secondary == address for secondary, _mask in interface.secondary_addresses):
                    return node.name
        return None

    def _state_requirements(
        self, node, solution: List[ConfigLine], config: List[Requirement]
    ) -> List[Requirement]:
        network = self.network
        name = self.node_name
        del config
        result: List[Requirement] = []

        def add(line: str, task: Optional[str], passed: bool, message: str = "",
                expected: Optional[List[str]] = None,
                depends: Optional[List[Tuple[str, str]]] = None,
                consequence_of: Optional[List[Tuple[str, str]]] = None) -> None:
            result.append(
                Requirement(
                    name, "state", line, task=task, passed=passed,
                    message=message, expected=list(expected or []),
                    depends=list(depends or []),
                    consequence_of=list(consequence_of or []),
                )
            )

        interfaces: Dict[str, Optional[str]] = {}
        addressed: List[str] = []
        ospf_task: Tuple[bool, Optional[str]] = (False, None)
        ntp_task: Tuple[bool, Optional[str]] = (False, None)
        ntp_servers: List[str] = []
        ssh_markers: Dict[str, Optional[str]] = {}
        groups: Dict[int, Set[str]] = {}
        group_tasks: Dict[int, Optional[str]] = {}
        for line in solution:
            match = re.match(r"^interface\s+(\S+)$", line.parent or "")
            if match and re.match(r"^(?:ip address|encapsulation dot1q)\b", line.command):
                interfaces[canonical_interface(match.group(1))] = line.task
                if line.command.startswith("ip address"):
                    addressed.append(canonical_interface(match.group(1)))
            if line.token.startswith("router ospf ") or (
                match and re.match(r"^ip ospf \d+ area\b", line.command)
            ):
                ospf_task = (True, line.task)
            server = re.match(r"^ntp server (\S+)", line.token)
            if server:
                ntp_task = (True, line.task)
                if server.group(1) not in ntp_servers:
                    ntp_servers.append(server.group(1))
            for marker in ("ip ssh version 2", "login local", "transport input ssh"):
                if marker in line.token:
                    ssh_markers[marker] = line.task
            channel = re.match(r"^channel-group\s+(\d+)\s+mode\s+active$", line.command)
            if channel:
                group = int(channel.group(1))
                members = groups.setdefault(group, set())
                group_tasks[group] = line.task
                if match:
                    interface = canonical_interface(match.group(1))
                    if interface_parent(interface) is None and not interface.startswith(
                        ("Port-channel", "Vlan", "Loopback")
                    ):
                        members.add(interface)

        for interface in sorted(interfaces, key=natural_key):
            task = interfaces[interface]
            depends = self._peer_prefixes([interface])
            if network.interface_oper_up(name, interface):
                add(f"interface {interface} is up", task, True, depends=depends)
                continue
            line, message, expected, consequence, own_cause = self._interface_problem(
                node, interface
            )
            add(line, task, False, message, expected, [] if own_cause else depends, consequence)

        if ospf_task[0]:
            peers = [peer for peer, _prefix in self._peer_prefixes(addressed)]
            depends = [(peer, "router ospf") for peer in peers] + self._peer_prefixes(addressed)
            causes = [(name, "router ospf")] + [(peer, "router ospf") for peer in peers]
            if network.ospf_neighbors(name):
                add("OSPF has a FULL neighbor", ospf_task[1], True, depends=depends)
            else:
                add(
                    "OSPF: no FULL neighbor adjacency",
                    ospf_task[1],
                    False,
                    f"{name} has no FULL OSPF neighbor. " + self._ospf_hint(),
                    depends=depends,
                    consequence_of=causes,
                )

        if ntp_task[0]:
            depends = []
            for address in ntp_servers:
                owner = self._address_owner(address)
                if owner is not None and (owner, "ntp") not in depends:
                    depends.append((owner, "ntp"))
            info = network.ntp_info(name)
            if info["synchronized"]:
                add("NTP is synchronized", ntp_task[1], True, depends=depends)
            else:
                add(
                    "NTP: clock is not synchronized with an authenticated server",
                    ntp_task[1],
                    False,
                    f"{name}'s clock is not synchronized to an NTP server. " + self._ntp_hint(),
                    depends=depends,
                )

        for group in sorted(groups):
            task = group_tasks.get(group)
            members = sorted(groups[group], key=natural_key)
            depends = self._peer_prefixes(members)
            causes = [(name, f"interface {member} -> channel-group") for member in members]
            causes += [(peer, prefix + " -> channel-group") for peer, prefix in depends]
            status = network.channel_status(name, group)
            flags = self._member_flags(group)
            if status["formed"]:
                add(f"EtherChannel {group} is formed", task, True, depends=depends)
            else:
                add(
                    f"EtherChannel {group}: LACP peer is not formed",
                    task,
                    False,
                    f"Port-channel{group} is not up: LACP did not bundle its members "
                    "with the other switch. Both ends need channel-group "
                    f"{group} in a matching LACP mode on the links between them.",
                    depends=depends,
                    consequence_of=causes,
                )
            for interface in members:
                member_depends = self._peer_prefixes([interface])
                if status["members"].get(interface) is True:
                    add(f"EtherChannel {group}: {interface} is bundled", task, True,
                        depends=member_depends)
                    continue
                detail = flags.get(interface)
                add(
                    f"EtherChannel {group}: expected member {interface} is not bundled/up",
                    task,
                    False,
                    f"{interface} is not bundled in Port-channel{group}"
                    + (f" ({detail})." if detail else "."),
                    depends=member_depends,
                    consequence_of=causes,
                )

        if len(ssh_markers) == 3:
            task = ssh_markers.get("ip ssh version 2")
            if not node.domain_name or node.rsa_bits is None:
                missing = []
                if not node.domain_name:
                    missing.append("a domain name (ip domain-name)")
                if node.rsa_bits is None:
                    missing.append("RSA keys (crypto key generate rsa modulus 2048)")
                add(
                    "SSH: domain name and generated RSA keys are required",
                    task,
                    False,
                    f"{name} cannot accept SSH: it needs " + " and ".join(missing) + ".",
                    ["crypto key generate rsa modulus 2048"] if node.rsa_bits is None else [],
                )
            elif node.rsa_bits != 2048:
                add(
                    f"SSH: RSA modulus must be exactly 2048 bits (configured {node.rsa_bits})",
                    task,
                    False,
                    f"The RSA keys are {node.rsa_bits} bits; the task asks for 2048.",
                    ["crypto key generate rsa modulus 2048"],
                )
            else:
                add("SSH keys are ready", task, True)
        return result

    def _bundle(self):
        """The engine bundle behind the network facade, when it has one."""
        return getattr(self.network, "bundle", None)

    def _member_flags(self, group: int) -> Dict[str, str]:
        bundle = self._bundle()
        if bundle is None:
            return {}
        try:
            channels = bundle.l2.etherchannels(self.node_name)
        except Exception:  # pragma: no cover - diagnostics only
            logger.exception("EtherChannel flags unavailable on %s", self.node_name)
            return {}
        text: Dict[str, str] = {}
        for channel in channels:
            if channel.group != group:
                continue
            for member in channel.members:
                described = [
                    _MEMBER_FLAGS[flag] for flag in member.flags if flag in _MEMBER_FLAGS
                ]
                if described:
                    text[canonical_interface(member.interface)] = "; ".join(described)
        return text

    def _diagnosis(self, engine: str, method: str, *args, **kwargs) -> List[str]:
        bundle = self._bundle()
        function = getattr(getattr(bundle, engine, None), method, None)
        if function is None:
            return []
        try:
            return list(function(*args, **kwargs))
        except Exception:  # pragma: no cover - diagnostics only
            logger.exception("%s.%s failed on %s", engine, method, self.node_name)
            return []

    def _ospf_hint(self) -> str:
        problems = self._diagnosis("ospf", "diagnose", self.node_name)
        if problems:
            return " ".join(_sentence(problem) for problem in problems)
        return (
            "Both routers need the link up, OSPF enabled on it in the same area "
            "with matching hello and dead timers, and no passive interface."
        )

    def _ntp_hint(self) -> str:
        problems = self._diagnosis(
            "services", "ntp_diagnose", self.node_name, now=getattr(self.network, "now", None)
        )
        if problems:
            return " ".join(_sentence(problem) for problem in problems)
        return (
            "Check the server address and reachability, and with ntp authenticate: "
            "the key string, ntp trusted-key and the key on the ntp server line."
        )


class IOSGrader(BaseGrader):
    """Name retained for compatibility; canonical snapshots include VLAN state."""


def get_grader_for_device(
    node_name: str,
    node_config: dict,
    solution_path: str,
    snapshot: Optional[SimulationSnapshot] = None,
    network=None,
) -> BaseGrader:
    device_type = str(node_config.get("device_type", ""))
    kind = str(node_config.get("kind", ""))
    if "cisco" in device_type or kind in {"router", "switch"}:
        return IOSGrader(node_name, node_config, solution_path, snapshot=snapshot, network=network)
    return BaseGrader(node_name, node_config, solution_path, snapshot=snapshot, network=network)


# --------------------------------------------------------------------------- #
# Behavioral checks                                                           #
# --------------------------------------------------------------------------- #
class BehavioralGrader:
    def __init__(
        self,
        node_name: str,
        node_config: dict,
        checks: list,
        snapshot: Optional[SimulationSnapshot] = None,
        network=None,
    ) -> None:
        self.node_name = node_name
        self.node_config = node_config
        self.checks = checks
        self.snapshot = snapshot
        self._network = network

    @property
    def network(self):
        if self._network is None and self.snapshot is not None:
            self._network = self.snapshot.network()
        return self._network

    def _target_addresses(self, value: object) -> List[str]:
        if self.snapshot is None:
            return []
        target = str(value or "").strip()
        if not target:
            return []
        network = self.network
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

    def _no_address_reason(self, target: str) -> str:
        """Why ``target`` (a node name or an address) has no usable address."""
        node = self.snapshot.nodes.get(target)
        if node is None:
            return f"no device has {target} on an interface that is up"
        if node.kind == "host" and node.dhcp_enabled:
            return f"{target} has no IPv4 address: its DHCP request got no lease"
        if node.kind == "host" and node.cli_profile == "vpcs":
            return f"{target} has no IPv4 address (if it should use DHCP, run ip dhcp on {target})"
        return f"{target} has no IPv4 address on an interface that is up"

    def _source_problem(self) -> Optional[str]:
        """A reason the source node cannot send at all, or ``None``."""
        if any(endpoint.node == self.node_name for endpoint in self.network.ip_endpoints()):
            return None
        return self._no_address_reason(self.node_name)

    @staticmethod
    def _required(check: dict, key: str) -> str:
        value = str(check.get(key, "") or "").strip()
        if not value:
            raise _CheckDefinitionError(f"missing required {key}")
        return value

    def _check_ping(self, check: dict) -> Optional[str]:
        target = self._required(check, "target")
        try:
            target = str(ipaddress.IPv4Address(target))
        except ipaddress.AddressValueError as exc:
            raise _CheckDefinitionError("target is not a valid IPv4 address") from exc
        if self.network.can_reach(self.node_name, target):
            return None
        source = self._source_problem()
        if source:
            return f"{source}, so it cannot reach {target}"
        return f"{target} is unreachable from {self.node_name}"

    def _check_dhcp(self, check: dict) -> Optional[str]:
        node = self.snapshot.nodes[self.node_name]
        name = self.node_name
        if node.kind != "host":
            raise _CheckDefinitionError("DHCP checks require a host node")
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
            raise _CheckDefinitionError("host has no interface")
        interface = interfaces[0]
        if not node.dhcp_enabled:
            return f"{name} has not requested an address with DHCP (run ip dhcp on {name})"
        if interface.address_source != "dhcp":
            return (
                f"{name} asked for an address with DHCP but got no lease: no DHCP "
                "server answered it (check the pool, its switch port VLAN and the trunk)"
            )
        if not self.network.interface_oper_up(node.name, interface.name):
            return f"{name}'s interface {interface.name} is not up"
        try:
            lease = ipaddress.IPv4Interface(
                f"{interface.ip_address}/{interface.netmask}"
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return "the DHCP lease does not contain a valid IPv4 address and mask"
        if lease.ip.is_unspecified or lease.ip.is_multicast:
            return "the DHCP lease is not a valid unicast host address"
        if lease.network.prefixlen < 31 and lease.ip in {
            lease.network.network_address,
            lease.network.broadcast_address,
        }:
            return "the DHCP lease is not a usable host address"
        if not node.default_gateway:
            return (
                f"{name}'s DHCP lease has no default gateway "
                "(add default-router to the pool)"
            )
        try:
            learned_gateway = ipaddress.IPv4Address(node.default_gateway)
        except ipaddress.AddressValueError:
            return "DHCP gave an invalid default gateway"
        if learned_gateway.is_unspecified or learned_gateway.is_multicast:
            return "DHCP gave an invalid default gateway"
        if learned_gateway not in lease.network:
            return (
                f"the DHCP default gateway {learned_gateway} is outside the leased "
                f"subnet {lease.network.with_prefixlen}"
            )
        if lease.network.prefixlen < 31 and learned_gateway in {
            lease.network.network_address,
            lease.network.broadcast_address,
        }:
            return "DHCP gave an invalid default gateway"

        expected_network = check.get("network")
        if expected_network:
            try:
                required_network = ipaddress.IPv4Network(
                    str(expected_network), strict=False
                )
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
                raise _CheckDefinitionError("check defines an invalid DHCP network") from exc
            if lease.network != required_network:
                return (
                    f"{name}'s lease {lease.ip} is on {lease.network.with_prefixlen}, "
                    f"expected {required_network.with_prefixlen}"
                )
        expected_gateway = check.get("gateway")
        if expected_gateway:
            try:
                required_gateway = ipaddress.IPv4Address(str(expected_gateway))
            except ipaddress.AddressValueError as exc:
                raise _CheckDefinitionError("check defines an invalid DHCP gateway") from exc
            if learned_gateway != required_gateway:
                return (
                    f"{name} learned gateway {learned_gateway} from DHCP, expected "
                    f"{required_gateway}"
                )
        return None

    def _check_ping_node(self, check: dict) -> Optional[str]:
        target_node = self._required(check, "target_node")
        if target_node not in self.snapshot.nodes:
            raise _CheckDefinitionError(f"target_node '{target_node}' does not exist")
        addresses = self._target_addresses(target_node)
        if not addresses:
            return self._no_address_reason(target_node)
        if any(self.network.can_reach(self.node_name, address) for address in addresses):
            return None
        source = self._source_problem()
        if source:
            return f"{source}, so it cannot reach {target_node}"
        return (
            f"{target_node} ({', '.join(addresses)}) is unreachable from {self.node_name}"
        )

    def _check_ssh(self, check: dict) -> Optional[str]:
        target = self._required(check, "target")
        username = self._required(check, "username")
        password = check.get("password")
        if not isinstance(password, str) or not password:
            raise _CheckDefinitionError("missing required password")
        addresses = self._target_addresses(target)
        if not addresses:
            return self._no_address_reason(target)
        reasons: List[str] = []
        for address in addresses:
            allowed, reason = self.network.ssh_authenticate(
                self.node_name, username, password, address
            )
            if allowed:
                return None
            reasons.append(f"SSH from {self.node_name} to {address} as {username} failed: {reason}")
        return reasons[0] if reasons else "SSH authentication failed"

    def _check_telnet_refused(self, check: dict) -> Optional[str]:
        target = self._required(check, "target")
        addresses = self._target_addresses(target)
        if not addresses:
            return self._no_address_reason(target)
        reachable = False
        for address in addresses:
            if not self.network.can_reach(self.node_name, address):
                continue
            reachable = True
            allowed, reason = self.network.telnet_allowed(self.node_name, address)
            if not allowed and reason == "Connection refused by remote host":
                return None
            if allowed:
                return (
                    f"Telnet from {self.node_name} to {address} was accepted; the VTY "
                    "transport policy must refuse it"
                )
        if not reachable:
            return (
                f"{target} is unreachable from {self.node_name}, so the Telnet refusal "
                "could not be verified"
            )
        return "Telnet was not refused by the VTY transport policy"

    def evaluate(self) -> Tuple[List[Requirement], str]:
        name = self.node_name
        if self.snapshot is None:
            requirement = Requirement(
                name, "error", "Behavioral grading requires a simulator snapshot",
                message="Grading needs a running simulator.",
            )
            return [requirement], "Behavioral verification failed."
        handlers = {
            "ping": self._check_ping,
            "dhcp": self._check_dhcp,
            "ping_node": self._check_ping_node,
            "ssh": self._check_ssh,
            "telnet_refused": self._check_telnet_refused,
        }
        requirements: List[Requirement] = []
        for check in self.checks:
            check_type = str(check.get("type", "")).strip().lower()
            description = check.get("description") or check_type or "unnamed check"
            task = _task_key(check.get("task"))
            handler = handlers.get(check_type)
            if handler is None:
                requirements.append(
                    Requirement(
                        name, "error",
                        f"Unsupported behavioral check type '{check.get('type', '')}': {description}",
                        task=task, title=description,
                        message=f"The lab uses an unknown check type '{check.get('type', '')}'.",
                    )
                )
                continue
            try:
                reason = handler(check)
            except _CheckDefinitionError as exc:
                requirements.append(
                    Requirement(
                        name, "error", f"Behavioral check failed: {description} ({exc}).",
                        task=task, title=description,
                        message=f"The lab definition of this check is invalid: {exc}.",
                    )
                )
                continue
            except Exception:
                logger.exception("Behavioral check %r on %s failed", check_type, name)
                requirements.append(
                    Requirement(
                        name, "error",
                        f"Behavioral check failed: {description} (internal grading error).",
                        task=task, title=description,
                        message="The grader hit an internal error on this check.",
                    )
                )
                continue
            requirements.append(
                Requirement(
                    name, "check",
                    f"Behavioral check failed: {description} ({reason})." if reason else description,
                    task=task, passed=reason is None, title=description,
                    message=_sentence(reason) if reason else "",
                )
            )
        failed = any(not requirement.passed for requirement in requirements)
        return requirements, "Behavioral verification failed." if failed else ""

    def grade(self) -> dict:
        requirements, error = self.evaluate()
        return _legacy_result(self.node_name, requirements, error)


# --------------------------------------------------------------------------- #
# Tasks, findings and the report                                              #
# --------------------------------------------------------------------------- #
def _findings(requirements: List[Requirement]) -> List[dict]:
    """Student-facing findings for failed requirements (config lines merged per
    block and per node)."""
    findings: List[dict] = []
    merged: Dict[Tuple[str, Optional[str]], dict] = {}
    for requirement in requirements:
        if requirement.passed:
            continue
        if requirement.kind == "config" and requirement.mergeable:
            key = (requirement.node, requirement.block)
            finding = merged.get(key)
            if finding is None:
                finding = {
                    "node": requirement.node,
                    "kind": "config",
                    "title": "",
                    "message": "",
                    "expected": [requirement.block] if requirement.block else [],
                    "found": [],
                    "_block_missing": False,
                }
                merged[key] = finding
                findings.append(finding)
            if requirement.block_missing:
                finding["_block_missing"] = True
            for line in requirement.expected:
                if line not in finding["expected"]:
                    finding["expected"].append(line)
            for line in requirement.found:
                if line not in finding["found"]:
                    finding["found"].append(line)
            continue
        findings.append(
            {
                "node": requirement.node,
                "kind": requirement.kind,
                "title": requirement.title,
                "message": requirement.message or _sentence(requirement.line),
                "expected": list(requirement.expected),
                "found": list(requirement.found),
            }
        )
    for (_node, block), finding in merged.items():
        block_missing = finding.pop("_block_missing")
        if block is None:
            finding["message"] = "Missing configuration:"
        elif block_missing:
            finding["message"] = f"{block} is not configured:"
        else:
            finding["message"] = f"Missing under {block}:"
            if finding["found"]:
                finding["found"].insert(0, block)
    return findings


def _points(task: dict) -> float:
    value = task.get("points", 1)
    try:
        points = float(value)
    except (TypeError, ValueError):
        logger.warning("Task %r has invalid points %r; using 1", task.get("id"), value)
        return 1.0
    if points < 0 or math.isnan(points) or math.isinf(points):
        logger.warning("Task %r has invalid points %r; using 1", task.get("id"), value)
        return 1.0
    return points


def _number(value: float):
    return int(value) if float(value).is_integer() else value


def _task_results(tasks: list, requirements: List[Requirement]) -> List[dict]:
    definitions = [task for task in tasks or [] if isinstance(task, dict)]
    known = {_task_key(task.get("id")) for task in definitions}
    by_task: Dict[Optional[str], List[Requirement]] = {}
    unknown: Set[str] = set()
    for requirement in requirements:
        key = requirement.task
        if key is not None and key not in known:
            unknown.add(key)
            key = None
        by_task.setdefault(key, []).append(requirement)
    if unknown:
        logger.warning("Lab grading references unknown task ids: %s", ", ".join(sorted(unknown)))

    def result(task_id, description: str, items: List[Requirement], points: float) -> dict:
        graded = bool(items)
        passed = graded and all(item.passed for item in items)
        return {
            "id": task_id,
            "description": description,
            "graded": graded,
            "passed": passed,
            "points": _number(points),
            "earned": _number(points if passed else 0),
            "requirements": len(items),
            "satisfied": sum(1 for item in items if item.passed),
            "findings": _findings(items),
        }

    results = [
        result(
            task.get("id"),
            str(task.get("description") or f"Task {task.get('id')}"),
            by_task.get(_task_key(task.get("id")), []),
            _points(task),
        )
        for task in definitions
    ]

    # ``requires``: a task (typically a verification task) counts only once the
    # tasks it verifies pass, so a check that already holds in the untouched
    # lab does not earn points.
    final: Dict[Optional[str], bool] = {
        _task_key(task.get("id")): item["passed"] for task, item in zip(definitions, results)
    }
    graded_keys = {
        _task_key(task.get("id")) for task, item in zip(definitions, results) if item["graded"]
    }
    for task, item in zip(definitions, results):
        required = [_task_key(value) for value in (task.get("requires") or [])]
        # A task with nothing to grade cannot block another one.
        required = [key for key in required if key in known and key in graded_keys]
        blocking = [key for key in required if not final.get(key)]
        if item["graded"] and blocking:
            if item["passed"]:
                item["passed"] = False
                item["earned"] = 0
                final[_task_key(task.get("id"))] = False
            labels = ", ".join(blocking)
            item["findings"].append(
                {
                    "node": "",
                    "kind": "requires",
                    "title": "",
                    "message": (
                        f"This task verifies earlier work and counts once task{'s' if len(blocking) > 1 else ''} "
                        f"{labels} pass{'' if len(blocking) > 1 else 'es'}."
                    ),
                    "expected": [],
                    "found": [],
                }
            )
    if by_task.get(None):
        results.append(result(None, OTHER_TASK_TITLE, by_task[None], 1.0))
    return results


def _matches_prefix(token: str, prefix: str) -> bool:
    return token == prefix or token.startswith(prefix + " ")


def _resolve_dependencies(
    requirements: List[Requirement], task_order: Dict[str, int]
) -> List[Requirement]:
    """Apply ``depends`` and ``consequence_of`` across nodes (see Requirement).

    A requirement moves to the latest task among the solution lines it depends
    on; a failed requirement is dropped when a failed configuration line it
    lists in ``consequence_of`` is in the same task (that line already reports
    the cause).
    """
    config = [item for item in requirements if item.kind == "config"]
    for requirement in requirements:
        if not requirement.depends or requirement.task not in task_order:
            continue
        latest = requirement.task
        for node, prefix in requirement.depends:
            for line in config:
                if line.node != node or line.task not in task_order:
                    continue
                if _matches_prefix(line.token, prefix) and task_order[line.task] > task_order[latest]:
                    latest = line.task
        requirement.task = latest
    failed = [item for item in config if not item.passed]
    kept: List[Requirement] = []
    for requirement in requirements:
        if not requirement.passed and requirement.consequence_of and any(
            line.node == node and line.task == requirement.task and _matches_prefix(line.token, prefix)
            for node, prefix in requirement.consequence_of
            for line in failed
        ):
            continue
        kept.append(requirement)
    return kept


def grade_lab(
    yaml_path: str,
    skip_tasks: list = None,
    lab_dir: str = None,
    snapshot: Optional[SimulationSnapshot] = None,
) -> dict:
    """Grade configuration, implied state and behavior against one snapshot.

    ``skip_tasks`` is accepted for API compatibility; every task is evaluated
    again because a passed task can regress.
    """
    del skip_tasks
    started = time.perf_counter()
    lab_definition = load_lab_definition(yaml_path) or {}
    lab_info = lab_definition.get("lab") or {}
    if not lab_dir:
        lab_dir = os.path.dirname(os.path.abspath(yaml_path))

    node_configs = {
        node["name"]: node
        for node in lab_info.get("nodes", []) or []
        if isinstance(node, dict) and node.get("name")
    }
    checks_by_node: Dict[str, list] = {}
    unknown_node_checks = []
    for check in lab_info.get("checks", []) or []:
        if not isinstance(check, dict):
            continue
        node_name = check.get("node")
        if node_name not in node_configs:
            unknown_node_checks.append(check)
        else:
            checks_by_node.setdefault(node_name, []).append(check)

    network = snapshot.network() if snapshot is not None else None
    evaluated: List[Tuple[str, List[Requirement], str]] = []
    for node_name, node_config in node_configs.items():
        solution_path = os.path.join(lab_dir, f"solution_{node_name}.cfg")
        grader = get_grader_for_device(
            node_name, node_config, solution_path, snapshot=snapshot, network=network
        )
        try:
            node_requirements, error = grader.evaluate()
        except Exception:
            logger.exception("Grading failed on node %s", node_name)
            node_requirements = [
                Requirement(
                    node_name, "error", f"Internal grading error on {node_name}",
                    message="The grader hit an internal error on this device.",
                )
            ]
            error = "Internal grading error."
        if node_name in checks_by_node:
            behavioral, behavioral_error = BehavioralGrader(
                node_name,
                node_config,
                checks_by_node[node_name],
                snapshot=snapshot,
                network=network,
            ).evaluate()
            node_requirements = node_requirements + behavioral
            if behavioral_error:
                error = " ".join(value for value in (error, behavioral_error) if value)
        evaluated.append((node_name, node_requirements, error))

    task_definitions = [task for task in lab_info.get("tasks") or [] if isinstance(task, dict)]
    task_order = {
        _task_key(task.get("id")): position for position, task in enumerate(task_definitions)
    }
    kept = _resolve_dependencies(
        [item for _name, items, _error in evaluated for item in items], task_order
    )
    kept_ids = {id(item) for item in kept}
    results = []
    requirements: List[Requirement] = []
    for node_name, node_requirements, error in evaluated:
        node_requirements = [item for item in node_requirements if id(item) in kept_ids]
        results.append(_legacy_result(node_name, node_requirements, error))
        requirements.extend(node_requirements)

    for check in unknown_node_checks:
        node_name = str(check.get("node", ""))
        requirement = Requirement(
            node_name, "error", f"Behavioral check references unknown node '{node_name}'",
            task=_task_key(check.get("task")),
            title=str(check.get("description") or check.get("type") or ""),
            message=f"The lab defines a check for '{node_name}', which is not a lab node.",
        )
        requirements.append(requirement)
        results.append(
            {
                "node": node_name,
                "passed": False,
                "missing_lines": [requirement.line],
                "error": "Invalid lab check definition.",
            }
        )

    tasks = _task_results(task_definitions, requirements)
    passed = bool(results) and all(result["passed"] for result in results)
    graded = [task for task in tasks if task["graded"]]
    possible = float(sum(task["points"] for task in graded))
    earned = float(sum(task["earned"] for task in graded))
    if passed:
        percentage = 100
    elif possible > 0:
        percentage = min(99, int(math.floor(100.0 * earned / possible + 1e-9)))
    else:
        percentage = 0

    report = {
        "lab_id": lab_info.get("id", ""),
        "lab_title": lab_info.get("title", ""),
        "total_earned": percentage,
        "total_possible": 100,
        "percentage": percentage,
        "passed": passed,
        "node_results": results,
        "tasks": tasks,
        "summary": {
            "tasks_graded": len(graded),
            "tasks_passed": sum(1 for task in graded if task["passed"]),
            "requirements": len(requirements),
            "satisfied": sum(1 for requirement in requirements if requirement.passed),
        },
    }
    logger.info(
        "Graded %s: passed=%s score=%s%% tasks=%d/%d requirements=%d/%d (%.0f ms)",
        report["lab_id"],
        passed,
        percentage,
        report["summary"]["tasks_passed"],
        report["summary"]["tasks_graded"],
        report["summary"]["satisfied"],
        report["summary"]["requirements"],
        (time.perf_counter() - started) * 1000.0,
    )
    return report
