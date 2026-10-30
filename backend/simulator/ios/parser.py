"""Cisco IOS command DSL, registry and matcher (Agent A1).

This module provides the command-description language used by every IOS command
module, a registry that compiles those descriptions into a per-mode command
tree, and an IOS-faithful matcher used by :mod:`simulator.ios.shell` for
execution, ``?`` help and Tab completion.

Registration
------------
Command modules register handlers with the :func:`command` decorator::

    from simulator.ios.parser import command, CONFIG

    @command("hostname {name:WORD}", modes=(CONFIG,), privilege=15,
             help={"hostname": "Set system's network name",
                   "name": "This system's network name"})
    def _hostname(ctx):
        ctx.node.hostname = ctx.args["name"]
        ctx.mark_dirty()
        return None

``@command`` arguments:

* ``pattern``   – DSL string (grammar below).
* ``modes``     – tuple of mode names the command is valid in (see the mode
                  constants ``EXEC``/``CONFIG``/``CONFIG_IF`` ... below).
* ``privilege`` – minimum privilege level (1 or 15) required to see/run it.
                  Config modes are always privilege 15.
* ``help``      – optional dict mapping a keyword (by its literal spelling) or a
                  param *name* to the one-line description shown by ``?``.
* ``hidden``    – reserved; hides the command from ``?`` listings.
* ``name``      – optional debug label.

Pattern grammar
---------------
A pattern is a whitespace-separated sequence of elements:

* ``keyword``            – a literal keyword (letters, digits, ``-``). Matched
                           case-insensitively by unique prefix (IOS semantics).
* ``[ ... ]``            – an optional sub-sequence.
* ``( a | b | c )``      – alternation; each branch is itself a sub-sequence.
* ``{name:TYPE}``        – a typed parameter captured into ``ctx.args[name]``.

``TYPE`` is one of:

====================  ====================================================
TYPE                  accepts / ``ctx.args`` value
====================  ====================================================
``WORD``              one whitespace-delimited token (``str``)
``LINE``              the rest of the raw line (``str``)
``<lo-hi>``           an integer in ``[lo, hi]`` (``int``)
``A.B.C.D``           an IPv4 address (``str``)
``A.B.C.D/M``         an IPv4 address with prefix length (``str``)
``H.H.H``             a dotted-hex MAC, normalised to ``aabb.ccdd.eeff``
``INTERFACE``         one interface, abbreviations and the ``ethernet 0/0``
                      two-token form accepted; physical ports are validated
                      against ``node.has_interface`` (``str`` canonical name)
``INTERFACE_RANGE``   an interface range (rest of line); value is ``List[str]``
``VLAN_LIST``         ``10``/``10,20``/``10-15,20`` -> sorted ``List[int]``
``HH:MM:SS``          a clock time -> ``(h, m, s)`` ints
``MONTH``             a month name/abbrev -> month number 1..12
====================  ====================================================

Matching, errors and help are described on :class:`CommandRegistry`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Dict, List, Optional, Tuple, Union

from ..models import (
    canonical_interface,
    format_mac,
    is_physical_interface,
)

# --------------------------------------------------------------------------- #
# Mode name constants (the single source of truth; see PLAN "CLI mode names"). #
# --------------------------------------------------------------------------- #
EXEC = "exec"
CONFIG = "config"
CONFIG_IF = "config-if"
CONFIG_SUBIF = "config-subif"
CONFIG_IF_RANGE = "config-if-range"
CONFIG_LINE = "config-line"
CONFIG_ROUTER = "config-router"
DHCP_CONFIG = "dhcp-config"
CONFIG_VLAN = "config-vlan"

#: Every configuration mode (global + submodes).
CONFIG_MODES = (
    CONFIG,
    CONFIG_IF,
    CONFIG_SUBIF,
    CONFIG_IF_RANGE,
    CONFIG_LINE,
    CONFIG_ROUTER,
    DHCP_CONFIG,
    CONFIG_VLAN,
)
#: Configuration submodes (everything that sits on top of ``config``).
CONFIG_SUBMODES = tuple(mode for mode in CONFIG_MODES if mode != CONFIG)

# --------------------------------------------------------------------------- #
# Error strings (exact IOS wording).                                          #
# --------------------------------------------------------------------------- #
INVALID = "% Invalid input detected at '^' marker."
INCOMPLETE = "% Incomplete command."
SHOW_SUBCOMMAND_HINT = '% Type "show ?" for a list of subcommands'


def ambiguous_message(text: str) -> str:
    """Return the ``% Ambiguous command`` line for ``text`` (two spaces)."""
    return f'% Ambiguous command:  "{text}"'


# --------------------------------------------------------------------------- #
# Parameter types.                                                            #
# --------------------------------------------------------------------------- #
WORD = "WORD"
LINE = "LINE"
RANGE = "RANGE"
IPV4 = "A.B.C.D"
IPV4_PREFIX = "A.B.C.D/M"
MAC = "H.H.H"
INTERFACE = "INTERFACE"
INTERFACE_RANGE = "INTERFACE_RANGE"
VLAN_LIST = "VLAN_LIST"
TIME = "HH:MM:SS"
MONTH = "MONTH"

#: Help placeholder shown by ``?`` for each parameter type.  IOS shows bare
#: ``WORD``/``LINE``/``A.B.C.D``/``H.H.H`` and bracketed numeric ranges such as
#: ``<1-255>``; the remaining synthetic types use an angle-bracket placeholder.
_PLACEHOLDERS = {
    WORD: "WORD",
    LINE: "LINE",
    IPV4: "A.B.C.D",
    IPV4_PREFIX: "A.B.C.D/M",
    MAC: "H.H.H",
    INTERFACE: "<interface>",
    INTERFACE_RANGE: "<interface-range>",
    VLAN_LIST: "<vlan-list>",
    TIME: "hh:mm:ss",
    MONTH: "<month>",
}

_MONTHS = [
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
]


@dataclass(frozen=True)
class Keyword:
    """A literal keyword element of a pattern."""

    word: str


@dataclass(frozen=True)
class Param:
    """A typed parameter element of a pattern."""

    name: str
    ptype: str
    lo: Optional[int] = None
    hi: Optional[int] = None

    @property
    def placeholder(self) -> str:
        if self.ptype == RANGE:
            return f"<{self.lo}-{self.hi}>"
        return _PLACEHOLDERS.get(self.ptype, self.name.upper())


TokenSpec = Union[Keyword, Param]


# --------------------------------------------------------------------------- #
# Pattern compilation.                                                        #
# --------------------------------------------------------------------------- #
_SPECIAL = set("[](){}|")


class PatternError(ValueError):
    """Raised when a command pattern is malformed (a programming error)."""


def _product(prefixes: List[List[TokenSpec]], suffixes: List[List[TokenSpec]]):
    return [p + s for p in prefixes for s in suffixes]


class _PatternParser:
    """Expand a pattern string into a list of linear token sequences."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0

    def parse(self) -> List[List[TokenSpec]]:
        seqs = self._parse_seq(())
        if self.i != len(self.text):
            raise PatternError(f"Unexpected {self.text[self.i]!r} in pattern {self.text!r}")
        return seqs

    def _parse_seq(self, stop: Tuple[str, ...]) -> List[List[TokenSpec]]:
        result: List[List[TokenSpec]] = [[]]
        while self.i < len(self.text):
            char = self.text[self.i]
            if char in stop:
                break
            if char.isspace():
                self.i += 1
                continue
            if char == "[":
                self.i += 1
                inner = self._parse_seq(("]",))
                self._expect("]")
                result = _product(result, [[]] + inner)
            elif char == "(":
                self.i += 1
                alts = self._parse_alternation()
                self._expect(")")
                result = _product(result, alts)
            elif char == "{":
                self.i += 1
                param = self._parse_param()
                self._expect("}")
                result = _product(result, [[param]])
            else:
                result = _product(result, [[Keyword(self._read_word())]])
        return result

    def _parse_alternation(self) -> List[List[TokenSpec]]:
        alts = list(self._parse_seq(("|", ")")))
        while self.i < len(self.text) and self.text[self.i] == "|":
            self.i += 1
            alts.extend(self._parse_seq(("|", ")")))
        return alts

    def _parse_param(self) -> Param:
        start = self.i
        while self.i < len(self.text) and self.text[self.i] != "}":
            self.i += 1
        body = self.text[start:self.i]
        if ":" not in body:
            raise PatternError(f"Parameter {body!r} must be {{name:TYPE}}")
        name, type_str = body.split(":", 1)
        name = name.strip()
        type_str = type_str.strip()
        match = re.fullmatch(r"<(-?\d+)-(-?\d+)>", type_str)
        if match:
            return Param(name, RANGE, int(match.group(1)), int(match.group(2)))
        if type_str not in _PLACEHOLDERS:
            raise PatternError(f"Unknown parameter type {type_str!r}")
        return Param(name, type_str)

    def _read_word(self) -> str:
        start = self.i
        while self.i < len(self.text) and not self.text[self.i].isspace() and self.text[self.i] not in _SPECIAL:
            self.i += 1
        return self.text[start:self.i]

    def _expect(self, char: str) -> None:
        if self.i >= len(self.text) or self.text[self.i] != char:
            raise PatternError(f"Expected {char!r} in pattern {self.text!r}")
        self.i += 1


def compile_pattern(pattern: str) -> List[List[TokenSpec]]:
    """Expand ``pattern`` into every linear token sequence it describes."""
    return _PatternParser(pattern).parse()


# --------------------------------------------------------------------------- #
# Command + context.                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class Command:
    """One registered command."""

    pattern: str
    modes: Tuple[str, ...]
    privilege: int = 1
    help: Dict[str, str] = field(default_factory=dict)
    hidden: bool = False
    handler: Optional[object] = None
    name: Optional[str] = None
    expansions: List[List[TokenSpec]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.expansions:
            self.expansions = compile_pattern(self.pattern)


@dataclass
class CommandContext:
    """Passed to every command handler.

    Attributes
    ----------
    shell / session / node
        The executing :class:`~simulator.ios.shell.IosShell`, its session, and
        the :class:`~simulator.models.NodeState` it drives.
    args
        Parsed parameters keyed by name (see the pattern grammar for value
        types).
    path
        The canonical keyword path that matched, e.g. ``["show", "history"]``.
        When a leading ``no`` matched it is ``path[0]`` and ``negate`` is True.
    raw
        The full command text (command portion only; any ``| filter`` has been
        split off by the shell before dispatch).

    Handlers return ``str`` (printed), ``None`` (no output), or are generator
    functions yielding ``str`` / :class:`~simulator.ios.protocol.Sleep` /
    :class:`~simulator.ios.protocol.Prompt`.  A ``Prompt`` is resumed with the
    user's typed line via ``generator.send(...)``.
    """

    shell: object
    session: object
    node: object
    args: Dict[str, object] = field(default_factory=dict)
    path: List[str] = field(default_factory=list)
    raw: str = ""
    negate: bool = False

    # -- helpers delegating to the shell/session ---------------------------- #
    def push_mode(self, mode: str, target: object = None) -> None:
        self.shell.push_mode(mode, target)

    @property
    def target(self) -> object:
        """The current submode target (interface/line/router/pool/...)."""
        return self.session.target

    def mark_dirty(self) -> None:
        """Flag the node's configuration as changed and notify the runtime.

        Sets ``node.config_dirty`` (``reload`` asks to save) and, when the shell
        is wired to a runtime, calls ``runtime.mark_changed()`` so the engine
        bundle is rebuilt and DHCP leases are recomputed.
        """
        try:
            self.node.config_dirty = True
        except AttributeError:
            pass
        rt = self.runtime
        if rt is not None and hasattr(rt, "mark_changed"):
            rt.mark_changed()

    # -- Phase 2 engine / runtime access ----------------------------------- #
    @property
    def engines(self):
        """Current engine bundle (:class:`simulator.engines.EngineBundle`) or None.

        The shell holds an ``engine_provider`` zero-arg callable that returns a
        bundle reflecting the node's *current* state (the runtime rebuilds it
        after configuration changes).  Command handlers read live network state
        through it, e.g. ``ctx.engines.ospf.neighbors(ctx.node.name)`` or
        ``ctx.engines.l3.routing_table(ctx.node.name)``.  It is ``None`` only in
        unit tests that did not wire a provider.
        """
        provider = getattr(self.shell, "engine_provider", None)
        return provider() if provider is not None else None

    @property
    def runtime(self):
        """The owning ``SimulationRuntime`` (for now()/emit_log/nested sessions),
        or ``None`` in unit tests."""
        return getattr(self.shell, "runtime", None)

    def now(self) -> float:
        """Current epoch time from the runtime, falling back to wall-clock.

        Config handlers that need a timestamp (``clock set``, ``crypto key
        generate rsa``, lease math) should pass ``now=ctx.now()`` to the engine.
        """
        rt = self.runtime
        if rt is not None and hasattr(rt, "now"):
            return rt.now()
        import time

        return time.time()

    def emit_log(self, message: str) -> None:
        """Emit a syslog line for this node via the runtime (no-op in tests)."""
        rt = self.runtime
        if rt is not None and hasattr(rt, "emit_log"):
            rt.emit_log(self.node.name, message)


# --------------------------------------------------------------------------- #
# Parse result.                                                               #
# --------------------------------------------------------------------------- #
@dataclass
class ParseResult:
    status: str  # "ok" | "ambiguous" | "invalid" | "incomplete"
    command: Optional[Command] = None
    args: Dict[str, object] = field(default_factory=dict)
    path: List[str] = field(default_factory=list)
    error_offset: Optional[int] = None  # char offset of the offending token
    matched_count: int = 0  # input tokens consumed before success/failure


# --------------------------------------------------------------------------- #
# Tokenisation.                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Token:
    text: str
    start: int


def tokenize(line: str) -> List[Token]:
    """Split ``line`` into whitespace-delimited tokens with start offsets."""
    tokens: List[Token] = []
    index = 0
    length = len(line)
    while index < length:
        if line[index].isspace():
            index += 1
            continue
        start = index
        while index < length and not line[index].isspace():
            index += 1
        tokens.append(Token(line[start:index], start))
    return tokens


# --------------------------------------------------------------------------- #
# Parameter validation.                                                       #
# --------------------------------------------------------------------------- #
def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _valid_ipv4_prefix(value: str) -> bool:
    if "/" not in value:
        return False
    address, _, prefix = value.partition("/")
    if not _valid_ipv4(address) or not prefix.isdigit():
        return False
    return 0 <= int(prefix) <= 32


def _parse_vlan_list(token: str) -> Optional[List[int]]:
    ids: set = set()
    for part in token.split(","):
        if not part:
            return None
        if "-" in part:
            lo_str, _, hi_str = part.partition("-")
            if not lo_str.isdigit() or not hi_str.isdigit():
                return None
            lo, hi = int(lo_str), int(hi_str)
            if hi < lo:
                return None
            for vlan in range(lo, hi + 1):
                ids.add(vlan)
        elif part.isdigit():
            ids.add(int(part))
        else:
            return None
    if not ids or any(not 1 <= vlan <= 4094 for vlan in ids):
        return None
    return sorted(ids)


def _month_number(token: str) -> Optional[int]:
    lowered = token.lower()
    for index, name in enumerate(_MONTHS, start=1):
        if name.startswith(lowered) and len(lowered) >= 3:
            return index
    return None


_INTERFACE_NAME_RE = re.compile(
    r"(?:Ethernet|FastEthernet|GigabitEthernet|Serial)\d+(?:/\d+)+(?:\.\d+)?$"
    r"|(?:Loopback|Vlan|Tunnel|Port-channel)\d+$"
)


def _valid_interface_name(canonical: str) -> bool:
    return bool(_INTERFACE_NAME_RE.fullmatch(canonical))


def expand_interface_range(value: str) -> List[str]:
    """Expand ``Gi0/0 - 3`` / ``e0/0, e0/2`` into canonical interface names."""
    text = value.strip()
    result: List[str] = []
    for group in (part for part in re.split(r"\s*,\s*", text) if part):
        halves = re.split(r"\s*-\s*", group, maxsplit=1)
        if len(halves) == 1:
            result.append(canonical_interface(halves[0]))
            continue
        start = canonical_interface(halves[0])
        end_text = halves[1].strip()
        if end_text.isdigit():
            match = re.match(r"^(.*?/)(\d+)$", start)
            if not match:
                return []
            end = match.group(1) + end_text
        else:
            end = canonical_interface(end_text)
        left = re.match(r"^(.*?/)(\d+)$", start)
        right = re.match(r"^(.*?/)(\d+)$", end)
        if not left or not right or left.group(1).lower() != right.group(1).lower():
            return []
        first, last = int(left.group(2)), int(right.group(2))
        if last < first or last - first > 64:
            return []
        result.extend(left.group(1) + str(index) for index in range(first, last + 1))
    return result


def _read_interface(tokens: List[Token], index: int) -> Tuple[int, str]:
    """Return (tokens_consumed, canonical name) for an INTERFACE at ``index``."""
    token = tokens[index].text
    if re.fullmatch(r"[A-Za-z-]+", token) and index + 1 < len(tokens):
        following = tokens[index + 1].text
        if re.match(r"^\d", following):
            return 2, canonical_interface(token + following)
    return 1, canonical_interface(token)


def _consume_param(
    param: Param,
    tokens: List[Token],
    index: int,
    line: str,
    node: object,
) -> Optional[Tuple[int, object]]:
    """Try to consume ``param`` starting at ``tokens[index]``.

    Returns ``(tokens_consumed, value)`` or ``None`` when the token(s) do not
    satisfy the parameter type.
    """
    ptype = param.ptype
    if ptype == LINE:
        value = line[tokens[index].start:].rstrip()
        return (len(tokens) - index, value) if value else None
    if ptype == INTERFACE_RANGE:
        text = line[tokens[index].start:].rstrip()
        names = expand_interface_range(text)
        if not names:
            return None
        for name in names:
            if is_physical_interface(name) and node is not None and not node.has_interface(name):
                return None
        return (len(tokens) - index, names)
    if ptype == INTERFACE:
        consumed, canonical = _read_interface(tokens, index)
        if not _valid_interface_name(canonical):
            return None
        if is_physical_interface(canonical) and node is not None and not node.has_interface(canonical):
            return None
        return (consumed, canonical)

    token = tokens[index].text
    if ptype == WORD:
        return (1, token)
    if ptype == RANGE:
        if re.fullmatch(r"-?\d+", token):
            value = int(token)
            if param.lo is not None and param.hi is not None and param.lo <= value <= param.hi:
                return (1, value)
        return None
    if ptype == IPV4:
        return (1, token) if _valid_ipv4(token) else None
    if ptype == IPV4_PREFIX:
        return (1, token) if _valid_ipv4_prefix(token) else None
    if ptype == MAC:
        if re.fullmatch(r"[0-9a-fA-F]{1,4}\.[0-9a-fA-F]{1,4}\.[0-9a-fA-F]{1,4}", token):
            try:
                return (1, format_mac(token))
            except ValueError:
                return None
        return None
    if ptype == VLAN_LIST:
        ids = _parse_vlan_list(token)
        return (1, ids) if ids else None
    if ptype == TIME:
        match = re.fullmatch(r"(\d{1,2}):(\d{2}):(\d{2})", token)
        if match:
            hour, minute, second = (int(group) for group in match.groups())
            if hour < 24 and minute < 60 and second < 60:
                return (1, (hour, minute, second))
        return None
    if ptype == MONTH:
        month = _month_number(token)
        return (1, month) if month else None
    return None


# --------------------------------------------------------------------------- #
# Command tree.                                                               #
# --------------------------------------------------------------------------- #
@dataclass
class _Edge:
    spec: TokenSpec
    node: "_TreeNode"
    help: str = ""


class _TreeNode:
    __slots__ = ("keyword_edges", "param_edges", "handlers")

    def __init__(self) -> None:
        self.keyword_edges: Dict[str, _Edge] = {}
        self.param_edges: Dict[Tuple[str, str], _Edge] = {}
        self.handlers: List[Command] = []


class CommandRegistry:
    """Holds every registered command and compiles per-mode command trees.

    Matching (IOS semantics), per input token:

    * an exact keyword match wins outright;
    * otherwise a keyword matched by unique prefix wins; a prefix matching more
      than one keyword is ``ambiguous``;
    * if no keyword matches, each typed parameter edge is tried in registration
      order and the first that validates wins;
    * if nothing matches, the token is ``invalid`` (its start offset is
      reported so the shell can align the ``^`` caret).

    When the input is exhausted at a node with a handler the result is ``ok``;
    otherwise it is ``incomplete``.
    """

    def __init__(self) -> None:
        self.commands: List[Command] = []
        self._trees: Dict[Tuple[str, int], _TreeNode] = {}
        self._built_for = -1

    # -- registration ------------------------------------------------------- #
    def add(self, command: Command) -> None:
        self.commands.append(command)
        self._trees.clear()
        self._built_for = -1

    def clear(self) -> None:
        self.commands.clear()
        self._trees.clear()
        self._built_for = -1

    # -- tree construction -------------------------------------------------- #
    def tree(self, mode: str, privilege: int) -> _TreeNode:
        if self._built_for != len(self.commands):
            self._trees.clear()
            self._built_for = len(self.commands)
        key = (mode, privilege)
        root = self._trees.get(key)
        if root is None:
            root = _TreeNode()
            for command in self.commands:
                if mode not in command.modes or command.privilege > privilege:
                    continue
                for expansion in command.expansions:
                    self._insert(root, expansion, command)
            self._trees[key] = root
        return root

    @staticmethod
    def _insert(root: _TreeNode, expansion: List[TokenSpec], command: Command) -> None:
        node = root
        for spec in expansion:
            if isinstance(spec, Keyword):
                key = spec.word.lower()
                edge = node.keyword_edges.get(key)
                if edge is None:
                    edge = _Edge(spec, _TreeNode(), _help_for(command, spec.word))
                    node.keyword_edges[key] = edge
                elif not edge.help:
                    edge.help = _help_for(command, spec.word)
            else:
                key_pair = (spec.ptype, spec.name)
                edge = node.param_edges.get(key_pair)
                if edge is None:
                    edge = _Edge(spec, _TreeNode(), command.help.get(spec.name, ""))
                    node.param_edges[key_pair] = edge
                elif not edge.help:
                    edge.help = command.help.get(spec.name, "")
            node = edge.node
        node.handlers.append(command)

    # -- resolution of a single position ---------------------------------

    def _resolve(
        self,
        node: _TreeNode,
        tokens: List[Token],
        index: int,
        node_ctx: object,
        line: str,
    ) -> Tuple[str, Optional[_TreeNode], int, object, bool]:
        """Resolve one position.

        Returns ``(status, next_node, next_index, info, is_keyword)`` where
        status is ``"ok"``/``"ambiguous"``/``"none"``.  For keyword matches
        ``info`` is the canonical keyword; for parameters ``info`` is
        ``(name, value)``.
        """
        token = tokens[index].text
        lowered = token.lower()
        exact = node.keyword_edges.get(lowered)
        if exact is not None:
            return ("ok", exact.node, index + 1, exact.spec.word, True)
        prefix_edges = [
            edge for key, edge in node.keyword_edges.items() if key.startswith(lowered)
        ]
        if len(prefix_edges) == 1:
            edge = prefix_edges[0]
            return ("ok", edge.node, index + 1, edge.spec.word, True)
        if len(prefix_edges) > 1:
            return ("ambiguous", None, index, None, False)
        for edge in node.param_edges.values():
            consumed = _consume_param(edge.spec, tokens, index, line, node_ctx)
            if consumed is not None:
                count, value = consumed
                return ("ok", edge.node, index + count, (edge.spec.name, value), False)
        return ("none", None, index, None, False)

    # -- matching ----------------------------------------------------------- #
    def match(self, mode: str, line: str, node_ctx: object, privilege: int) -> ParseResult:
        """Parse ``line`` in ``mode`` at ``privilege`` and classify it."""
        root = self.tree(mode, privilege)
        tokens = tokenize(line)
        node = root
        index = 0
        args: Dict[str, object] = {}
        path: List[str] = []
        while index < len(tokens):
            status, nxt, next_index, info, is_keyword = self._resolve(
                node, tokens, index, node_ctx, line
            )
            if status == "ambiguous":
                return ParseResult("ambiguous", path=list(path), matched_count=index)
            if status == "none":
                return ParseResult(
                    "invalid",
                    path=list(path),
                    error_offset=tokens[index].start,
                    matched_count=index,
                )
            if is_keyword:
                path.append(info)  # canonical keyword
            else:
                name, value = info  # type: ignore[misc]
                args[name] = value
            node = nxt  # type: ignore[assignment]
            index = next_index
        if node.handlers:
            return ParseResult(
                "ok",
                command=node.handlers[0],
                args=args,
                path=path,
                matched_count=index,
            )
        return ParseResult("incomplete", path=list(path), matched_count=index)

    # -- help --------------------------------------------------------------- #
    def help(self, mode: str, buffer: str, node_ctx: object, privilege: int) -> str:
        """Return the ``?`` listing for ``buffer`` (always ends with a newline)."""
        root = self.tree(mode, privilege)
        tokens = tokenize(buffer)
        at_fresh_token = buffer == "" or buffer[-1:].isspace()
        upto = len(tokens) if at_fresh_token else len(tokens) - 1
        node = self._walk(root, tokens, upto, node_ctx, buffer)
        if node is None:
            return "% Unrecognized command\n"
        if at_fresh_token:
            return self._list_next(node)
        return self._list_matching(node, tokens[-1].text)

    def _walk(
        self,
        root: _TreeNode,
        tokens: List[Token],
        upto: int,
        node_ctx: object,
        line: str,
    ) -> Optional[_TreeNode]:
        node = root
        index = 0
        while index < upto:
            status, nxt, next_index, _info, _is_keyword = self._resolve(
                node, tokens, index, node_ctx, line
            )
            if status != "ok" or next_index > upto:
                return None
            node = nxt  # type: ignore[assignment]
            index = next_index
        return node

    @staticmethod
    def _list_next(node: _TreeNode) -> str:
        rows: List[Tuple[str, str]] = []
        for edge in sorted(node.keyword_edges.values(), key=lambda item: item.spec.word.lower()):
            rows.append((edge.spec.word, edge.help))
        for edge in node.param_edges.values():
            rows.append((edge.spec.placeholder, edge.help))
        if node.handlers:
            rows.append(("<cr>", ""))
        return _format_help_rows(rows)

    @staticmethod
    def _list_matching(node: _TreeNode, partial: str) -> str:
        lowered = partial.lower()
        matched = [
            edge for key, edge in node.keyword_edges.items() if key.startswith(lowered)
        ]
        if matched:
            rows = [
                (edge.spec.word, edge.help)
                for edge in sorted(matched, key=lambda item: item.spec.word.lower())
            ]
            return _format_help_rows(rows)
        if node.param_edges:
            rows = [(edge.spec.placeholder, edge.help) for edge in node.param_edges.values()]
            return _format_help_rows(rows)
        return "% Unrecognized command\n"

    # -- completion --------------------------------------------------------- #
    def complete(self, mode: str, buffer: str, node_ctx: object, privilege: int) -> Optional[str]:
        """Tab-complete a unique keyword prefix, else return ``None``."""
        if buffer == "" or buffer[-1:].isspace():
            return None
        root = self.tree(mode, privilege)
        tokens = tokenize(buffer)
        node = self._walk(root, tokens, len(tokens) - 1, node_ctx, buffer)
        if node is None:
            return None
        partial = tokens[-1]
        matches = [
            edge for key, edge in node.keyword_edges.items() if key.startswith(partial.text.lower())
        ]
        if len(matches) == 1:
            return buffer[: partial.start] + matches[0].spec.word + " "
        return None


def _help_for(command: Command, word: str) -> str:
    return command.help.get(word) or command.help.get(word.lower()) or ""


def _format_help_rows(rows: List[Tuple[str, str]]) -> str:
    if not rows:
        return "\n"
    width = max(len(token) for token, _ in rows)
    lines: List[str] = []
    for token, description in rows:
        if description:
            lines.append(f"  {token.ljust(width)}  {description}")
        else:
            lines.append(f"  {token}")
    return "\n".join(lines) + "\n"


#: Public alias so the shell can format filter ``| ?`` rows identically.
format_help_rows = _format_help_rows


#: Process-wide registry populated by the :func:`command` decorator.
REGISTRY = CommandRegistry()


def command(
    pattern: str,
    modes: Tuple[str, ...],
    privilege: int = 1,
    help: Optional[Dict[str, str]] = None,
    hidden: bool = False,
    name: Optional[str] = None,
):
    """Register a command handler described by ``pattern`` (see module docs)."""

    def decorator(handler):
        REGISTRY.add(
            Command(
                pattern=pattern,
                modes=tuple(modes),
                privilege=privilege,
                help=dict(help or {}),
                hidden=hidden,
                handler=handler,
                name=name,
            )
        )
        return handler

    return decorator
