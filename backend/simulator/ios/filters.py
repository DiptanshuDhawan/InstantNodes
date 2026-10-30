"""Output pipes for ``show ... | <filter>`` (Cisco IOS output modifiers).

The IOS shell (``ios/shell.py``) splits an entered line at the output pipe with
:func:`split_pipe`, parses the filter spec with :func:`parse_filter`, runs the
command to produce text, then calls :meth:`OutputFilter.apply` on that text.
``show ... | ?`` help is served by :func:`filter_help`.

Supported filters (unique-prefix abbreviations allowed):

* ``include REGEX``  keep lines matching REGEX
* ``exclude REGEX``  drop lines matching REGEX
* ``begin REGEX``    output from the first matching line onward
* ``section REGEX``  output each matching line plus its more-indented sub-lines
* ``count REGEX``    replace output with ``Number of lines which match regexp = N``

Errors are reported as :class:`FilterSyntaxError` carrying an ``offset``
(relative to the spec string handed to :func:`parse_filter`) and a ``kind``:

* ``"invalid"``     the keyword matches no filter, or the regex does not compile
* ``"incomplete"``  the keyword has no regex argument (or no keyword was given)
* ``"ambiguous"``   the keyword prefix matches more than one filter
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

__all__ = [
    "FilterSyntaxError",
    "OutputFilter",
    "split_pipe",
    "parse_filter",
    "filter_help",
    "FILTER_KEYWORDS",
]


#: Ordered mapping of filter keyword -> one-line help (``| ?`` output order).
FILTER_KEYWORDS: Dict[str, str] = {
    "begin": "Begin with the line that matches",
    "count": "Count number of lines which match regexp",
    "exclude": "Exclude lines that match",
    "include": "Include lines that match",
    "section": "Filter a section of output",
}


class FilterSyntaxError(Exception):
    """Raised by :func:`parse_filter` for a malformed filter spec.

    ``offset`` is the 0-based index into the spec string where the problem is;
    ``kind`` is one of ``"invalid"``, ``"incomplete"`` or ``"ambiguous"``.
    """

    def __init__(self, offset: int, kind: str) -> None:
        self.offset = int(offset)
        self.kind = kind
        super().__init__(f"{kind} filter spec at offset {offset}")


def split_pipe(line: str) -> Tuple[str, Optional[str], int]:
    """Split ``line`` at the first ``|`` that is preceded by whitespace.

    Returns ``(command_text, pipe_spec, pipe_offset)``.  ``command_text`` is the
    text before the pipe (right-stripped); ``pipe_spec`` is everything after the
    pipe, verbatim (so offsets from :func:`parse_filter` line up); ``pipe_offset``
    is the index of the ``|`` in the original line.  When there is no such pipe,
    returns ``(line, None, -1)``.
    """
    for index in range(1, len(line)):
        if line[index] == "|" and line[index - 1].isspace():
            return line[:index].rstrip(), line[index + 1:], index
    return line, None, -1


def _resolve_keyword(token: str, start: int, keywords: Dict[str, str]) -> str:
    """Resolve a (possibly abbreviated) filter keyword, else raise."""
    lowered = token.lower()
    if lowered in keywords:  # exact match wins over any longer keyword
        return lowered
    matches = [name for name in keywords if name.startswith(lowered)]
    if not matches:
        raise FilterSyntaxError(start, "invalid")
    if len(matches) > 1:
        raise FilterSyntaxError(start, "ambiguous")
    return matches[0]


def parse_filter(spec: str, keywords: Optional[Dict[str, str]] = None) -> "OutputFilter":
    """Parse a filter spec (the text after ``|``) into an :class:`OutputFilter`.

    ``keywords`` defaults to :data:`FILTER_KEYWORDS`; it exists so callers/tests
    can exercise prefix resolution (including the ambiguous branch) against an
    alternate keyword table.  Raises :class:`FilterSyntaxError` on any problem.
    """
    table = FILTER_KEYWORDS if keywords is None else keywords

    # Locate the keyword token.
    kw_start = 0
    while kw_start < len(spec) and spec[kw_start].isspace():
        kw_start += 1
    if kw_start >= len(spec):
        raise FilterSyntaxError(len(spec), "incomplete")  # no keyword at all

    kw_end = kw_start
    while kw_end < len(spec) and not spec[kw_end].isspace():
        kw_end += 1
    token = spec[kw_start:kw_end]
    keyword = _resolve_keyword(token, kw_start, table)

    # Locate the regex argument (remainder of the spec after one+ spaces).
    arg_start = kw_end
    while arg_start < len(spec) and spec[arg_start].isspace():
        arg_start += 1
    if arg_start >= len(spec):
        raise FilterSyntaxError(len(spec), "incomplete")  # keyword without regex
    pattern = spec[arg_start:]

    try:
        regex = re.compile(pattern)
    except re.error:
        raise FilterSyntaxError(arg_start, "invalid")

    return OutputFilter(keyword, regex, pattern)


def filter_help(spec_prefix: str) -> List[Tuple[str, str]]:
    """Rows for ``show ... | ?`` limited to keywords matching ``spec_prefix``."""
    token = (spec_prefix or "").strip().lower()
    return [
        (name, FILTER_KEYWORDS[name])
        for name in ("begin", "count", "exclude", "include", "section")
        if name.startswith(token)
    ]


@dataclass
class OutputFilter:
    """A parsed output filter.  Apply it with :meth:`apply`."""

    mode: str
    regex: "re.Pattern[str]"
    pattern: str

    def apply(self, text: str) -> str:
        """Filter ``text`` (``\\n``-separated) and return the filtered text."""
        if self.mode == "count":
            count = sum(1 for line in _split_lines(text) if self.regex.search(line))
            return f"Number of lines which match regexp = {count}"

        lines = _split_lines(text)
        if self.mode == "include":
            kept = [line for line in lines if self.regex.search(line)]
        elif self.mode == "exclude":
            kept = [line for line in lines if not self.regex.search(line)]
        elif self.mode == "begin":
            kept = []
            started = False
            for line in lines:
                if not started and self.regex.search(line):
                    started = True
                if started:
                    kept.append(line)
        elif self.mode == "section":
            kept = _sections(lines, self.regex)
        else:  # pragma: no cover - defensive
            kept = lines
        return "\n".join(kept)


def _split_lines(text: str) -> List[str]:
    """Split ``text`` into logical lines, dropping the trailing-newline artifact."""
    if text == "":
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _sections(lines: List[str], regex: "re.Pattern[str]") -> List[str]:
    """Each line matching ``regex`` plus the lines indented beneath it."""
    out: List[str] = []
    index = 0
    total = len(lines)
    while index < total:
        line = lines[index]
        if regex.search(line):
            base = _indent(line)
            out.append(line)
            index += 1
            while index < total:
                nxt = lines[index]
                if nxt.strip() and _indent(nxt) <= base:
                    break
                out.append(nxt)
                index += 1
        else:
            index += 1
    return out
