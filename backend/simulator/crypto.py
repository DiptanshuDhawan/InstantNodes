"""Cisco-compatible credential encodings used by the native simulator.

* Type 5 secrets use FreeBSD MD5-crypt (``$1$salt$hash``), as rendered by IOS
  for ``enable secret`` and ``username ... secret``.
* Type 7 passwords use the well-known reversible Cisco Vigenere encoding, as
  rendered for line passwords when ``service password-encryption`` is enabled.

Everything here is deterministic so repeated ``show running-config`` output is
stable for a given device and credential.
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_TYPE7_KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"
_TYPE5_PATTERN = re.compile(r"^\$1\$([./0-9A-Za-z]{1,8})\$([./0-9A-Za-z]{22})$")
_TYPE7_PATTERN = re.compile(r"^(\d{2})((?:[0-9A-Fa-f]{2})*)$")


def _to64(value: int, length: int) -> str:
    output = []
    for _ in range(length):
        output.append(_ITOA64[value & 0x3F])
        value >>= 6
    return "".join(output)


def md5_crypt(password: str, salt: str) -> str:
    """Return the ``$1$`` MD5-crypt hash of ``password`` with ``salt``."""
    magic = b"$1$"
    secret = password.encode("utf-8")
    salt_bytes = salt[:8].encode("ascii")

    alternate = hashlib.md5(secret + salt_bytes + secret).digest()
    context = hashlib.md5(secret + magic + salt_bytes)
    remaining = len(secret)
    while remaining > 0:
        context.update(alternate[: min(16, remaining)])
        remaining -= 16
    length = len(secret)
    while length:
        context.update(b"\x00" if length & 1 else secret[:1])
        length >>= 1
    final = context.digest()

    for round_number in range(1000):
        step = hashlib.md5()
        step.update(secret if round_number & 1 else final)
        if round_number % 3:
            step.update(salt_bytes)
        if round_number % 7:
            step.update(secret)
        step.update(final if round_number & 1 else secret)
        final = step.digest()

    encoded = (
        _to64((final[0] << 16) | (final[6] << 8) | final[12], 4)
        + _to64((final[1] << 16) | (final[7] << 8) | final[13], 4)
        + _to64((final[2] << 16) | (final[8] << 8) | final[14], 4)
        + _to64((final[3] << 16) | (final[9] << 8) | final[15], 4)
        + _to64((final[4] << 16) | (final[10] << 8) | final[5], 4)
        + _to64(final[11], 2)
    )
    return "$1$" + salt[:8] + "$" + encoded


def deterministic_salt(*parts: str, length: int = 4) -> str:
    """Return a stable crypt salt derived from the supplied context strings."""
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).digest()
    return "".join(_ITOA64[byte & 0x3F] for byte in digest[:length])


def type5_secret(password: str, *context: str) -> str:
    """Return an IOS type 5 secret with a stable, context-derived salt."""
    return md5_crypt(password, deterministic_salt("type5", *context, password))


def is_type5(value: str) -> bool:
    return bool(_TYPE5_PATTERN.match(value or ""))


def verify_type5(password: str, encoded: str) -> bool:
    match = _TYPE5_PATTERN.match(encoded or "")
    if not match:
        return False
    return md5_crypt(password, match.group(1)) == encoded


def type7_encode(password: str, seed: int = 2) -> str:
    """Encode ``password`` with Cisco's reversible type 7 algorithm."""
    seed = seed % 16
    output = [f"{seed:02d}"]
    for index, character in enumerate(password):
        key = _TYPE7_KEY[(seed + index) % len(_TYPE7_KEY)]
        output.append(f"{ord(character) ^ ord(key):02X}")
    return "".join(output)


def type7_seed(*context: str) -> int:
    digest = hashlib.sha256("\0".join(("type7",) + context).encode("utf-8")).digest()
    return digest[0] % 16


def type7_decode(encoded: str) -> Optional[str]:
    """Decode a type 7 string, returning ``None`` when it is malformed."""
    match = _TYPE7_PATTERN.match(encoded or "")
    if not match:
        return None
    seed = int(match.group(1))
    if seed > 15:
        return None
    payload = match.group(2)
    output = []
    for index in range(0, len(payload), 2):
        key = _TYPE7_KEY[(seed + index // 2) % len(_TYPE7_KEY)]
        output.append(chr(int(payload[index : index + 2], 16) ^ ord(key)))
    return "".join(output)


def verify_credential(
    password: str,
    plaintext: Optional[str] = None,
    encoded: Optional[str] = None,
) -> bool:
    """Verify a password against a stored plaintext value or encoded secret.

    ``encoded`` accepts the IOS forms ``"5 $1$..."``, ``"$1$..."``, ``"7 0822..."``
    or ``"0 plaintext"``.
    """
    if plaintext is not None:
        return password == plaintext
    if not encoded:
        return False
    value = encoded.strip()
    kind = None
    parts = value.split(None, 1)
    if len(parts) == 2 and parts[0] in {"0", "5", "7", "8", "9"}:
        kind, value = parts
    if kind in (None, "5") and is_type5(value):
        return verify_type5(password, value)
    if kind == "7":
        decoded = type7_decode(value)
        return decoded is not None and decoded == password
    if kind == "0":
        return password == value
    return False
