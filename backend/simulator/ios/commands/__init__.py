"""IOS command modules.

Importing a command module executes its ``@command`` registrations against
``simulator.ios.parser.REGISTRY``.  :func:`ensure_registered` auto-discovers and
imports every non-underscore module in this package exactly once (the shell
calls it before building command trees), so a new command module just needs to
be dropped into this directory -- no edit to this file is required.

Imports are tolerant: a module that fails to import (for example one that is
being written concurrently) is skipped and recorded in :data:`IMPORT_ERRORS`
rather than breaking the whole command set.  The integrator checks that
``IMPORT_ERRORS`` is empty once all modules are in place.
"""

from __future__ import annotations

import importlib
import pkgutil

_REGISTERED = False

#: module name -> repr(exception) for any command module that failed to import.
IMPORT_ERRORS: dict = {}


def ensure_registered() -> None:
    """Import every command module once so its registrations have run."""
    global _REGISTERED
    if _REGISTERED:
        return
    _REGISTERED = True  # set first so a failing import cannot cause re-entrancy
    for info in pkgutil.iter_modules(__path__):
        name = info.name
        if name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{__name__}.{name}")
        except Exception as exc:  # pragma: no cover - defensive during parallel dev
            IMPORT_ERRORS[name] = repr(exc)
