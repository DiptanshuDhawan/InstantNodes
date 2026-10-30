"""Grading service for native in-process simulator sessions."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from grading_engine import grade_lab as _grade_lab
from simulator import manager


def grade_session(
    lab_yaml_path: str,
    gns3_project_id: str,
    skip_tasks: list = None,
) -> dict:
    """Grade an immutable snapshot of one native runtime.

    ``gns3_project_id`` is retained as the parameter name during migration; its
    value is an opaque ``sim-...`` runtime ID.
    """
    lab_dir = os.path.dirname(os.path.abspath(lab_yaml_path))
    return manager.grade(
        gns3_project_id,
        lambda snapshot: _grade_lab(
            lab_yaml_path,
            skip_tasks=skip_tasks,
            lab_dir=lab_dir,
            snapshot=snapshot,
        ),
    )
