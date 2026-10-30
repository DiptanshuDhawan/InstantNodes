"""Native in-process network simulation API."""

from .manager import SimulationManager, get_manager, manager, simulation_manager
from .runtime import (
    InvalidRuntimeState,
    NodeNotFound,
    RuntimeNotFound,
    SimulationRuntime,
    SimulationSnapshot,
    SimulatorError,
    TerminalAttachment,
    TerminalNotFound,
    classify_node,
)

__all__ = [
    "SimulationManager",
    "SimulationRuntime",
    "SimulationSnapshot",
    "SimulatorError",
    "RuntimeNotFound",
    "InvalidRuntimeState",
    "NodeNotFound",
    "TerminalNotFound",
    "TerminalAttachment",
    "classify_node",
    "get_manager",
    "manager",
    "simulation_manager",
]
