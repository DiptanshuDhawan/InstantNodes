"""Thread-safe process singleton for native simulation runtimes."""

from __future__ import annotations

from pathlib import Path
import threading
import uuid
from typing import Callable, Dict, Optional, TypeVar, Union

from .runtime import (
    InvalidRuntimeState,
    RuntimeNotFound,
    SimulationRuntime,
    SimulationSnapshot,
    SimulatorError,
    TerminalAttachment,
)


T = TypeVar("T")


class SimulationManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._runtimes: Dict[str, SimulationRuntime] = {}
        self._terminal_runtimes: Dict[str, str] = {}

    @staticmethod
    def generate_runtime_id() -> str:
        return "sim-" + uuid.uuid4().hex

    def create(
        self,
        slug: Optional[str] = None,
        yaml_path: Optional[str] = None,
        runtime_id: Optional[str] = None,
        definition: Optional[dict] = None,
    ) -> SimulationRuntime:
        if yaml_path is None:
            raise SimulatorError("A lab YAML path is required")
        resolved_slug = slug or Path(yaml_path).resolve().parent.name
        identifier = runtime_id or self.generate_runtime_id()
        if not identifier.startswith("sim-"):
            raise SimulatorError("Simulator runtime IDs must start with 'sim-'")
        with self._lock:
            if identifier in self._runtimes:
                raise SimulatorError(f"Simulator runtime '{identifier}' already exists")
        runtime = SimulationRuntime(
            identifier,
            resolved_slug,
            yaml_path,
            definition=definition,
        )
        with self._lock:
            if identifier in self._runtimes:
                raise SimulatorError(f"Simulator runtime '{identifier}' already exists")
            self._runtimes[identifier] = runtime
        return runtime

    create_runtime = create

    def get(self, runtime_id: str) -> SimulationRuntime:
        with self._lock:
            runtime = self._runtimes.get(runtime_id)
        if runtime is None:
            raise RuntimeNotFound(f"Simulator runtime '{runtime_id}' was not found")
        return runtime

    def find(self, runtime_id: Optional[str]) -> Optional[SimulationRuntime]:
        if not runtime_id:
            return None
        with self._lock:
            return self._runtimes.get(runtime_id)

    def stop(self, runtime_id: Optional[str]) -> bool:
        runtime = self.find(runtime_id)
        if runtime is None:
            return False
        runtime.stop()
        return True

    def remove(self, runtime_id: Optional[str]) -> bool:
        if not runtime_id:
            return False
        with self._lock:
            runtime = self._runtimes.pop(runtime_id, None)
            stale = [
                terminal_id
                for terminal_id, identifier in self._terminal_runtimes.items()
                if identifier == runtime_id
            ]
            for terminal_id in stale:
                self._terminal_runtimes.pop(terminal_id, None)
        if runtime is not None:
            runtime.stop()
            return True
        return False

    def reset(self, runtime_id: str) -> int:
        return self.get(runtime_id).reset()

    reset_to_authored_baseline = reset

    def status(self, runtime_id: str) -> dict:
        return self.get(runtime_id).status_report()

    def attach(
        self,
        runtime_id: str,
        node_name: str,
        sink: Optional[Callable[[str], None]] = None,
    ) -> TerminalAttachment:
        """Attach a terminal viewer to a node's persistent console.

        ``sink`` (optional) is called with every later output chunk of that
        console (push model); ``initial_output`` carries the first screen.
        """
        runtime = self.get(runtime_id)
        attachment = runtime.attach(node_name, sink=sink)
        with self._lock:
            self._terminal_runtimes[attachment.connection_id] = runtime_id
        return attachment

    attach_terminal = attach

    def execute(
        self,
        attachment: Union[TerminalAttachment, str],
        data: str,
        runtime_id: Optional[str] = None,
    ) -> str:
        connection_id = (
            attachment.connection_id
            if isinstance(attachment, TerminalAttachment)
            else attachment
        )
        identifier = runtime_id
        if isinstance(attachment, TerminalAttachment):
            identifier = attachment.runtime_id
        if identifier is None:
            with self._lock:
                identifier = self._terminal_runtimes.get(connection_id)
        if identifier is None:
            raise RuntimeNotFound("Terminal is not associated with a simulator runtime")
        return self.get(identifier).execute(connection_id, data)

    execute_terminal_input = execute

    def detach(self, attachment: Union[TerminalAttachment, str]) -> None:
        connection_id = (
            attachment.connection_id
            if isinstance(attachment, TerminalAttachment)
            else attachment
        )
        with self._lock:
            runtime_id = self._terminal_runtimes.pop(connection_id, None)
        if runtime_id:
            runtime = self.find(runtime_id)
            if runtime:
                runtime.detach(connection_id)

    def snapshot(self, runtime_id: str) -> SimulationSnapshot:
        return self.get(runtime_id).snapshot()

    def grade(self, runtime_id: str, grader: Callable[[SimulationSnapshot], T]) -> T:
        """Grade one immutable snapshot, never live terminal state."""
        snapshot = self.snapshot(runtime_id)
        if snapshot.status != "running":
            raise InvalidRuntimeState("Only a running simulator can be graded")
        return grader(snapshot)

    def clear(self) -> None:
        """Dispose all runtimes; intended for process shutdown and unit tests."""
        with self._lock:
            runtimes = list(self._runtimes.values())
            self._runtimes.clear()
            self._terminal_runtimes.clear()
        for runtime in runtimes:
            runtime.stop()


manager = SimulationManager()
simulation_manager = manager


def get_manager() -> SimulationManager:
    return manager
