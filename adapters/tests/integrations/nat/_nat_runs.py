"""Run code inside real NAT Runners, with the exporters an acs_guardian middleware registered on its builder."""
from __future__ import annotations

from types import SimpleNamespace

from nat.builder.context import ContextState
from nat.builder.workflow_builder import WorkflowBuilder
from nat.observability.exporter_manager import ExporterManager
from nat.runtime.runner import Runner

from acs.integrations.nat.adapter import build_acs_middleware


class Fn:
    """A Runner entry function whose body is a coroutine function of the run's input."""
    has_single_output = True

    def __init__(self, name: str, body) -> None:
        self.config = SimpleNamespace(name=name, type="local")
        self.instance_name = self.display_name = name
        self.body = body

    async def ainvoke(self, message, to_type=None):
        return await self.body(message)


async def with_middleware(config, body, *, with_builder: bool = True) -> None:
    """Await body(middleware, run) with a middleware NAT built; run(name, entry, message) runs one Runner."""
    async with WorkflowBuilder() as builder, \
            build_acs_middleware(config, builder if with_builder else None) as middleware:
        exporters = {name: c.instance for name, c in builder._telemetry_exporters.items()} if with_builder else {}

        async def run(name: str, entry, message: str = "input"):
            async with Runner(message, Fn(name, entry), ContextState.get(),
                              ExporterManager.from_exporters(exporters)) as runner:
                return await runner.result()
        await body(middleware, run)
