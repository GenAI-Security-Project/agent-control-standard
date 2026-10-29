"""Reading a negotiated ServerHello."""
from __future__ import annotations




def method_evaluated(server_hello: dict | None, method: str) -> bool:
    """Whether the negotiated Guardian evaluates `method`; handshake.json says
    clients MUST treat methods missing from methods_evaluated as
    ALLOW-by-default. With no negotiated list, every method counts as
    evaluated."""
    if not isinstance(server_hello, dict):
        return True
    evaluated = server_hello.get("methods_evaluated")
    if not isinstance(evaluated, list):
        return True
    return method in evaluated
