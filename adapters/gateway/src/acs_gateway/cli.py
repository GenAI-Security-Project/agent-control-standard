"""The acs-gateway command: the model port and, when configured, the admin port."""
from __future__ import annotations

import asyncio
import os
import sys

from acs_gateway.config import GatewayConfig, prepare_state_dirs


async def _serve(servers: list) -> int:
    main_task = asyncio.create_task(servers[0].serve())
    # The admin port opens only after the model port's startup, which waits for the Guardian, has finished.
    while not servers[0].started and not main_task.done():
        await asyncio.sleep(0.05)
    tasks = [main_task, *(asyncio.create_task(s.serve()) for s in servers[1:])] if servers[0].started else [main_task]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for server in servers:
        server.should_exit = True
    await asyncio.gather(*tasks, return_exceptions=True)
    return 0 if servers[0].started else 1


def main() -> int:
    try:
        # acs.client reads its state directories when first imported, so they are set before app imports it.
        prepare_state_dirs(os.environ)
        config = GatewayConfig.from_env(os.environ)
    except (ValueError, OSError) as e:
        sys.stderr.write(f"acs-gateway: {e}\n")
        return 2
    import uvicorn

    from acs_gateway.app import create_admin_app, create_app, load_admin_token, load_secret_file

    app = create_app(config)
    servers = [uvicorn.Server(uvicorn.Config(app, host=config.listen_host, port=config.listen_port,
                                             lifespan="on", log_level="info"))]
    if config.admin_port is not None:
        if config.admin_token_file is None:
            sys.stderr.write("acs-gateway: ACS_GATEWAY_ADMIN_PORT needs ACS_GATEWAY_ADMIN_TOKEN_FILE\n")
            return 2
        try:
            token = load_admin_token(config.admin_token_file)
        except (ValueError, OSError) as e:
            sys.stderr.write(f"acs-gateway: {e}\n")
            return 2
        admin = create_admin_app(app.state.gateway, token)
        servers.append(uvicorn.Server(uvicorn.Config(admin, host=config.admin_host, port=config.admin_port,
                                                     lifespan="off", log_level="info")))
    approvals = app.state.gateway.approvals
    if approvals is not None:
        from acs_gateway.approver import create_approver_app

        assert config.approver_token_file is not None
        try:
            secret = load_secret_file(config.approver_token_file, "ACS_GATEWAY_APPROVER_TOKEN_FILE")
        except (ValueError, OSError) as e:
            sys.stderr.write(f"acs-gateway: {e}\n")
            return 2
        # The approver page (LAB-08). Same process and event loop as the model port, so an answer wakes the held
        # request directly. Opens after the model port's startup, like the admin port.
        servers.append(uvicorn.Server(uvicorn.Config(create_approver_app(approvals, secret, config.approver_host),
                                                     host=config.approver_host, port=config.approver_port,
                                                     lifespan="off", log_level="info")))
    sys.stderr.write(f"acs-gateway: mode {config.mode}, model port {config.listen_port}\n")
    return asyncio.run(_serve(servers))
