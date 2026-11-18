"""Install the Relay extra outside the checkout and exercise its native plugin."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

wheel = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="acs-relay-wheel-") as directory:
    root = Path(directory)
    subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(root / "venv")], check=True
    )
    python = str(root / "venv/bin/python")
    subprocess.run(
        ["uv", "pip", "install", "--python", python, f"{wheel}[relay]"], check=True
    )
    code = """
import asyncio, os
from pathlib import Path
import nemo_relay as relay
from acs.integrations.relay.plugin import register
from acs.integrations.relay.adapter import ACSGuardianDenied
from acs.testing.harness import ProgrammableGuardian
from acs.client import _handshake
os.environ['ACS_HMAC_SECRET'] = 'installed-relay-wheel-test-secret'
os.environ['ACS_HMAC_KEY_ID'] = 'test-key'
_handshake._HANDSHAKE_CACHE_DIR = Path('sessions')
async def main():
    register()
    with ProgrammableGuardian(hmac_secret=os.environ['ACS_HMAC_SECRET']) as guardian:
        guardian.handlers['steps/toolCallRequest'] = lambda req: {'decision':'deny','reasoning':'wheel check'}
        calls = []
        async def tool(args):
            calls.append(args)
            return relay.ToolExecutionResult('should be blocked')
        config = {'version':1,'components':[{'kind':'acs_guardian','config':{'guardian_url':guardian.url()}}]}
        async with relay.plugin.activate(config):
            try:
                await relay.tools.execute('probe',{},tool)
            except ACSGuardianDenied:
                pass
            else:
                raise AssertionError('DENY did not block installed tool')
        assert not calls
asyncio.run(main())
"""
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONPATH", "ACS_SPEC_DIR", "VIRTUAL_ENV")
    }
    subprocess.run([python, "-c", code], cwd=root, env=env, check=True, timeout=60)
print("PASS installed Relay wheel denies a real managed tool")
