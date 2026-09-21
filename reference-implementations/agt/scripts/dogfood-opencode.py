#!/usr/bin/env python3
"""Manual host-level evidence for #92 using the local-model recipe in the host README."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import socketserver
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument('scenario', choices=['live', 'proceed-loss', 'deny-loss'])
parser.add_argument('--output', type=Path, required=True, help='New scratch directory; must not exist')
args = parser.parse_args()
tree = Path(__file__).resolve().parents[1]
root = args.output.resolve()
if root.exists():
    parser.error('--output must name a new directory')
bun = shutil.which('bun')
opencode = shutil.which('opencode')
if not bun or not opencode:
    parser.error('Install bun and opencode and put them on PATH')
root.mkdir(parents=True)
# Use only the environment needed for local executables. Do not inherit provider
# credentials or host settings. PWD and --dir must agree with subprocess cwd.
env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SHELL'] if key in os.environ}
env['PWD'] = str(root.resolve())
for kind in ['DATA', 'CACHE', 'CONFIG', 'STATE']:
    env[f'XDG_{kind}_HOME'] = str(root / ('xdg-' + kind.lower()))
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
env.update(ACS_GUARDIAN_PORT=str(port), ACS_GUARDIAN_HOST='127.0.0.1',
           ACS_GUARDIAN_URL=f'http://127.0.0.1:{port}/acs',
           ACS_ON_DECISION_FAILURE='deny' if args.scenario == 'deny-loss' else 'proceed',
           ACS_AUDIT_LOG=str(root / 'audit.jsonl'), ACS_ENVELOPE_LOG=str(root / 'envelopes.jsonl'),
           ACS_SESSION_CONTEXT_LOG=str(root / 'context.jsonl'))
guardian_log = (root / 'guardian.log').open('w')
guardian = subprocess.Popen([bun, 'run', 'packages/guardian/src/main.ts'],
                            cwd=tree, env=env, stdout=guardian_log, stderr=subprocess.STDOUT)
commands = ["printf '%s\\n' 'ACS_ALLOWED' > allowed.txt",
            "echo rm -rf / > denied.txt" if args.scenario == 'live'
            else "printf '%s\\n' 'ACS_OUTAGE' > outage.txt"]
fault_injected = False
model_requests = []

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *unused):
        pass

    def do_POST(self):
        global fault_injected
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        count = sum(m['role'] == 'tool' for m in body['messages'])
        tool_loop = any(t.get('function', {}).get('name') == 'bash' for t in body.get('tools', []))
        model_requests.append({'tool_loop': tool_loop, 'tool_results': count,
                               'command': commands[count] if tool_loop and count < 2 else None})
        if tool_loop and args.scenario.endswith('-loss') and count == 1 and not fault_injected:
            assert (root / 'allowed.txt').read_text() == 'ACS_ALLOWED\n'
            guardian.terminate()
            guardian.wait(timeout=10)
            fault_injected = True
            (root / 'fault.json').write_text(json.dumps({'after_first_tool_result': True, 'guardian_returncode': guardian.returncode}))
        common = {'id': 'chatcmpl-acs-fixture', 'created': 1700000000, 'model': 'model-1', 'object': 'chat.completion.chunk'}
        if tool_loop and count < 2:
            delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': f'call_fixture_{count}',
                'type': 'function', 'function': {'name': 'bash', 'arguments': json.dumps({'command': commands[count], 'description': 'ACS conformance marker'})}}]}
            finish = 'tool_calls'
        else:
            delta = {'role': 'assistant', 'content': 'FIXTURE_DONE'}
            finish = 'stop'
        chunks = [{**common, 'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}]},
                  {**common, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}]}]
        payload = ''.join('data: ' + json.dumps(c) + '\n\n' for c in chunks) + 'data: [DONE]\n\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(payload.encode())))
        self.end_headers()
        self.wfile.write(payload.encode())

class LocalServer(ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'localhost'
        self.server_port = self.server_address[1]

server = LocalServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
config = {
    '$schema': 'https://opencode.ai/config.json', 'model': 'stub/model-1', 'small_model': 'stub/model-1',
    'plugin': [str(tree / 'hosts/opencode/acs-plugin.ts')], 'permission': {'*': 'deny', 'bash': 'allow'},
    'autoupdate': False, 'share': 'disabled', 'enabled_providers': ['stub'],
    'provider': {'stub': {'npm': '@ai-sdk/openai-compatible', 'name': 'ACS fixture',
        'options': {'baseURL': f'http://127.0.0.1:{server.server_port}/v1', 'apiKey': 'unused'},
        'models': {'model-1': {'id': 'model-1', 'tool_call': True, 'limit': {'context': 32768, 'output': 4096}}}}}}
(root / 'opencode.json').write_text(json.dumps(config, indent=2))
try:
    for _ in range(100):
        if 'Guardian listening at' in (root / 'guardian.log').read_text():
            break
        if guardian.poll() is not None:
            raise RuntimeError((root / 'guardian.log').read_text())
        time.sleep(.1)
    else:
        raise RuntimeError('Guardian startup timed out')
    with (root / 'host.jsonl').open('w') as stdout, (root / 'host.stderr').open('w') as stderr:
        result = subprocess.run([opencode, 'run', '--dir', str(root), '--model', 'stub/model-1',
                                 '--title', 'ACS decision-honoring fixture', '--format', 'json', 'Run the conformance fixture.'],
                                cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=180)
    if result.returncode:
        raise RuntimeError(f'OpenCode exited {result.returncode}; inspect {root / "host.stderr"}')

    def rows(name):
        path = root / name
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    wire = rows('envelopes.jsonl')
    host = rows('host.jsonl')
    audit = rows('audit.jsonl')
    tools = [event['part'] for event in host if event['type'] == 'tool_use']
    responses = [row for row in wire if row['direction'] == 'response']
    requests = [row for row in wire if row['direction'] == 'request']
    posture = env['ACS_ON_DECISION_FAILURE']

    def check(condition, message):
        if not condition:
            raise RuntimeError(f'{message}; inspect evidence in {root}')

    check(len(tools) == 2, 'Expected exactly two tool outcomes')
    check(all(part['tool'] == 'bash' for part in tools), 'Unexpected tool')
    check([part['state']['input']['command'] for part in tools] == commands, 'Commands changed')
    check(tools[0]['state']['status'] == 'completed', 'Allowed control did not complete')
    check((root / 'allowed.txt').read_text() == 'ACS_ALLOWED\n', 'Allowed marker mismatch')
    check(len({event['sessionID'] for event in host}) == 1, 'Host changed sessions')
    check(bool(responses), 'No Guardian responses; check that the ACS plugin loaded')
    check(len(responses) == len(requests), 'Incomplete wire exchange')
    check(all(req['rpc_id'] == res['rpc_id'] for req, res in zip(requests, responses)), 'RPC correlation mismatch')
    check(responses[0]['method'] == 'handshake/hello', 'Missing handshake')
    check(responses[0]['envelope']['result']['on_decision_failure'] == posture, 'Wrong negotiated posture')
    expected_methods = ['handshake/hello', 'steps/toolCallRequest', 'steps/toolCallResult']
    if args.scenario == 'live':
        expected_methods.append('steps/toolCallRequest')
    check([row['method'] for row in requests] == expected_methods, 'Unexpected hook coverage')
    check([row['envelope']['result']['decision'] for row in responses[1:]] ==
          (['allow', 'allow', 'deny'] if args.scenario == 'live' else ['allow', 'allow']), 'Unexpected wire decisions')
    expected_status = 'completed' if args.scenario == 'proceed-loss' else 'error'
    check(tools[1]['state']['status'] == expected_status, 'Second tool outcome mismatch')

    if args.scenario == 'live':
        check(not (root / 'denied.txt').exists(), 'Denied marker exists')
        reason = 'destructive_shell_command_blocked'
        check(reason in responses[-1]['envelope']['result']['reason_codes'], 'Missing policy reason')
        check(reason in tools[1]['state']['error'], 'Host dropped policy reason')
        check(not audit, 'Unexpected failure audit on live path')
        # Show that the exact denied command would create its marker without ACS.
        control = root / 'control'
        control.mkdir()
        subprocess.run(['/bin/sh', '-c', commands[1]], cwd=control, env=env, check=True)
        check((control / 'denied.txt').read_text() == 'rm -rf /\n', 'Ungoverned control failed')
    else:
        check(fault_injected, 'Guardian loss was not injected')
        check((root / 'outage.txt').exists() == (posture == 'proceed'), 'Outage marker mismatch')
        if posture == 'proceed':
            check((root / 'outage.txt').read_text() == 'ACS_OUTAGE\n', 'Outage marker content mismatch')
        expected_audit = ['steps/toolCallRequest', 'steps/toolCallResult'] if posture == 'proceed' else ['steps/toolCallRequest']
        check([row['method'] for row in audit] == expected_audit, 'Failure audit coverage mismatch')
        check(all(row['session_id'] == tools[0]['sessionID'] and row['posture'] == posture
                  and row['posture_source'] == 'negotiated' and row['failure']['kind'] == 'transport'
                  and row['outcome'] == ('proceeded' if posture == 'proceed' else 'blocked')
                  for row in audit), 'Failure audit semantics mismatch')

    summary = {
        'scenario': args.scenario, 'result': 'pass', 'platform': platform.system() + ' ' + platform.machine(),
        'acs_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=tree, text=True).strip(),
        'bun': subprocess.check_output([bun, '--version'], text=True).strip(),
        'opencode': subprocess.check_output([opencode, '--version'], text=True).strip(),
        'agt_pin': json.loads((tree / 'agt.lock').read_text()), 'negotiated_posture': posture,
        'guardian_stopped_after_first_tool': fault_injected,
        'wire_responses': responses,
        'tool_outcomes': [{'call_id': part['callID'], 'command': part['state']['input']['command'],
                           'status': part['state']['status'], 'error': part['state'].get('error')}
                          for part in tools],
        'failure_audit': audit,
        'markers': {name: (root / name).read_text() if (root / name).exists() else None
                    for name in ['allowed.txt', 'denied.txt', 'outage.txt', 'control/denied.txt']},
    }
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'{args.scenario}: PASS; evidence in {root}', flush=True)
finally:
    (root / 'model-requests.json').write_text(json.dumps(model_requests, indent=2))
    server.shutdown()
    server.server_close()
    if guardian.poll() is None:
        guardian.terminate()
        guardian.wait(timeout=10)
    guardian_log.close()
