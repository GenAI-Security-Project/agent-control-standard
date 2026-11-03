#!/usr/bin/env bash
# Install Grok's ACS hook at an absolute path.
#
# Grok's workspace root is the git repo, not this agt/ tree. The shipped
# hooks.json uses $GROK_PROJECT_DIR, which resolves only when that workspace
# is this repository and the session was started with `grok --trust`.
# That file is a local demo. This script writes the hook Grok should run.
#
# GROK_HOOKS_DIR overrides the destination directory. The default is
# ~/.grok/hooks. The file name is acs-agt.json.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hook_path="$repo_root/hosts/grok/acs-hook.ts"
template="$repo_root/hosts/grok/hooks.json"

if [ ! -f "$hook_path" ]; then
  echo "install-grok-hook: missing $hook_path" >&2
  exit 1
fi

if [ ! -f "$template" ]; then
  echo "install-grok-hook: missing $template" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "install-grok-hook: jq is required" >&2
  exit 1
fi

if [ -n "${GROK_HOOKS_DIR:-}" ]; then
  hooks_dir="$GROK_HOOKS_DIR"
else
  hooks_dir="${HOME}/.grok/hooks"
fi

mkdir -p "$hooks_dir"
dest="$hooks_dir/acs-agt.json"

# jq builds the shell command, so a path character it must escape stays
# inside the JSON string. The quotes around the path are for the shell
# Grok uses to launch the hook.
json="$(jq --arg hook "$hook_path" '
  ("bun run \"" + $hook + "\"") as $cmd
  | .hooks.PreToolUse[0].matcher = "run_terminal_command"
  | .hooks.PreToolUse[0].hooks[0].type = "command"
  | .hooks.PreToolUse[0].hooks[0].command = $cmd
  | .hooks.PreToolUse[0].hooks[0].timeout = 30
  | .hooks.PostToolUse[0].matcher = "run_terminal_command"
  | .hooks.PostToolUse[0].hooks[0].type = "command"
  | .hooks.PostToolUse[0].hooks[0].command = $cmd
  | .hooks.PostToolUse[0].hooks[0].timeout = 30
' "$template")"

printf '%s\n' "$json" > "$dest"
