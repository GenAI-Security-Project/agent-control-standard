GO ?= go

.PHONY: all help setup build dev-secret run test test-race example-runtime codex-example opencode-example require-bun require-conformance-deps example-check conformance fmt fmt-check vet lint vulncheck tidy-check coverage docs-check check

all: build

help:
	@printf '%s\n' \
		'setup             install dependencies required by the quality gate' \
		'build             compile every package in the main Go module' \
		'run               start the Guardian with guardian.yaml' \
		'test              run all Go tests' \
		'test-race         run all Go tests with the race detector' \
		'codex-example     start the Guardian and a governed Codex session' \
		'opencode-example  start the Guardian and a governed OpenCode session' \
		'example-check     test the custom engine and host adapters' \
		'conformance       run the shared ACS harness against this Guardian' \
		'docs-check        validate documentation links and named tests' \
		'check             run the complete local quality gate'

setup: require-bun
	$(GO) mod download
	cd ../agt && bun install --frozen-lockfile

build:
	$(GO) build ./...

dev-secret:
	mkdir -p .acs
	@test -f .acs/hmac-secret || (umask 077; set -C; openssl rand -hex 32 > .acs/hmac-secret) || test -f .acs/hmac-secret
	chmod 600 .acs/hmac-secret

run: example-runtime
	exec .acs/bin/acs-guardian --config guardian.yaml

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

example-runtime: dev-secret
	mkdir -p .acs/bin
	$(GO) build -o .acs/bin/acs-guardian ./cmd/guardian

require-bun:
	@command -v bun >/dev/null || { printf '%s\n' 'bun is required on PATH'; exit 1; }

require-conformance-deps:
	@test -d ../agt/node_modules || { printf '%s\n' 'shared conformance dependencies are missing; run make setup'; exit 1; }

codex-example: example-runtime
	@command -v codex >/dev/null || { printf '%s\n' 'codex is required on PATH'; exit 1; }
	$(GO) build -o .acs/bin/acs-codex-hook ./examples/codex/cmd/acs-codex-hook
	scripts/run-host-example.sh codex --dangerously-bypass-hook-trust -s workspace-write --config sandbox_workspace_write.network_access=true

opencode-example: example-runtime
	@command -v opencode >/dev/null || { printf '%s\n' 'opencode is required on PATH'; exit 1; }
	$(GO) build -o .acs/bin/acs-opencode-hook ./examples/opencode/cmd/acs-opencode-hook
	scripts/run-host-example.sh opencode

example-check: example-runtime require-bun
	cd examples/custom-engine && $(GO) vet ./... && $(GO) test ./...
	$(GO) test ./examples/codex/cmd/acs-codex-hook
	$(GO) test ./examples/opencode/cmd/acs-opencode-hook
	$(GO) build -o .acs/bin/acs-opencode-hook ./examples/opencode/cmd/acs-opencode-hook
	ACS_HOST_EXAMPLE_PORT=0 scripts/run-host-example.sh bun test examples/opencode/plugin.test.mjs
	bash -n scripts/run-host-example.sh

conformance: example-runtime require-bun require-conformance-deps
	scripts/check-common-conformance.sh

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$(gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'))"; \
	test -z "$$unformatted" || { printf '%s\n' "$$unformatted"; exit 1; }

vet:
	$(GO) vet ./...

lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...

vulncheck:
	$(GO) tool govulncheck ./...

tidy-check:
	$(GO) mod tidy -diff

coverage:
	scripts/check-coverage.sh

docs-check:
	$(GO) run ./cmd/docs-check

check: fmt-check tidy-check vet lint vulncheck test-race example-check conformance coverage docs-check
