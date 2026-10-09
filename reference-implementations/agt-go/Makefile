GO ?= go
GOOS ?= $(shell $(GO) env GOHOSTOS)
GOARCH ?= $(shell $(GO) env GOHOSTARCH)
EVALUATOR ?= agt
TARGET := $(GOOS)-$(GOARCH)
AGT_DIR := $(CURDIR)/.acs/agt/$(TARGET)
OUTPUT_DIR ?= .acs/bin/$(TARGET)/$(EVALUATOR)
PLATFORMS ?= linux/amd64,linux/arm64
IMAGE ?= acs-guardian:local
IMAGE_PLATFORM ?= linux/$(shell $(GO) env GOHOSTARCH)
IMAGE_OUTPUT ?= type=oci,dest=.acs/acs-guardian.oci.tar

ifneq ($(EVALUATOR),agt)
ifneq ($(EVALUATOR),go)
$(error EVALUATOR must be agt or go)
endif
endif
export GOOS GOARCH
EXE := $(if $(filter windows,$(GOOS)),.exe,)
export ACS_GUARDIAN_BIN := $(abspath $(OUTPUT_DIR))/acs-guardian$(EXE)
export ACS__POLICY__EVALUATOR := $(EVALUATOR)

ifeq ($(GOOS),windows)
ifeq ($(origin CC),default)
CC := $(if $(filter windows,$(shell $(GO) env GOHOSTOS)),gcc,x86_64-w64-mingw32-gcc)
endif
export CC
RPATH :=
else ifeq ($(GOOS),darwin)
RPATH :=
else
RPATH := -Wl,-rpath,$(AGT_DIR)/lib -Wl,-rpath,$$ORIGIN
endif
ifeq ($(shell $(GO) env GOHOSTOS),windows)
export PATH := $(shell cygpath -u '$(AGT_DIR)/lib'):$(PATH)
else
export PATH := $(AGT_DIR)/lib:$(PATH)
endif

AGT_GOFLAGS := $(GOFLAGS)
ifeq ($(GOOS),darwin)
AGT_GOFLAGS += -ldflags=-extldflags=-Wl,-rpath,@loader_path
endif
AGT_CGO := CGO_ENABLED=1 CGO_LDFLAGS='-L$(AGT_DIR)/lib $(RPATH)' GOFLAGS='$(AGT_GOFLAGS)'
BUILD_ENV := $(if $(filter agt,$(EVALUATOR)),$(AGT_CGO),CGO_ENABLED=0)
BUILD_TAGS := $(if $(filter agt,$(EVALUATOR)),-tags agteval,)

.PHONY: all help setup agt-native build dev-secret run test test-race host-target image image-check example-runtime codex-example opencode-example require-bun require-conformance-deps example-check conformance fmt fmt-check vet lint vulncheck tidy-check coverage docs-check check

all: build

help:
	@printf '%s\n' \
		'setup             install dependencies required by the quality gate' \
		'agt-native        build the AGT runtime library and fetch opa, as agt-native.lock pins' \
		'build             compile every package and the Guardian with AGT' \
		'run               build and run the selected evaluator on this host' \
		'test              test the selected evaluator on this host' \
		'image             build Linux images with Docker Buildx, without publishing' \
		'image-check       run the local image through shared conformance probes' \
		'EVALUATOR=agt|go   select the implementation; default: agt' \
		'GOOS, GOARCH      select the build target; default: this host' \
		'test-race         run every test with the Go evaluator and the race detector' \
		'codex-example     start the Guardian and a governed Codex session' \
		'opencode-example  start the Guardian and a governed OpenCode session' \
		'example-check     test the custom engine and host adapters' \
		'conformance       run the shared ACS harness against this Guardian' \
		'docs-check        validate documentation links and named tests' \
		'check             run the complete local quality gate'

setup: host-target require-bun agt-native
	$(GO) mod download
	cd ../agt && bun install --frozen-lockfile

agt-native:
	scripts/build-agt-native.sh

build: $(if $(filter agt,$(EVALUATOR)),agt-native,)
	mkdir -p $(OUTPUT_DIR)
	$(BUILD_ENV) $(GO) build $(BUILD_TAGS) ./...
	$(BUILD_ENV) $(GO) build $(BUILD_TAGS) -o $(ACS_GUARDIAN_BIN) ./cmd/guardian
ifeq ($(EVALUATOR),agt)
	cp $(AGT_DIR)/lib/* $(OUTPUT_DIR)/
endif

dev-secret:
	mkdir -p .acs
	@test -f .acs/hmac-secret || (umask 077; set -C; openssl rand -hex 32 > .acs/hmac-secret) || test -f .acs/hmac-secret
	chmod 600 .acs/hmac-secret

run: example-runtime
	ACS__POLICY__EVALUATOR=$(EVALUATOR) ACS__POLICY__OPA_PATH=$(AGT_DIR)/bin exec $(ACS_GUARDIAN_BIN) --config guardian.yaml

test: host-target $(if $(filter agt,$(EVALUATOR)),agt-native,)
	$(BUILD_ENV) $(GO) test -count=1 $(if $(filter agt,$(EVALUATOR)),-race,) $(BUILD_TAGS) ./...

test-race: host-target
	CGO_ENABLED=1 $(GO) test -count=1 -race ./...

host-target:
	@test '$(TARGET)' = "$$($(GO) env GOHOSTOS)-$$($(GO) env GOHOSTARCH)" || { printf '%s\n' 'run and test require the host GOOS and GOARCH'; exit 1; }

image:
	mkdir -p .acs
	docker buildx build --platform $(PLATFORMS) --build-arg EVALUATOR=$(EVALUATOR) --tag $(IMAGE) --output $(IMAGE_OUTPUT) --file Dockerfile ../..

image-check: host-target require-bun require-conformance-deps
	IMAGE=$(IMAGE) IMAGE_PLATFORM=$(IMAGE_PLATFORM) ACS_OPA_PATH='$(AGT_DIR)/bin/opa$(EXE)' scripts/check-image.sh

example-runtime: host-target dev-secret build

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
	ACS_OPA_PATH='$(AGT_DIR)/bin/opa$(EXE)' scripts/check-common-conformance.sh

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$(gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*' -not -path './.acs/*'))"; \
	test -z "$$unformatted" || { printf '%s\n' "$$unformatted"; exit 1; }

vet:
	$(GO) vet ./...
	$(AGT_CGO) $(GO) vet -tags agteval ./...

lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
	$(AGT_CGO) $(GO) run honnef.co/go/tools/cmd/staticcheck@2026.2.1 -tags agteval ./...

vulncheck:
	$(GO) tool govulncheck ./...

tidy-check:
	$(GO) mod tidy -diff

coverage:
	scripts/check-coverage.sh

docs-check:
	$(GO) run ./cmd/docs-check

check: host-target fmt-check tidy-check vet lint vulncheck build test-race test example-check conformance coverage docs-check
	$(MAKE) build EVALUATOR=go
	$(MAKE) test EVALUATOR=go
ifneq ($(EVALUATOR),agt)
	$(MAKE) build EVALUATOR=agt
	$(MAKE) test EVALUATOR=agt
endif
