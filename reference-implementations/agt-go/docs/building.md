# Build and package the Guardian

`make build` uses the AGT evaluator. Set `EVALUATOR=go` for the Go evaluator.
`GOOS` and `GOARCH` use Go's standard target names. Both default to the host.

| Target | Native AGT library |
| --- | --- |
| `linux/amd64` | `.so` |
| `linux/arm64` | `.so` |
| `darwin/amd64` | `.dylib` |
| `darwin/arm64` | `.dylib` |
| `windows/amd64` | `.dll` |

```bash
make build
make build EVALUATOR=go
make build GOOS=windows GOARCH=amd64
make build EVALUATOR=go GOOS=darwin GOARCH=arm64
make run
make run EVALUATOR=go
make test
make test EVALUATOR=go
```

The binary is in `.acs/bin/<GOOS>-<GOARCH>/<EVALUATOR>/`.
Windows binaries have the `.exe` extension. An AGT build includes its library and build record beside the binary.
`OUTPUT_DIR` changes the output directory. Keep the library and record together when copying the binary.

## Native toolchains

Install Go, Rust through rustup, a C compiler, Make, Bash, Git, curl, jq, and OpenSSL.
On macOS, install the Xcode command line tools. Native macOS builds require the Apple SDK on a Mac.
On Windows, use the MSYS2 MinGW-w64 shell with GCC, Make, and the listed tools on PATH.
The Rust target is `x86_64-pc-windows-gnu`. The build script installs the pinned Rust target.

The Go evaluator cross-builds without a C compiler. AGT cross-builds also require the target C compiler and system libraries.
For Windows from Linux, install MinGW-w64. The Makefile selects `x86_64-w64-mingw32-gcc`.
For a Linux architecture change, set `CC` to the target compiler.
Cross-builds do not execute tests. `make run`, `make test`, and `make check` require the host target.

The native script stores each platform's library and OPA in `.acs/agt/<GOOS>-<GOARCH>/`.
Host builds also copy OPA into `.acs/agt/bin/` for the reference YAML.
`policy.opa_path` accepts an executable or its directory. Windows uses `opa.exe`.
OPA 0.70.0 names its Apple Silicon binary `opa_darwin_arm64_static` and its Intel Mac binary `opa_darwin_amd64`.

## Linux container images

The image uses AGT by default. Docker Desktop runs the Linux image on Windows and macOS.
The image listens on port 8787 and requires a HMAC secret file with at least 32 bytes.
The image runs as user 65532. Audit files go to `/data`.

```bash
make image
make image EVALUATOR=go IMAGE=acs-guardian-go:local
make image PLATFORMS=linux/amd64 IMAGE_OUTPUT=type=docker
docker run --rm -p 8787:8787 --user "$(id -u):$(id -g)" \
  --tmpfs "/data:uid=$(id -u),gid=$(id -g),mode=0700" \
  --mount type=bind,src="$(pwd)/.acs/hmac-secret",dst=/run/secrets/acs-hmac,readonly \
  acs-guardian:local
```

`make image` exports an OCI archive to `.acs/acs-guardian.oci.tar` for `linux/amd64` and `linux/arm64`.
Use `IMAGE_OUTPUT=type=docker` to load a host image into Docker.
The build requires a Buildx builder with OCI export and the selected platforms.
The command does not publish the image. Both Linux targets use cross-compilers on the builder's architecture.
Run `make image-check` to test the loaded image through a host-published port.
`IMAGE_PLATFORM=linux/arm64` selects the arm64 image for that check. Execution requires an arm64 host or Docker emulation.
The example uses the host user to read the protected secret file.
Mount writable storage at `/data` to retain audit files after the container stops.

## Verification limits

CI defines a complete gate on Linux amd64, Linux arm64, Windows amd64, Intel Mac, and Apple Silicon.
A workflow definition does not establish a successful run. Verify the platform job results before publishing.
Cross-builds establish compilation only. Wine checks Windows execution without replacing a real Windows runner.
`make check` checks Go's cgo flag rules for all five targets without executing their build commands.
This validation does not link native libraries or run target binaries.
`go list` shows selected flags but does not validate the flags.
The CLI tests accept `ACS_TEST_GUARDIAN_BINARY` to exercise a previously compiled binary on its target.
The variable changes the test artifact only. It does not skip startup, decisions, or shutdown checks.
