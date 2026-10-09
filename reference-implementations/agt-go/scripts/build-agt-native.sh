#!/usr/bin/env bash
# Build the pinned native library and OPA. See docs/building.md.
set -euo pipefail

cd "$(dirname "$0")/.."
lock=agt-native.lock

die() {
  echo "build-agt-native: $*" >&2
  exit 1
}

for tool in jq git curl rustup cargo go; do
  command -v "$tool" >/dev/null || die "$tool is required on PATH"
done

pinned() { jq -er "$1" "$lock" || die "$lock has no $1"; }
agt_repo="$(pinned .agt_repo)"
agt_ref="$(pinned .agt_ref)"
workspace_path="$(pinned .workspace_path)"
crate="$(pinned .crate)"
crate_version="$(pinned .crate_version)"
features="$(pinned '.cargo_features | join(",")')"
toolchain="$(pinned .rust_toolchain)"
opa_version="$(pinned .opa_version)"

host_os="$(go env GOHOSTOS)"
host_arch="$(go env GOHOSTARCH)"
target_os="${GOOS:-$host_os}"
target_arch="${GOARCH:-$host_arch}"
platform="$target_os-$target_arch"
opa_asset="opa_${target_os}_${target_arch}"
opa_name=opa
case "$platform" in
  linux-amd64) target=x86_64-unknown-linux-gnu; library="lib$crate.so"; opa_asset="${opa_asset}_static" ;;
  linux-arm64) target=aarch64-unknown-linux-gnu; library="lib$crate.so"; opa_asset="${opa_asset}_static" ;;
  darwin-amd64) target=x86_64-apple-darwin; library="lib$crate.dylib" ;;
  darwin-arm64) target=aarch64-apple-darwin; library="lib$crate.dylib"; opa_asset="${opa_asset}_static" ;;
  windows-amd64) target=x86_64-pc-windows-gnu; library="$crate.dll"; opa_asset="${opa_asset}.exe"; opa_name=opa.exe ;;
  *) die "unsupported target $platform; supported: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64" ;;
esac
if [ "$target_os" = darwin ] && [ "$host_os" != darwin ]; then
  die "macOS native builds require a Mac and the Apple SDK; use EVALUATOR=go for a Go cross-build"
fi
out="${AGT_OUT:-.acs/agt/$platform}"
opa_sha256="$(pinned ".opa_sha256[\"$platform\"]")"

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# No identifying information on outbound git traffic, as
# ../agt/scripts/verify-pin.sh does.
export GIT_TERMINAL_PROMPT=0
src=.acs/agt/src
if [ ! -d "$src/.git" ]; then
  git -c credential.helper= init --quiet "$src"
  git -C "$src" -c credential.helper= remote add origin "$agt_repo"
fi
if [ "$(git -C "$src" rev-parse -q --verify HEAD || true)" != "$agt_ref" ]; then
  git -C "$src" -c credential.helper= fetch --quiet --depth 1 origin "$agt_ref"
  git -C "$src" -c credential.helper= checkout --quiet --detach FETCH_HEAD
fi
[ "$(git -C "$src" rev-parse HEAD)" = "$agt_ref" ] || die "$src is not at $agt_ref"
[ -z "$(git -C "$src" status --porcelain --untracked-files=all)" ] || die "$src has local changes; the pin names the commit, so only unmodified source is built"

rustup toolchain list | grep -q "^$toolchain-" || rustup toolchain install "$toolchain" --profile minimal
rustup target add "$target" --toolchain "$toolchain"
if [ "$target_os" = windows ]; then
  compiler="${CC:-gcc}"
  command -v "$compiler" >/dev/null || die "$compiler is required for Windows GNU builds"
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$compiler"
elif [ "$target_os" = linux ] && [ "$target_arch" != "$host_arch" ]; then
  compiler="${CC:?set CC to the target C compiler for a native cross-build}"
  command -v "$compiler" >/dev/null || die "$compiler is required"
  linker_variable="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_LINKER"
  export "$linker_variable=$compiler"
fi
manifest="$src/$workspace_path/Cargo.toml"
pkgid="$(cargo +"$toolchain" pkgid --locked --manifest-path "$manifest" -p "$crate")"
[ "${pkgid##*[#@]}" = "$crate_version" ] || die "$crate at $agt_ref is version ${pkgid##*[#@]}, and $lock pins $crate_version"
cargo +"$toolchain" build --quiet --release --locked --manifest-path "$manifest" -p "$crate" --features "$features" --target "$target"

# A running Guardian maps the installed library, so each file is replaced by
# rename, never rewritten in place.
mkdir -p "$out/lib" "$out/bin"
cp "$src/$workspace_path/target/$target/release/$library" "$out/lib/$library.new"
if [ "$target_os" = darwin ]; then
  install_name_tool -id "@rpath/$library" "$out/lib/$library.new"
  codesign --force --sign - "$out/lib/$library.new"
fi
if [ "$target_os" = windows ]; then
  cp "$src/$workspace_path/target/$target/release/lib$crate.dll.a" "$out/lib/"
fi
if [ -f "$out/lib/$library" ] && [ "$(sha256 "$out/lib/$library")" = "$(sha256 "$out/lib/$library.new")" ]; then
  rm "$out/lib/$library.new"
else
  mv "$out/lib/$library.new" "$out/lib/$library"
fi
jq -n \
  --arg agt_ref "$agt_ref" --arg crate "$crate" --arg crate_version "$crate_version" \
  --arg features "$features" --arg toolchain "$toolchain" --arg sha256 "$(sha256 "$out/lib/$library")" \
  '{agt_ref: $agt_ref, crate: $crate, crate_version: $crate_version, cargo_features: ($features | split(",")), rust_toolchain: $toolchain, sha256: $sha256}' \
  >"$out/lib/agt-native.json.new"
mv "$out/lib/agt-native.json.new" "$out/lib/agt-native.json"

opa="$out/bin/$opa_name"
if [ ! -f "$opa" ] || [ "$(sha256 "$opa")" != "$opa_sha256" ]; then
  curl --proto '=https' --tlsv1.2 -fsSL -o "$opa.download" \
    "https://github.com/open-policy-agent/opa/releases/download/v$opa_version/$opa_asset"
  if [ "$(sha256 "$opa.download")" != "$opa_sha256" ]; then
    rm -f "$opa.download"
    die "opa $opa_version for $platform does not match the SHA-256 $lock pins"
  fi
  chmod +x "$opa.download"
  mv "$opa.download" "$opa"
fi
if [ "$platform" = "$host_os-$host_arch" ]; then
  mkdir -p .acs/agt/bin
  cp "$opa" ".acs/agt/bin/$opa_name"
fi
echo "build-agt-native: AGT $agt_ref ($crate $crate_version) in $out/lib, opa $opa_version in $out/bin"
