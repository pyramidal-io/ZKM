#!/usr/bin/env bash
# Reproduce the Aztec profile gate in the immutable official v6.0.0 OCI image.
set -euo pipefail

AZTEC_VERSION="6.0.0"
AZTEC_PACKAGES_COMMIT="0472012201fdff1429d184f8d25cecf13ca94326"
AZTEC_IMAGE="azteclabs/aztec@sha256:59b10cc8e89bb9226db1f771a5abbe5d5f8d71483c00c7472187e6ddc7adab8d"

mode=docker
case "${1:-}" in
  "") test "$#" -eq 0 ;;
  --inside-image) test "$#" -eq 1; mode=inside-image ;;
  *) echo "usage: $0 [--inside-image]" >&2; exit 64 ;;
esac
# Forgejo's socket-free x86 job selects AZTEC_IMAGE as its pinned job
# container. The default local entry point selects that same image below.
if [ "$mode" = docker ]; then
  command -v docker >/dev/null || {
    echo "AZTEC PROFILE: FAIL — docker is required" >&2
    exit 1
  }
fi
command -v python3 >/dev/null || {
  echo "AZTEC PROFILE: FAIL — python3 is required" >&2
  exit 1
}

ROOT="$(git rev-parse --show-toplevel)"
test -n "$ROOT"
test -f "$ROOT/PUBLIC_SURFACE"

actual_commit="$(
  git ls-remote https://github.com/aztec-labs-eng/aztec-nr \
    "refs/tags/v${AZTEC_VERSION}^{}" | cut -f1
)"
if [ "$actual_commit" != "$AZTEC_PACKAGES_COMMIT" ]; then
  echo "AZTEC PROFILE: FAIL — v${AZTEC_VERSION} tag target changed" >&2
  exit 1
fi

if [ "$mode" = inside-image ]; then
  # V6's runtime image no longer bundles Nargo. Use the official rc.3
  # release, authenticated by the release asset SHA-256 for each architecture.
  case "$(uname -m)" in
    x86_64) noir_arch=x86_64; noir_sha=5792dd962afce1eed834570f95d9f72cc4a09d45cd846d3b80b7a57392732973 ;;
    aarch64) noir_arch=aarch64; noir_sha=98be47cd6b2a81f3857c029acd8298fd590eebeb153ef51e1dc6f10c973e00e9 ;;
    *) echo 'unsupported V6 profile architecture' >&2; exit 1 ;;
  esac
  profile_bin="$(mktemp -d /tmp/zkm-profile-bin.XXXXXX)"
  trap 'rm -rf "$profile_bin"' EXIT
  curl --fail --silent --show-error --location --retry 3 \
    "https://github.com/noir-lang/noir/releases/download/v1.0.0-rc.3/noir-${noir_arch}-unknown-linux-gnu.tar.gz" \
    --output "$profile_bin/noir.tar.gz"
  echo "$noir_sha  $profile_bin/noir.tar.gz" | sha256sum --check --strict -
  tar -xzf "$profile_bin/noir.tar.gz" -C "$profile_bin"
  printf '%s\n' '#!/usr/bin/env bash' \
    'exec node --no-warnings /usr/src/yarn-project/aztec/dest/bin/index.js "$@"' \
    > "$profile_bin/aztec"
  chmod +x "$profile_bin/aztec"
  ln -s "$profile_bin/nargo" "$profile_bin/aztec-nargo"
  export PATH="$profile_bin:$PATH"
  test "$(aztec --version)" = "$AZTEC_VERSION"
  test "$(aztec-nargo --version | sed -n 's/^nargo version = //p')" = "1.0.0-rc.3"
  command -v nc >/dev/null
  # bb's internal HTTP client does not use the runner proxy. Fetch a bounded
  # 2^19-point prefix with curl instead. Its four 4-MiB chunk hashes were
  # independently checked against the pinned Aztec source's CRS hash table.
  export CRS_PATH="$profile_bin/crs"
  mkdir "$CRS_PATH"
  compressed="$CRS_PATH/bn254_g1_compressed.dat"
  curl --fail --silent --show-error --location --retry 3 \
    --range 0-16777215 --max-filesize 16777216 \
    --output "$compressed" \
    https://crs.aztec-cdn.foundation/g1_compressed.dat
  test "$(wc -c < "$compressed")" -eq 16777216
  echo "1d03ebeb73e1a6d426e44a2ccc88b04125ca185ab9d1679817380502a723fa80  $compressed" \
    | sha256sum --check --strict -
  bash aztec/scripts/txe-test.sh
  python3 "$ROOT/.github/scripts/check-third-party-licenses.py" \
    --root "$ROOT" --profile aztec \
    --aztec-dir "$HOME/nargo/github.com/aztec-labs-eng/aztec-nr/v${AZTEC_VERSION}" \
    --zka-dir "$ROOT/aztec/vendor/zka"
  echo "AZTEC PROFILE: OK (${AZTEC_VERSION}, immutable OCI and source pins verified)"
  exit 0
fi

created_home=0
if [ -n "${AZTEC_CACHE_HOME:-}" ]; then
  aztec_home="$AZTEC_CACHE_HOME"
  mkdir -p "$aztec_home"
else
  aztec_home="$(mktemp -d)"
  created_home=1
fi
case "$aztec_home" in
  /*) ;;
  *)
    echo "AZTEC PROFILE: FAIL — cache home must be absolute" >&2
    exit 1
    ;;
esac
cleanup() {
  if [ "$created_home" -eq 1 ]; then
    rm -rf "$aztec_home"
  fi
}
trap cleanup EXIT

docker run --rm --interactive --pull=always --platform linux/amd64 \
  --entrypoint bash \
  --user "$(id -u):$(id -g)" \
  --env HOME=/zkm-home \
  --volume "$ROOT:/workspace" \
  --volume "$aztec_home:/zkm-home" \
  --workdir /workspace \
  "$AZTEC_IMAGE" -s <<'AZTEC_CI'
set -euo pipefail
bash .github/scripts/run-aztec-ci.sh --inside-image
AZTEC_CI
