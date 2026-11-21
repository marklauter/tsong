#!/usr/bin/env bash
# Builds Tsong's image and runs it in local podman, with the stub bootstrap
# file and config in this folder.
#
#   deploy/podman/run.sh build    build the image, tsong:local
#   deploy/podman/run.sh start    run it as the container "tsong"
#   deploy/podman/run.sh stop     stop it: SIGTERM, then the health drain
#   deploy/podman/run.sh logs     follow its output, the audit lines included
#   deploy/podman/run.sh check    run `tsong check` on the config in the image
#
# The container runs with a read-only root filesystem and no volume. The
# bootstrap file, the config and the signing key are mounted read-only. The
# ports are published on 127.0.0.1 only, because the stub's allow lists are
# open.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# Podman on Windows takes Windows paths for mounts.
mount_dir="$(cd "$here" && pwd -W 2>/dev/null || pwd)"
repo_dir="$(cd "$repo" && pwd -W 2>/dev/null || pwd)"

image=tsong:local
name=tsong
# Longer than health.drain in bootstrap.toml, so the drain can finish.
stop_timeout=15

# The ES256 signing key, generated once into keys/, which Git ignores.
signing_key() {
  local key="$here/keys/signing.pem"
  if [ ! -f "$key" ]; then
    # Readable by its owner alone; userns below maps the owner to uid 10001.
    (umask 077 && mkdir -p "$here/keys" \
      && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key")
    echo "generated $key"
  fi
}

# The container's user, uid 10001, runs as the host user, so it can read
# the key and the files mounted from this folder, which the host user owns.
userns=(--userns=keep-id:uid=10001,gid=10001)

mounts=(
  -v "$mount_dir/bootstrap.toml:/etc/tsong/bootstrap.toml:ro"
  -v "$mount_dir/tsong.toml:/etc/tsong/tsong.toml:ro"
  -v "$mount_dir/keys:/etc/tsong/keys:ro"
)

"$repo/scripts/podman.sh"
case "${1:-}" in
  build)
    MSYS_NO_PATHCONV=1 podman build -t "$image" -f "$repo_dir/Containerfile" "$repo_dir"
    ;;
  start)
    signing_key
    MSYS_NO_PATHCONV=1 podman run -d --name "$name" --replace \
      "${userns[@]}" --read-only --tmpfs /tmp \
      "${mounts[@]}" \
      --stop-timeout "$stop_timeout" \
      -p 127.0.0.1:8443:8443 -p 127.0.0.1:8444:8444 \
      -p 127.0.0.1:8445:8445 -p 127.0.0.1:8447:8447 \
      "$image"
    echo "gateway http://localhost:8443  issuer http://localhost:8444"
    echo "admin   http://localhost:8445  health http://localhost:8447/health/ready"
    ;;
  stop)
    podman stop -t "$stop_timeout" "$name"
    ;;
  logs)
    podman logs -f "$name"
    ;;
  check)
    signing_key
    MSYS_NO_PATHCONV=1 podman run --rm "${userns[@]}" --read-only "${mounts[@]}" "$image" \
      check /etc/tsong/tsong.toml
    ;;
  *)
    sed -n '2,/^set /{/^#/p;}' "$0" >&2
    exit 2
    ;;
esac
