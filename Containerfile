# Tsong's container image: `deploy/podman/run.sh build` builds it.
#
# The build stage compiles the release binary. The runtime stage is Debian
# slim. It runs as an unprivileged user with no home directory, and works
# with a read-only root filesystem.

FROM docker.io/library/rust:1-bookworm AS build
WORKDIR /src
COPY . .
# The toolchain rust-toolchain.toml pins, without the editor's components.
ENV RUSTUP_TOOLCHAIN=stable
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tsong \
    && install -D target/release/tsong /out/tsong

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 tsong \
    && useradd --system --uid 10001 --gid tsong --home-dir /nonexistent --no-create-home tsong
COPY --from=build /out/tsong /usr/local/bin/tsong
USER 10001:10001
WORKDIR /
# gateway, issuer, admin, health: the ports the sample files use.
EXPOSE 8443 8444 8445 8447
# A stop sends SIGTERM: readiness fails for health.drain, then the
# listeners close. Give the stop a timeout longer than the drain.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/tsong"]
CMD ["serve", "/etc/tsong/bootstrap.toml"]
