# Build context must be the PARENT directory (side-by-side checkout) because
# of the ../zed-interfaces path dependency:
#
#   docker build -f zed-api-server.rs/Dockerfile -t ghcr.io/zed-pkg/zed-api-server:dev .
#
# The toolchain must satisfy the crate's `edition = "2024"` (>= 1.85) and the
# aws-sdk-* crates' MSRV (>= 1.94.1), so the base is pinned to 1.97.1.
# RUSTUP_TOOLCHAIN overrides the repo's floating rust-toolchain.toml channel so
# the build uses the toolchain already present in the image.
# `-bookworm` keeps the build glibc compatible with the Debian 12 runtime stage.
FROM rust:1.97-slim-bookworm AS build
ENV RUSTUP_TOOLCHAIN=1.97.1
WORKDIR /work
COPY zed-interfaces ./zed-interfaces
COPY zed-api-server.rs ./zed-api-server.rs
WORKDIR /work/zed-api-server.rs
RUN cargo build --release --locked

FROM debian:12-slim
ARG ZED_API_REVISION=unknown
ARG ZED_INTERFACES_REVISION=unknown
LABEL org.opencontainers.image.title="Zed registry API" \
      org.opencontainers.image.description="Zed package registry API server" \
      org.opencontainers.image.source="https://github.com/zed-pkg/zed-api-server.rs" \
      org.opencontainers.image.revision="$ZED_API_REVISION" \
      org.opencontainers.image.licenses="MIT" \
      io.zpkg.interfaces.revision="$ZED_INTERFACES_REVISION"
RUN useradd --system --uid 10001 zed
COPY --from=build /work/zed-api-server.rs/target/release/zed-api-server /usr/local/bin/zed-api-server
USER zed
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/zed-api-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/zed-api-server"]
