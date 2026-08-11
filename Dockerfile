# Build context must be the PARENT directory because the release workflow
# supplies side-by-side, commit-verified cross-repository sources:
#
#   docker build -f zed-api-server.rs/Dockerfile \
#     --build-arg ZED_INTERFACES_REVISION=15577e17a820c3b2b1a39ee178d4645185309a05 \
#     --build-arg ZED_LIB_CORE_REVISION=38ef3f50638614a14170d5c677173e040e916a6d \
#     -t ghcr.io/zed-pkg/zed-api-server:dev .
#
# The toolchain must satisfy the crate's `edition = "2024"` (>= 1.85) and the
# aws-sdk-* crates' MSRV (>= 1.94.1), so the base is pinned to 1.97.1.
# RUSTUP_TOOLCHAIN overrides the repo's floating rust-toolchain.toml channel so
# the build uses the toolchain already present in the image.
# `-bookworm` keeps the build glibc compatible with the Debian 12 runtime stage.
FROM rust:1.97-slim-bookworm AS build
ARG ZED_INTERFACES_REVISION
ARG ZED_LIB_CORE_REVISION
ENV RUSTUP_TOOLCHAIN=1.97.1
WORKDIR /work
COPY zed-interfaces ./zed-interfaces
COPY zed-lib-core ./zed-lib-core
COPY zed-api-server.rs ./zed-api-server.rs
WORKDIR /work/zed-api-server.rs
RUN test -n "$ZED_INTERFACES_REVISION" \
    && test -n "$ZED_LIB_CORE_REVISION" \
    && grep -F "rev = \"$ZED_INTERFACES_REVISION\"" Cargo.toml \
    && grep -F "?rev=$ZED_INTERFACES_REVISION#$ZED_INTERFACES_REVISION" Cargo.lock \
    && grep -F "rev = \"$ZED_LIB_CORE_REVISION\"" Cargo.toml \
    && grep -F "?rev=$ZED_LIB_CORE_REVISION#$ZED_LIB_CORE_REVISION" Cargo.lock \
    && cargo build --release --locked

FROM debian:12-slim
ARG ZED_API_REVISION=unknown
ARG ZED_INTERFACES_REVISION=unknown
ARG ZED_LIB_CORE_REVISION=unknown
LABEL org.opencontainers.image.title="Zed registry API" \
      org.opencontainers.image.description="Zed package registry API server" \
      org.opencontainers.image.source="https://github.com/zed-pkg/zed-api-server.rs" \
      org.opencontainers.image.revision="$ZED_API_REVISION" \
      org.opencontainers.image.licenses="MIT" \
      io.zpkg.interfaces.revision="$ZED_INTERFACES_REVISION" \
      io.zpkg.lib-core.revision="$ZED_LIB_CORE_REVISION"
# The AWS SDK and reqwest both need a system trust store for HTTPS S3-compatible
# endpoints. Debian slim does not include one, so Cloudflare R2 and AWS S3 fail
# during TLS setup even though plaintext local MinIO remains healthy.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 zed
COPY --from=build /work/zed-api-server.rs/target/release/zed-api-server /usr/local/bin/zed-api-server
USER zed
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/zed-api-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/zed-api-server"]
