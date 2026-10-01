# dufs with OIDC login and api_keys. Build from the repo root: docker build -t dufs-oidc .
FROM rust:1.98.1-trixie AS builder
WORKDIR /src

# Dependency layer: manifests plus a stub main so only crates are compiled here.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/dufs target/release/deps/dufs-* target/release/.fingerprint/dufs-*

COPY src ./src
COPY assets ./assets
RUN cargo build --release --locked

FROM debian:trixie-20260918-slim
RUN useradd --system --no-create-home --shell /usr/sbin/nologin dufs \
    && mkdir /data && chown dufs /data
COPY --from=builder /src/target/release/dufs /usr/local/bin/dufs
USER dufs
VOLUME /data
EXPOSE 5000
ENTRYPOINT ["dufs", "/data"]
