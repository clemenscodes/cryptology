FROM rust:1.82.0-alpine3.20 AS build

ENV APP=cryptology
ENV TARGET=x86_64-unknown-linux-musl

RUN apk update && \
  apk add --no-cache \
  gcc \
  libgcc \
  git=2.45.2-r0 \
  gzip=1.13-r0 \
  unzip=6.0-r14 \
  xz=5.6.2-r0 \
  curl=8.10.1-r0 \
  pkgconf=2.2.0-r0 \
  openssl=3.3.2-r1 \
  openssl-dev=3.3.2-r1 \
  musl-dev=1.2.5-r0 \
  make=4.4.1-r2

WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY rust-toolchain.docker.toml rust-toolchain.toml
COPY crates/cryptology/Cargo.toml crates/cryptology/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml
COPY crates/workspace crates/workspace

RUN mkdir -p \
  crates/cli/src \
  crates/cryptology/src && \
  touch crates/cli/src/lib.rs && \
  echo "fn main() {println!(\"if you see this, the build broke\")}" > crates/cryptology/src/main.rs && \
  rustup target add ${TARGET} && \
  cargo build --release --target ${TARGET} && \
  rm -rf target/${TARGET}/release/deps/${APP}* && \
  rm -rf target/${TARGET}/release/deps/libcli*

COPY crates crates

RUN cargo build -p ${APP} --release --target ${TARGET} && \
  mv target/${TARGET}/release/${APP} ${APP}

FROM rust:1.82.0-alpine3.20 AS start

ENV APP=cryptology

WORKDIR /app

COPY --from=build /app/${APP} /usr/local/bin/${APP}

RUN addgroup -g 1000 ${APP} && \
  adduser -D -s /bin/sh -u 1000 -G ${APP} ${APP} && \
  chown ${APP}:${APP} /usr/local/bin/${APP}

USER ${APP}

CMD ["cryptology"]
