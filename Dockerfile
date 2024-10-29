FROM rust:1.82.0-alpine3.20 AS build

ENV APP=cryptology
ENV CARGO_BUILD_TARGET=x86_64-unknown-linux-musl

RUN apk update && \
  apk add --no-cache \
  musl-dev=1.2.5-r0

WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY rust-toolchain.docker.toml rust-toolchain.toml
COPY crates/workspace crates/workspace
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml
COPY crates/${APP}/Cargo.toml crates/${APP}/Cargo.toml

RUN mkdir -p \
  crates/cli/src \
  crates/${APP}/src && \
  touch crates/cli/src/lib.rs && \
  echo "fn main() {println!(\"if you see this, the build broke\")}" > crates/${APP}/src/main.rs && \
  cargo build --release && \
  rm -rf target/${CARGO_BUILD_TARGET}/release/deps/${APP}* && \
  rm -rf target/${CARGO_BUILD_TARGET}/release/deps/libcli*

COPY crates crates

RUN cargo build -p ${APP} --release && \
  mv target/${CARGO_BUILD_TARGET}/release/${APP} ${APP}

FROM rust:1.82.0-alpine3.20 AS start

ENV APP=cryptology

WORKDIR /app

COPY --from=build /app/${APP} /usr/local/bin/${APP}

RUN addgroup -g 1000 ${APP} && \
  adduser -D -s /bin/sh -u 1000 -G ${APP} ${APP} && \
  chown ${APP}:${APP} /usr/local/bin/${APP}

USER ${APP}

CMD ["/bin/sh", "-c"]
