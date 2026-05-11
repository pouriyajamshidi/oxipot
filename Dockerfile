FROM ubuntu:latest AS builder

LABEL maintainer="Pouriya Jamshidi"

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    make \
    build-essential \
    musl-tools \
    musl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /oxipot

COPY ./Cargo.lock ./Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -rf src

COPY ./src ./src
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

COPY --from=builder /oxipot/target/x86_64-unknown-linux-musl/release/oxipot /usr/local/bin/oxipot
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV TZ=Europe/Brussels
ENV RUST_LOG=info

EXPOSE 2223

VOLUME ["/oxipot/db"]

CMD ["/usr/local/bin/oxipot"]
