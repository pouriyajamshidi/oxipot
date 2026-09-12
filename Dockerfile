FROM rust:1.98.1-alpine3.24 AS builder

LABEL maintainer="Pouriya Jamshidi"

RUN apk add --no-cache musl-dev

WORKDIR /oxipot

COPY ./Cargo.lock ./Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY ./src ./src
RUN touch src/main.rs && cargo build --release

FROM alpine:3.24

RUN apk add --no-cache ca-certificates

WORKDIR /oxipot

COPY --from=builder /oxipot/target/release/oxipot /usr/local/bin/oxipot

ENV TZ=Europe/Brussels
ENV RUST_LOG=info

EXPOSE 2223

VOLUME ["/oxipot/db"]

CMD ["/usr/local/bin/oxipot"]
