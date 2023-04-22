FROM rust:1.69 as builder

RUN USER=root cargo new --bin oxipot

WORKDIR /oxipot

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./build.rs ./build.rs

RUN cargo build --release

RUN rm src/*.rs
RUN rm ./target/release/deps/oxipot*

COPY ./src/main.rs /oxipot/src/
COPY . /oxipot/

RUN cargo build --release

FROM ubuntu:latest

ENV TZ="Europe/Brussels"

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /oxipot

WORKDIR /oxipot

COPY --from=builder /oxipot/target/release/oxipot  /oxipot/

EXPOSE 2223

ENV RUST_LOG=info

CMD [ "/oxipot/oxipot"]
