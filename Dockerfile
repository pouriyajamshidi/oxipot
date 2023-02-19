FROM rust:1.67.0 as builder

RUN USER=root cargo new --bin oxipot

WORKDIR /oxipot

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./build.rs ./build.rs

RUN cargo build --release
RUN rm src/*.rs

COPY . /oxipot/

RUN rm ./target/release/deps/oxipot*
RUN cargo build --release

FROM ubuntu:latest

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends wget tzdata && rm -rf /var/lib/apt/lists/*

ENV TZ="Europe/Brussels"

RUN wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.16_amd64.deb
RUN wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2.16_amd64.deb
RUN wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb

RUN dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
RUN dpkg -i libssl-dev_1.1.1f-1ubuntu2.16_amd64.deb
RUN dpkg -i openssl_1.1.1f-1ubuntu2.16_amd64.deb

WORKDIR /oxipot

COPY --from=builder /oxipot/target/release/oxipot  /oxipot

EXPOSE 2223

ENV RUST_LOG=debug

CMD [ "./oxipot"]
