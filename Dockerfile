FROM ubuntu:latest as builder

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    make \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo new --bin oxipot

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

ARG TZ
ENV TZ ${TZ}

RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ="Europe/Brussels"

RUN mkdir /oxipot

RUN mkdir /oxipot/db

WORKDIR /oxipot

COPY --from=builder /oxipot/target/release/oxipot  /oxipot/

EXPOSE 2223

ENV RUST_LOG=info

CMD [ "/oxipot/oxipot"]
