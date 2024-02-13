# builder image
FROM rust:1.76.0-slim-bookworm as builder
WORKDIR /app

# update apt packages
RUN apt-get update

# install trunk
RUN cargo install --locked trunk
RUN rustup target add wasm32-unknown-unknown

# preload dependencies
COPY Cargo.toml Cargo.lock ./
COPY ./front/Cargo.toml ./front/Cargo.toml
COPY ./front/index.html ./front/index.html

RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cd front && \
    mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    trunk build --release && \
    cd .. && \
    cargo build --release && \
    rm -rf front/src && \
    rm -rf front/dist && \
    rm -rf src

# build project
COPY ./ .
RUN cd front && trunk build --release
RUN cargo build --release
# CMD ["./target/release/lumichat"]

# container image
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# copy artifacts over
COPY --from=builder /app/target/release/lumichat .
COPY --from=builder /app/front/dist/ /app/front/dist/
CMD ["./lumichat"]

ENV PORT=8080