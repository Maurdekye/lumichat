FROM rust:1.76.0 as builder
WORKDIR /app

# install trunk
RUN cargo install --locked trunk

# preload backend dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# preload frontend dependencies
COPY ./front/Cargo.toml ./front/Cargo.toml
RUN cd front && \
    mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# build project
COPY ./ .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# copy artifacts over
COPY --from=builder /app/target/release/lumichat .
COPY --from=builder /app/front/dist/ /app/front/dist/
ENTRYPOINT ["lumichat"]