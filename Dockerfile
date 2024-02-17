### builder image
FROM rust:1.76.0-slim-bookworm as builder
WORKDIR /app

# update apt packages, install dependencies, and clean up
RUN apt-get update && \
    apt-get install -y libpq-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# install trunk and add wasm32 target
RUN cargo install --locked trunk && \
    rustup target add wasm32-unknown-unknown

# build project
COPY ./ .
RUN cd front && trunk build --release && \
    cargo build --release

### container image
FROM debian:bookworm-slim
WORKDIR /app

# update apt packages, install dependencies, and clean up
RUN apt-get update && \
    apt-get install -y libssl-dev libpq-dev ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# copy artifacts over
COPY --from=builder /app/target/release/lumichat /app/target/release/lumichat
COPY --from=builder /app/front/dist/ /app/front/dist/

CMD ["./target/release/lumichat"]

ENV PORT=8080
