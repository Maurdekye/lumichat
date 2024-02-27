### builder image
FROM rust:1.76.0-slim-bookworm as builder
WORKDIR /app

# update apt packages
RUN apt-get update
RUN apt-get install -y libpq-dev pkg-config

# install trunk
RUN cargo install --locked trunk
RUN rustup target add wasm32-unknown-unknown

# build project
COPY ./ .
RUN cd front && trunk build --release
RUN cargo build --release

### container image
FROM debian:bookworm-slim
WORKDIR /app

# update apt packages
RUN apt-get update
RUN apt-get install -y libssl-dev libpq-dev ca-certificates

# copy artifacts over
COPY --from=builder /app/target/release/lumichat /app/target/release/lumichat
COPY --from=builder /app/front/dist/ /app/front/dist/

CMD ["./target/release/lumichat"]

ENV PORT=8080