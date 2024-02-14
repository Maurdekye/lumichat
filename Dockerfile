# builder image
FROM rust:1.76.0-slim-bookworm as builder
WORKDIR /app

# update apt packages
RUN apt-get update
RUN apt-get install -y libpq-dev

# install trunk
RUN cargo install --locked trunk
RUN rustup target add wasm32-unknown-unknown

# preload dependencies
COPY Cargo.toml Cargo.lock ./
COPY ./front/Cargo.toml ./front/Cargo.toml

# fake source files for preload
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cd front && \
    mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "<!doctype html><html><head></head><body></body></html>" > index.html && \
    trunk build --release && \
    cd .. && \
    cargo build --release && \
    rm -rf front/src && \
    rm -f front/index.html && \
    rm -rf front/dist && \
    rm -rf src

# build project (rapid development iteration threshold here forward; the remaining operations should be fast to execute)
COPY ./ .
RUN cd front && trunk build --release
# hack: have to update the source code to force a rebuild
RUN touch front/src/main.rs
RUN cd front && trunk build --release
RUN cargo build --release

# container image
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