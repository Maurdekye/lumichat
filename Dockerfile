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
COPY ./front/index.html ./front/index.html

# fake source files
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
# hack: have to update the source code to force a rebuild; just append a newline to main.rs
RUN cd front && trunk build --release
RUN echo "\n" >> front/src/main.rs
RUN cd front && trunk build --release
RUN cargo build --release
# CMD ["./target/release/lumichat"]

# container image
FROM debian:bookworm-slim
WORKDIR /app

# update apt packages
RUN apt-get update
RUN apt-get install -y libssl-dev libpq-dev ca-certificates

# copy artifacts over
COPY --from=builder /app/target/release/lumichat .
COPY --from=builder /app/front/dist/ /app/front/dist/

CMD ["./lumichat"]

ENV PORT=8080