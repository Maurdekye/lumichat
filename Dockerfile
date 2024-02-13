FROM rust:1.76.0 as builder
WORKDIR /app
COPY ./ .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/lumichat .
COPY --from=builder /app/front/dist/ /app/front/dist/
ENTRYPOINT ["lumichat"]