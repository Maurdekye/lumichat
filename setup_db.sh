#!/bin/bash
set -e

docker compose up -d db
cd shared
docker run --rm \
    -v "$(pwd)":/app \
    --network lumichat_default \
    willsquire/diesel-cli \
    --database-url=postgres://postgres:root@db:5432/postgres \
    setup