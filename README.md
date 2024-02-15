# Lumichat

## Docker Deployment

The first time you deploy the app, you'll need to apply the migrations to the database. Run `setup_db.sh` to deploy and initialize the database. Afterwards, run `docker compose up -d` to build and deploy the app and its remaining components.

To disable the app, run `docker compose down`. To redeploy again in the future, run `docker compose up -d`.

## Local Development (Linux / WSL2)

To set up a local development environment in Linux, you'll need to install a few things:

1. Install the [Rust programming language](https://www.rust-lang.org/tools/install)
2. Install [Docker](https://docs.docker.com/engine/install/)
3. Install the `libpq-dev` package:
```bash
apt-get update
apt-get install -y libpq-dev
```
4. Install the trunk build tool and wasm build target:
```bash
RUN cargo install --locked trunk
RUN rustup target add wasm32-unknown-unknown
```
5. Build the frontend:
```bash
cd front
trunk build
```
6. Initialize the database:
```bash
./setup_db.sh
```
7. Deploy auxiliary docker services:
```bash
docker compose up -d db redis
```
8. Build & run the backend:
```bash
cd ..
cargo run
```
To redeploy changes to the backend, rerun `cargo run`. To redeploy changes to the frontend, `cd` into `front` and run `trunk build`. The new frontend changes should be accessible without restarting the backend; just force refresh the page with shift+F5.

## Local Development (Windows)

Deploying a local development environment in Windows is currently unsupported.