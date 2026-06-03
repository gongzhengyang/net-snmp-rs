# Justfile for net-snmp-rs
#
# A task runner for building, testing, and running the docker-compose based
# integration test for the SNMP agent + CLI tools.
#
# Requirements: `just` (https://github.com/casey/just), a Rust toolchain
# (pinned by rust-toolchain.toml), and Docker with the compose plugin.
#
# Quick start:
#   just            # list all recipes
#   just build      # cargo build --release
#   just test       # run the full Rust test suite
#   just docker-test  # build image + run the CLI integration suite in containers

set shell := ["bash", "-uc"]

# Image tag produced by the compose build.
image := "net-snmp-rs:latest"

# Default musl target triple for the static release build copied into the image.
# Override on the CLI, e.g. `just musl_target=aarch64-unknown-linux-musl docker-build`
# (also update the COPY path in the Dockerfile and the paths in .dockerignore).
musl_target := "x86_64-unknown-linux-musl"

check:
    cargo build
    cargo fmt --all
    cargo check --workspace --all-targets
    cargo clippy --workspace --all-targets -- -D warnings
    cargo doc --workspace --no-deps
    cargo test --workspace --locked

# Build the static musl release binaries locally (installs the target on demand).
build-musl:
    rustup target add {{musl_target}}
    cargo build --release --locked --target {{musl_target}}

# Build static binaries locally, then assemble the copy-only image.
docker-build: build-musl
    docker compose build

docker-build-mirror:
    APK_MIRROR=mirrors.ustc.edu.cn \
    just docker-build

# Build static binaries locally, then start the `snmpd` agent detached.
docker-up: build-musl
    docker compose up --build -d snmpd

# The `tester` container runs `snmp-itest`, driving the real snmp* tools through
# GET / GETNEXT / WALK / SET / GETBULK, SNMPv3 (authPriv) and a trap round-trip
# against the live agent. `--exit-code-from tester` stops the whole stack once
# the test container finishes; the stack is always torn down afterwards and the
# test exit code is propagated to the caller (so CI fails when any check fails).
# Build static binaries locally, then run the integration-test suite in containers.
docker-test: build-musl
    #!/usr/bin/env bash
    set -uo pipefail
    docker compose up --build --exit-code-from tester snmpd tester
    code=$?
    docker compose down -v --remove-orphans
    exit "$code"

# Stop and remove the stack (containers, network, volumes).
docker-down:
    docker compose down -v --remove-orphans

# Remove build artifacts and tear down any running docker stack.
clean:
    cargo clean
    -docker compose down -v --remove-orphans
