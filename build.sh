#!/usr/bin/env bash
set -euo pipefail

go test ./...

for app in heartbeats serial-logger volsync-metrics cluster-heartbeat; do
  env KO_DOCKER_REPO=ghcr.io/dancavallaro/telemetry ko build \
    --platform linux/amd64,linux/arm64 \
    --tags latest,"$(cat ./cmd/$app/version)" \
    --base-import-paths \
    ./cmd/$app
done
