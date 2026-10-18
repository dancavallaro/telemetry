#!/usr/bin/env bash
set -euo pipefail

build_app() {
  app="$1"
  env KO_DOCKER_REPO=ghcr.io/dancavallaro/telemetry ko build \
    --platform linux/amd64,linux/arm64 \
    --tags latest,"$(cat "./cmd/$app/version")" \
    --base-import-paths \
    "./cmd/$app"
}

app="${1:-}"
if [[ -n "$app" ]]; then
  build_app "$app"
  exit 0
fi

go test ./...

for app in heartbeats serial-logger volsync-metrics cluster-heartbeat; do
  build_app "$app"
done
