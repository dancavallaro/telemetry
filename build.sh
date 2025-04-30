#!/usr/bin/env bash
set -euo pipefail

VERSION=v0.1.3

go test ./...

docker buildx build --push --platform linux/amd64 --target serial_logger -t ghcr.io/dancavallaro/telemetry/serial_logger:$VERSION .

docker buildx build --push --platform linux/amd64 --target heartbeats -t ghcr.io/dancavallaro/telemetry/heartbeats:$VERSION .
