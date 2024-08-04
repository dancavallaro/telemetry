#!/usr/bin/env bash
set -euo pipefail

go test ./...

docker build --target serial_logger -t serial_logger:latest .
docker tag serial_logger:latest ghcr.io/dancavallaro/telemetry/serial_logger:latest
docker push ghcr.io/dancavallaro/telemetry/serial_logger:latest

docker build --target heartbeats -t heartbeats:latest .
docker tag heartbeats:latest ghcr.io/dancavallaro/telemetry/heartbeats:latest
docker push ghcr.io/dancavallaro/telemetry/heartbeats:latest
