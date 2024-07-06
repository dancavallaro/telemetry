#!/usr/bin/env bash
set -euo pipefail

go test ./...

docker build -t serial_logger:latest docker/serial_logger
docker tag serial_logger:latest ghcr.io/dancavallaro/telemetry/serial_logger:latest
docker push ghcr.io/dancavallaro/telemetry/serial_logger:latest
