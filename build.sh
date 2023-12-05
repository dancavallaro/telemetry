#!/usr/bin/env bash
set -euo pipefail

go test ./...

go build -o heartbeats cmd/heartbeats/main.go
go build -o serial_logger cmd/serial_logger/main.go
